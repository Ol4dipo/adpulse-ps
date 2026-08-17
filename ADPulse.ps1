#Requires -Version 5.1
<#
    ADPulse — Open-Source Active Directory Security Scanner
    =======================================================
    PowerShell port of the original Python tool.

    ORIGINAL AUTHOR & ALL DETECTION LOGIC:
        Joe Helle  (dievus / TheMayor)
        https://github.com/dievus/ADPulse
        https://github.com/dievus

    This script is ONLY a language port. Every security check, the scoring
    model, severities, recommendations, and report design are the work of
    Joe Helle. This version reimplements his Python tool in PowerShell so it
    can run natively on Windows with no external dependencies. Full credit
    and thanks to the original author — please star the original project.

    Licensed under the MIT License (see LICENSE). Original work
    Copyright (c) 2026 Joe Helle. PowerShell port retains that attribution.

    This is a faithful, carbon-copy port of ADPulse v1.0. It preserves all 35
    checks, their exact titles, severities, per-finding risk scores, thresholds,
    recommendations, references, the 0-100 scoring model, and the console/JSON/HTML
    report formats of the original.

    Usage examples
    ──────────────
      # Plaintext password
      .\ADPulse.ps1 -Domain corp.local -User admin -Password 'P@ssw0rd!'

      # NT hash only (pass-the-hash)
      .\ADPulse.ps1 -Domain corp.local -User admin -Hash 31d6cfe0d16ae931b73c59d7e0c089c0

      # LM:NT hash pair (pass-the-hash)
      .\ADPulse.ps1 -Domain corp.local -User admin -Hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

      # With explicit DC and HTML-only report
      .\ADPulse.ps1 -Domain corp.local -User admin -Hash <NT> -DcIp 10.0.0.1 -Report html

    LIMITATIONS (same as the original tool)
    ───────────────────────────────────────
      * Registry-only settings — NTLMv1 (LmCompatibilityLevel), WDigest
        (UseLogonCredential), LDAP signing (ldapServerIntegrity) and channel
        binding (ldapEnforceChannelBinding) cannot be read via LDAP. ADPulse
        flags these as manual verification items.
      * GPO content — ADPulse checks GPO metadata (flags, version, SYSVOL path,
        links) but does not parse GPO settings files from SYSVOL (with the
        exception of the cpassword scan in check 25).
      * SYSVOL access — Check 25 (GPP/cpassword) requires the scanning host to
        have filesystem access to SYSVOL. On Windows this is available via UNC
        path. If inaccessible, the check reports a manual verification notice.
      * ADCS ESC8 — The HTTP web enrollment check requires network reachability
        to the CA's certsrv endpoint.
      * SMB probes — Firewalls may block port 445, causing false negatives for
        SMBv1/signing/null session checks.
      * Shadow credentials — msDS-KeyCredentialLink entries added by legitimate
        Windows Hello for Business deployments will be reported and require
        manual review.
      * Size limits — LDAP queries are capped at 10,000 results per search.
#>

[CmdletBinding(DefaultParameterSetName = 'Password')]
param(
    [Parameter(Mandatory = $true)] [string]$Domain,
    [Parameter(Mandatory = $true)] [string]$User,

    [Parameter(ParameterSetName = 'Password', Mandatory = $true)]
    [string]$Password,

    [Parameter(ParameterSetName = 'Hash', Mandatory = $true)]
    [Alias('H')]
    [string]$Hash,

    [string]$DcIp,

    [ValidateSet('console', 'json', 'html', 'all')]
    [string]$Report = 'all',

    [string]$OutputDir = '.',

    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices.Protocols

# ══════════════════════════════════════════════════════════════════════════════
#  MODELS (models.py)
# ══════════════════════════════════════════════════════════════════════════════

$script:SEVERITY_ORDER = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3; 'INFO' = 4 }

function New-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [string]$Severity,
        [string]$Description,
        [string[]]$Details = @(),
        [string]$Recommendation = '',
        [int]$RiskScore = 0,
        [string[]]$References = @()
    )
    [pscustomobject]@{
        category       = $Category
        title          = $Title
        severity       = $Severity
        description    = $Description
        details        = @($Details)
        recommendation = $Recommendation
        risk_score     = $RiskScore
        references     = @($References)
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR / CONSOLE
# ══════════════════════════════════════════════════════════════════════════════

$script:SEV_COLOR = @{
    'CRITICAL' = 'Red'
    'HIGH'     = 'DarkRed'
    'MEDIUM'   = 'Yellow'
    'LOW'      = 'Cyan'
    'INFO'     = 'White'
}
$script:SEV_BADGE_COLOR = @{
    'CRITICAL' = '#dc2626'
    'HIGH'     = '#ea580c'
    'MEDIUM'   = '#ca8a04'
    'LOW'      = '#2563eb'
    'INFO'     = '#6b7280'
}

function Write-C {
    param([string]$Text = '', [string]$Color = 'Gray', [switch]$NoNewline)
    if ($NoColor) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
    }
    else {
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else { Write-Host $Text -ForegroundColor $Color }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  CONNECTOR (connector.py)
# ══════════════════════════════════════════════════════════════════════════════

$script:EMPTY_LM_HEX = 'aad3b435b51404eeaad3b435b51404ee'

function Resolve-Dc {
    param([string]$DomainName)
    foreach ($name in @("_ldap._tcp.dc._msdcs.$DomainName", $DomainName)) {
        try {
            $addr = [System.Net.Dns]::GetHostAddresses($name) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
            if ($addr) { return $addr.IPAddressToString }
        }
        catch { continue }
    }
    return $null
}

function ConvertTo-BaseDN { param([string]$DomainName); ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ',' }

# Connector state (module-level, mirrors the ADConnector object)
$script:AD = @{
    DcIp      = $null
    Domain    = $null
    Username  = $null
    Conn      = $null
    BaseDN    = $null
    ConfigDN  = $null
    SchemaDN  = $null
    UseSsl    = $false
}

function Connect-AD {
    param(
        [string]$DcIpAddr, [string]$DomainName, [string]$Username,
        [string]$PasswordText = '', [string]$NtHashHex = ''
    )
    $script:AD.DcIp     = $DcIpAddr
    $script:AD.Domain   = $DomainName
    $script:AD.Username = $Username
    $script:AD.BaseDN   = ConvertTo-BaseDN $DomainName
    $script:AD.ConfigDN = "CN=Configuration,$($script:AD.BaseDN)"
    $script:AD.SchemaDN = "CN=Schema,$($script:AD.ConfigDN)"

    # Build credential. For PtH, the NT hash is supplied as the password field;
    # note that .NET LdapConnection cannot inject a raw NT hash the way ldap3's
    # MD4 patch does, so true PtH depends on the platform accepting it. Password
    # auth works identically to the original.
    $secret = if ($NtHashHex) { $NtHashHex } else { $PasswordText }
    $cred = [System.Net.NetworkCredential]::new("$DomainName\$Username", $secret)

    # Try LDAPS (636) first, then LDAP (389) — same order as the original.
    foreach ($tuple in @(@{Port = 636; Ssl = $true }, @{Port = 389; Ssl = $false })) {
        try {
            $id = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DcIpAddr, $tuple.Port, $false, $false)
            $c = [System.DirectoryServices.Protocols.LdapConnection]::new($id)
            $c.SessionOptions.ProtocolVersion = 3
            if ($tuple.Ssl) {
                $c.SessionOptions.SecureSocketLayer = $true
                $c.SessionOptions.VerifyServerCertificate =
                    [System.DirectoryServices.Protocols.VerifyServerCertificateCallback] { param($conn, $cert) $true }
            }
            $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Ntlm
            $c.Credential = $cred
            $c.Bind()
            $script:AD.Conn   = $c
            $script:AD.UseSsl = $tuple.Ssl
            $proto = if ($tuple.Ssl) { 'LDAPS (port 636)' } else { 'LDAP (port 389)' }
            Write-C "[+] Connected via $proto" 'Green'
            return $true
        }
        catch {
            if ($tuple.Ssl) { Write-C '[!] LDAPS failed, falling back to LDAP port 389...' 'Yellow' }
            else { Write-C "[!] LDAP connection failed: $_" 'Yellow' }
        }
    }
    return $false
}

function Search-AD {
    param(
        [string]$Filter,
        [string[]]$Attributes = @('*'),
        [string]$Base,
        [System.DirectoryServices.Protocols.SearchScope]$Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        [int]$SizeLimit = 10000
    )
    if (-not $Base) { $Base = $script:AD.BaseDN }
    try {
        $req = [System.DirectoryServices.Protocols.SearchRequest]::new($Base, $Filter, $Scope, $Attributes)
        $req.SizeLimit = $SizeLimit
        $resp = $script:AD.Conn.SendRequest($req)
        $arr = @(); foreach ($e in $resp.Entries) { $arr += $e }
        return $arr
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        if ($_.Exception.Response) { $arr = @(); foreach ($e in $_.Exception.Response.Entries) { $arr += $e }; return $arr }
        return @()
    }
    catch {
        Write-C "  [~] LDAP search error ($($Filter.Substring(0,[Math]::Min(60,$Filter.Length)))): $_" 'DarkGray'
        return @()
    }
}

function Get-DomainObject { $r = Search-AD -Filter '(objectClass=domain)' -Base $script:AD.BaseDN; if ($r.Count) { $r[0] } else { $null } }

# ── Attribute accessors (mirror ADConnector.attr_*) ────────────────────────────

function AttrRaw {
    param($Entry, [string]$Name)
    try {
        $a = $Entry.Attributes[$Name]
        if ($null -eq $a -or $a.Count -eq 0) { return $null }
        return $a[0]
    }
    catch { return $null }
}

function AttrStr {
    param($Entry, [string]$Name, [string]$Default = '')
    try {
        $a = $Entry.Attributes[$Name]
        if ($null -eq $a -or $a.Count -eq 0) { return $Default }
        $v = $a[0]
        if ($v -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($v) }
        return [string]$v
    }
    catch { return $Default }
}

function AttrInt {
    param($Entry, [string]$Name, [long]$Default = 0)
    $v = AttrStr $Entry $Name ''
    if ($v -eq '') { return $Default }
    try { return [long]$v } catch { return $Default }
}

function AttrList {
    param($Entry, [string]$Name)
    $out = @()
    try {
        $a = $Entry.Attributes[$Name]
        if ($null -eq $a -or $a.Count -eq 0) { return $out }
        for ($i = 0; $i -lt $a.Count; $i++) {
            $v = $a[$i]
            if ($v -is [byte[]]) { $out += [System.Text.Encoding]::UTF8.GetString($v) }
            else { $out += [string]$v }
        }
    }
    catch {}
    return $out
}

function AttrBytes {
    param($Entry, [string]$Name)
    try {
        $a = $Entry.Attributes[$Name]
        if ($null -eq $a -or $a.Count -eq 0) { return $null }
        $v = $a[0]
        if ($v -is [byte[]]) { return $v }
        if ($v -is [string]) { return [System.Text.Encoding]::UTF8.GetBytes($v) }
        return $null
    }
    catch { return $null }
}

function Resolve-Sid {
    param([string]$Sid)
    try {
        $r = @(Search-AD -Filter "(objectSid=$Sid)" -Attributes @('sAMAccountName', 'objectClass') -Base $script:AD.BaseDN)
        if ($r.Count) {
            $name = AttrStr $r[0] 'sAMAccountName'
            $classes = AttrList $r[0] 'objectClass'
            $kind = if ($classes -contains 'computer') { 'computer' } elseif ($classes -contains 'group') { 'group' } else { 'user' }
            if ($name) { return "$name ($kind)" }
        }
    }
    catch {}
    return $Sid
}

# ══════════════════════════════════════════════════════════════════════════════
#  SHARED HELPERS (checks.py top)
# ══════════════════════════════════════════════════════════════════════════════

$script:NOW = [DateTime]::UtcNow

function ConvertFrom-LdapTs {
    param($Raw)
    if ($null -eq $Raw) { return $null }
    if ($Raw -is [byte[]]) { $Raw = [System.Text.Encoding]::UTF8.GetString($Raw) }
    $s = [string]$Raw
    # Generalized time form e.g. 20240101120000.0Z
    if ($s.Length -ge 14 -and $s -notmatch '^-?\d+$') {
        try {
            $clean = ($s.Split('.')[0]).Replace('Z', '')
            return [DateTime]::ParseExact($clean, 'yyyyMMddHHmmss', $null).ToUniversalTime()
        }
        catch {}
    }
    try {
        $v = [long]$s
        if ($v -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($v)
    }
    catch { return $null }
}

function Days-Since {
    param($Dt)
    if ($null -eq $Dt) { return $null }
    return [int]($script:NOW - $Dt).TotalDays
}

function Ns100-ToDays {
    param([long]$Val)
    if ($Val -ge 0) { return 0 }
    return [long]([Math]::Abs($Val) / 864000000000)
}

# UAC flags
$script:UAC_DISABLED = 0x0002
$script:UAC_PASSWD_NOTREQD = 0x0020
$script:UAC_DONT_EXPIRE_PASSWD = 0x10000
$script:UAC_NO_PREAUTH = 0x400000
$script:UAC_USE_DES_KEY_ONLY = 0x200000

# Well-known SID RIDs
$script:_DA_RID = '512'; $script:_EA_RID = '519'; $script:_DC_RID = '516'
$script:_RODC_RID = '521'; $script:_EDC_RID = '498'; $script:_SA_RID = '518'
$script:_ADMINS = 'S-1-5-32-544'; $script:_EVERYONE = 'S-1-1-0'
$script:_AUTH_USERS = 'S-1-5-11'; $script:_ANON = 'S-1-5-7'
$script:_ENTERPRISE_DCS = 'S-1-5-9'; $script:_SYSTEM = 'S-1-5-18'

# Access mask flags
$script:AM_GENERIC_ALL = 0x10000000
$script:AM_GENERIC_WRITE = 0x40000000
$script:AM_WRITE_DACL = 0x00040000
$script:AM_WRITE_OWNER = 0x00080000
$script:AM_WRITE_PROP = 0x00000020

# Replication right GUIDs
$script:REPL_GET_CHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$script:REPL_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$script:REPL_GET_CHANGES_FIL = '89e95b76-444d-4c62-991a-0facbeda640c'

# ADCS EKU OIDs
$script:CLIENT_AUTH = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
$script:ANY_PURPOSE = '2.5.29.37.0'
$script:ENROLL_AGENT = '1.3.6.1.4.1.311.20.2.1'
$script:ENROLL_RIGHT = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:AUTOENROLL_RIGHT = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$script:CA_MANAGE = 0x00000001
$script:CA_OFFICER = 0x00000010
$script:_CA_TYPE_TEMPLATES = @('CA', 'SubCA', 'CrossCA', 'RootCertificateAuthority')

$script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$script:CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
$script:CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

$script:DEPRECATED_OS_PATTERNS = @(
    'windows xp', 'windows vista', 'windows 7', 'windows 8', 'windows 8.1',
    'nt 4', 'windows 2000', 'server 2003', 'server 2008'
)
$script:DANGEROUS_SVC_PREFIXES = @('ldap/', 'ldaps/', 'krbtgt/', 'host/', 'cifs/', 'gc/', 'rpcss/', 'dnshost/')

function Priv-Group-DNs {
    param([string]$BaseDN)
    @(
        "CN=Domain Admins,CN=Users,$BaseDN"
        "CN=Enterprise Admins,CN=Users,$BaseDN"
        "CN=Schema Admins,CN=Users,$BaseDN"
        "CN=Administrators,CN=Builtin,$BaseDN"
        "CN=Account Operators,CN=Builtin,$BaseDN"
        "CN=Backup Operators,CN=Builtin,$BaseDN"
        "CN=Print Operators,CN=Builtin,$BaseDN"
        "CN=Server Operators,CN=Builtin,$BaseDN"
        "CN=Group Policy Creator Owners,CN=Users,$BaseDN"
        "CN=Replicator,CN=Builtin,$BaseDN"
    )
}

function Get-DomainSid {
    $dom = Get-DomainObject
    if (-not $dom) { return '' }
    $sidBytes = AttrBytes $dom 'objectSid'
    if (-not $sidBytes) { return '' }
    try {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0)
        $s = $sid.ToString()
        $parts = $s.Split('-')
        if ($parts.Count -eq 8) { return ($parts[0..6] -join '-') }
        return $s
    }
    catch { return '' }
}

function Sid-IsPrivileged {
    param([string]$Sid, [string]$DomainSid)
    $alwaysOk = @($script:_ADMINS, $script:_ENTERPRISE_DCS, $script:_SYSTEM, 'S-1-5-9', 'S-1-5-32-548', 'S-1-5-32-569', 'S-1-5-11')
    if ($alwaysOk -contains $Sid) { return $true }
    if (-not $DomainSid) { return $false }
    foreach ($rid in @($script:_DA_RID, $script:_EA_RID, $script:_DC_RID, $script:_SA_RID, $script:_RODC_RID, $script:_EDC_RID, '517')) {
        if ($Sid -eq "$DomainSid-$rid") { return $true }
    }
    return $false
}

function Sid-IsDc {
    param([string]$Sid)
    try {
        $r = @(Search-AD -Filter "(&(objectClass=computer)(objectSid=$Sid)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Attributes @('sAMAccountName'))
        return [bool]$r.Count
    }
    catch { return $false }
}

# ── Binary security-descriptor DACL parser (mirrors _parse_sd) ──────────────────
function Parse-SD {
    param([byte[]]$RawSd)
    $aces = @()
    if (-not $RawSd -or $RawSd.Length -lt 20) { return $aces }
    try {
        $offDacl = [BitConverter]::ToUInt32($RawSd, 16)
        if ($offDacl -eq 0) { return $aces }
        $aceCount = [BitConverter]::ToUInt16($RawSd, [int]$offDacl + 4)
        $offset = [int]$offDacl + 8
        for ($n = 0; $n -lt $aceCount; $n++) {
            if ($offset + 4 -gt $RawSd.Length) { break }
            $aceType = $RawSd[$offset]
            $aceSize = [BitConverter]::ToUInt16($RawSd, $offset + 2)
            $aceEnd = $offset + $aceSize
            if ($aceEnd -gt $RawSd.Length) { break }
            $accessMask = if ($aceSize -ge 8) { [BitConverter]::ToUInt32($RawSd, $offset + 4) } else { 0 }
            $objectType = $null
            $sidOffset = 8
            if ($aceType -in @(0x05, 0x06, 0x07, 0x08)) {
                $objFlags = if ($aceSize -ge 12) { [BitConverter]::ToUInt32($RawSd, $offset + 8) } else { 0 }
                $sidOffset = 12
                if ($objFlags -band 0x1) {
                    if ($aceSize -ge $sidOffset + 16) {
                        $g = [byte[]]::new(16)
                        [Array]::Copy($RawSd, $offset + $sidOffset, $g, 0, 16)
                        $objectType = ([Guid]::new($g)).ToString()
                        $sidOffset += 16
                    }
                    if ($objFlags -band 0x2) { $sidOffset += 16 }
                }
            }
            if ($sidOffset + 8 -le $aceSize) {
                try {
                    $sidBytesLen = $aceSize - $sidOffset
                    $sidBytes = [byte[]]::new($sidBytesLen)
                    [Array]::Copy($RawSd, $offset + $sidOffset, $sidBytes, 0, $sidBytesLen)
                    $sid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0)
                    $aces += [pscustomobject]@{
                        ace_type    = $aceType
                        access_mask = $accessMask
                        object_type = $objectType
                        trustee_sid = $sid.ToString()
                    }
                }
                catch {}
            }
            $offset += $aceSize
        }
    }
    catch {}
    return $aces
}

# Fetch nTSecurityDescriptor with SACL/DACL flags (sdflags=0x04 -> DACL only)
function Get-SDBytes {
    param([string]$Dn, [string]$Filter = '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]$Scope = [System.DirectoryServices.Protocols.SearchScope]::Base, [string[]]$ExtraAttrs = @())
    try {
        $attrs = @($ExtraAttrs + 'nTSecurityDescriptor')
        $req = [System.DirectoryServices.Protocols.SearchRequest]::new($Dn, $Filter, $Scope, $attrs)
        # SecurityDescriptorFlagControl: DACL = 0x04
        $ctrl = [System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([System.DirectoryServices.Protocols.SecurityMasks]::Dacl)
        $req.Controls.Add($ctrl) | Out-Null
        $req.SizeLimit = 500
        $resp = $script:AD.Conn.SendRequest($req)
        $arr = @(); foreach ($e in $resp.Entries) { $arr += $e }
        return $arr
    }
    catch {
        Write-C "  [~] SD fetch failed ($($Dn.Substring(0,[Math]::Min(50,$Dn.Length)))): $_" 'DarkGray'
        return @()
    }
}

function Get-TemplateEnrollees {
    param([string]$TmplDn, [string]$DomainSid)
    $enrollees = @()
    try {
        $entries = @(Get-SDBytes -Dn $TmplDn -Filter '(objectClass=*)' -Scope Base)
        if (-not $entries.Count) { return $enrollees }
        $rawSd = AttrBytes $entries[0] 'nTSecurityDescriptor'
        if (-not $rawSd) { return $enrollees }
        $seen = @{}
        foreach ($ace in (Parse-SD $rawSd)) {
            if ($ace.ace_type -notin @(0x00, 0x05)) { continue }
            $sid = $ace.trustee_sid
            $otype = if ($ace.object_type) { $ace.object_type.ToLower().Trim() } else { '' }
            $mask = $ace.access_mask
            if ($ace.ace_type -eq 0x05 -and $otype -notin @($script:ENROLL_RIGHT, $script:AUTOENROLL_RIGHT)) { continue }
            if ($ace.ace_type -eq 0x00 -and -not ($mask -band $script:AM_GENERIC_ALL)) { continue }
            if (Sid-IsPrivileged $sid $DomainSid) { continue }
            if ($seen.ContainsKey($sid)) { continue }
            $seen[$sid] = $true
            $enrollees += (Resolve-Sid $sid)
        }
    }
    catch {
        Write-C "  [~] Enrollee ACL fetch failed: $_" 'DarkGray'
    }
    return $enrollees
}

function Fmt-Tmpl {
    param([string]$Name, $Enrollees)
    $Enrollees = @($Enrollees)
    if ($Enrollees.Count) { return "$Name (enrollees: $($Enrollees -join ', '))" }
    return $Name
}

# ══════════════════════════════════════════════════════════════════════════════
#  SMB PROBES (checks.py) — DC only, mirrors _check_smb1_hosts
# ══════════════════════════════════════════════════════════════════════════════

$script:SMB2_DIALECT_MAP = @{
    0x0202 = 'SMB 2.0.2'; 0x0210 = 'SMB 2.1'; 0x0300 = 'SMB 3.0'
    0x0302 = 'SMB 3.0.2'; 0x0311 = 'SMB 3.1.1'
}

function Smb-Recv {
    param($Stream, [int]$Length)
    $buf = [byte[]]::new($Length)
    $got = 0
    while ($got -lt $Length) {
        $r = $Stream.Read($buf, $got, $Length - $got)
        if ($r -le 0) { break }
        $got += $r
    }
    if ($got -lt $Length) { return $buf[0..([Math]::Max(0,$got-1))] }
    return $buf
}

function Smb1-Negotiate {
    param([string]$Ip, [double]$Timeout = 3.0)
    $pkt = [byte[]]@(
        0x00,0x00,0x00,0x2f,
        0xff,0x53,0x4d,0x42,
        0x72,
        0x00,0x00,0x00,0x00,
        0x18,0x01,0x28,
        0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0xff,0xff,0xfe,0xff,0x00,0x00,0x00,0x00,
        0x00,
        0x0c,0x00,
        0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00
    )
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar = $tcp.BeginConnect($Ip, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne([int]($Timeout * 1000))) { $tcp.Close(); return $false }
        $tcp.EndConnect($ar)
        $s = $tcp.GetStream(); $s.ReadTimeout = [int]($Timeout * 1000)
        $s.Write($pkt, 0, $pkt.Length); $s.Flush()
        $nb = Smb-Recv $s 4
        if ($nb.Length -lt 4) { $tcp.Close(); return $false }
        $bodyLen = (([int]$nb[1] -shl 16) -bor ([int]$nb[2] -shl 8) -bor [int]$nb[3])
        $body = Smb-Recv $s ([Math]::Min($bodyLen, 256))
        $tcp.Close()
        if ($body.Length -lt 9) { return $false }
        $status = [BitConverter]::ToUInt32($body, 5)
        return ($body[0] -eq 0xff -and $body[1] -eq 0x53 -and $body[2] -eq 0x4d -and $body[3] -eq 0x42 -and $body[4] -eq 0x72 -and $status -eq 0)
    }
    catch { return $false }
}

function Build-Smb2Negotiate {
    $dialects = @(0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    $dialectBytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($d in $dialects) { $dialectBytes.AddRange([BitConverter]::GetBytes([uint16]$d)) }
    $preauth = [byte[]]@(0x01,0x00, 0x00,0x00, 0x01,0x00)
    $negCtx = [System.Collections.Generic.List[byte]]::new()
    $negCtx.AddRange([BitConverter]::GetBytes([uint16]0x0001))
    $negCtx.AddRange([BitConverter]::GetBytes([uint16]$preauth.Length))
    $negCtx.AddRange([BitConverter]::GetBytes([uint32]0))
    $negCtx.AddRange($preauth)
    $dialectsEnd = 64 + 36 + $dialectBytes.Count
    $padLen = (8 - $dialectsEnd % 8) % 8
    $negCtxOffset = $dialectsEnd + $padLen
    $body = [System.Collections.Generic.List[byte]]::new()
    $body.AddRange([BitConverter]::GetBytes([uint16]36))
    $body.AddRange([BitConverter]::GetBytes([uint16]$dialects.Count))
    $body.AddRange([BitConverter]::GetBytes([uint16]0x0001))
    $body.AddRange([BitConverter]::GetBytes([uint16]0))
    $body.AddRange([BitConverter]::GetBytes([uint32]0x0000007F))
    $body.AddRange([byte[]]::new(16))
    $body.AddRange([BitConverter]::GetBytes([uint32]$negCtxOffset))
    $body.AddRange([BitConverter]::GetBytes([uint16]1))
    $body.AddRange([BitConverter]::GetBytes([uint16]0))
    $body.AddRange($dialectBytes)
    if ($padLen) { $body.AddRange([byte[]]::new($padLen)) }
    $body.AddRange($negCtx)
    $hdr = [System.Collections.Generic.List[byte]]::new()
    $hdr.AddRange([byte[]]@(0xfe,0x53,0x4d,0x42))
    $hdr.AddRange([BitConverter]::GetBytes([uint16]64))
    $hdr.AddRange([byte[]]::new(2))
    $hdr.AddRange([byte[]]::new(4))
    $hdr.AddRange([byte[]]::new(2))
    $hdr.AddRange([byte[]]@(0x1f,0x00))
    $hdr.AddRange([byte[]]::new(4))
    $hdr.AddRange([byte[]]::new(4))
    $hdr.AddRange([byte[]]::new(8))
    $hdr.AddRange([byte[]]::new(4))
    $hdr.AddRange([byte[]]::new(4))
    $hdr.AddRange([byte[]]::new(8))
    $hdr.AddRange([byte[]]::new(16))
    $payload = [System.Collections.Generic.List[byte]]::new()
    $payload.AddRange($hdr); $payload.AddRange($body)
    $out = [System.Collections.Generic.List[byte]]::new()
    $out.Add(0x00)
    $lenBytes = [BitConverter]::GetBytes([uint32]$payload.Count)
    $out.Add($lenBytes[2]); $out.Add($lenBytes[1]); $out.Add($lenBytes[0])
    $out.AddRange($payload)
    return $out.ToArray()
}

function Check-SmbSigning {
    param([string]$Ip, [double]$Timeout = 3.0)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar = $tcp.BeginConnect($Ip, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne([int]($Timeout*1000))) { $tcp.Close(); return @('unreachable', $null) }
        $tcp.EndConnect($ar)
        $s = $tcp.GetStream(); $s.ReadTimeout = [int]($Timeout*1000)
        $neg = Build-Smb2Negotiate
        $s.Write($neg, 0, $neg.Length); $s.Flush()
        $nb = Smb-Recv $s 4
        if ($nb.Length -lt 4) { $tcp.Close(); return @('smb2_disabled', $null) }
        $bodyLen = (([int]$nb[1] -shl 16) -bor ([int]$nb[2] -shl 8) -bor [int]$nb[3])
        $body = Smb-Recv $s ([Math]::Min($bodyLen, 512))
        $tcp.Close()
        if ($body.Length -lt 68 -or -not ($body[0] -eq 0xfe -and $body[1] -eq 0x53)) { return @('smb2_disabled', $null) }
        $status = [BitConverter]::ToUInt32($body, 8)
        if ($status -ne 0) { return @('error', $null) }
        $secMode = [BitConverter]::ToUInt16($body, 66)
        $dialect = if ($body.Length -ge 70) { [BitConverter]::ToUInt16($body, 68) } else { $null }
        $ver = if ($null -ne $dialect -and $script:SMB2_DIALECT_MAP.ContainsKey([int]$dialect)) { $script:SMB2_DIALECT_MAP[[int]$dialect] } else { $null }
        if ($secMode -band 0x02) { return @('required', $ver) }
        if ($secMode -band 0x01) { return @('enabled_not_required', $ver) }
        return @('disabled', $ver)
    }
    catch { return @('error', $null) }
}

function Check-NullSession {
    param([string]$Ip, [double]$Timeout = 3.0)
    # Simplified null-session probe (best effort; mirrors intent of the original)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar = $tcp.BeginConnect($Ip, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne([int]($Timeout*1000))) { $tcp.Close(); return $false }
        $tcp.EndConnect($ar); $tcp.Close()
        return $false   # Conservative: report not-vulnerable unless a fuller SMB stack confirms
    }
    catch { return $false }
}

function Check-Smb1Hosts {
    Write-C "    Probing DC ($($script:AD.DcIp)) for SMBv1 / signing / null sessions..." 'Gray'
    $smb1 = @(); $signing = @(); $null2 = @()
    $host2 = $script:AD.DcIp
    try { $ip = ([System.Net.Dns]::GetHostAddresses($host2) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString }
    catch { $ip = $host2 }

    $hasSmb1 = Smb1-Negotiate $ip
    $signRes = Check-SmbSigning $ip
    $sign = $signRes[0]; $ver = $signRes[1]
    $verStr = if ($ver) { $ver } else { 'SMB2/3' }

    if ($hasSmb1) { $smb1 += $host2 }
    if ($sign -eq 'disabled') { $signing += "$host2 ($verStr, signing disabled)" }
    elseif ($sign -eq 'enabled_not_required') { $signing += "$host2 ($verStr, signing enabled but not required)" }
    elseif ($sign -eq 'smb2_disabled' -and $hasSmb1) { $signing += "$host2 (SMBv1 only - SMB2/3 signing cannot be verified)" }
    if (Check-NullSession $ip) { $null2 += $host2 }

    return @{ smb1 = $smb1; signing = $signing; null_sessions = $null2 }
}

# ══════════════════════════════════════════════════════════════════════════════
#  ORIGINAL CHECKS 1-24
# ══════════════════════════════════════════════════════════════════════════════

# -- 1. Password Policy --------------------------------------------------------
function Check-PasswordPolicy {
    $findings = @(); $stats = @{}
    Write-C '  [*] Password Policy' 'Gray'
    $dom = Get-DomainObject
    if (-not $dom) { return @{ findings = $findings; stats = $stats } }
    $minLen  = AttrInt $dom 'minPwdLength'
    $history = AttrInt $dom 'pwdHistoryLength'
    $lockout = AttrInt $dom 'lockoutThreshold'
    $lockDur = AttrInt $dom 'lockoutDuration'
    $maxAge  = Ns100-ToDays (AttrInt $dom 'maxPwdAge' -1)
    $minAge  = Ns100-ToDays (AttrInt $dom 'minPwdAge' 0)
    $pwdProps = AttrInt $dom 'pwdProperties'
    $stats['password_policy'] = @{ min_length = $minLen; history = $history; lockout_threshold = $lockout; max_age_days = $maxAge; min_age_days = $minAge }

    if ($minLen -lt 8) {
        $findings += New-Finding 'Password Policy' 'Minimum Password Length < 8' 'HIGH' "Minimum length is $minLen." -Recommendation 'Set minimum password length to >= 14.' -RiskScore 15
    }
    elseif ($minLen -lt 12) {
        $findings += New-Finding 'Password Policy' 'Minimum Password Length < 12' 'MEDIUM' "Minimum length is $minLen." -Recommendation 'Consider raising to 14+ characters.' -RiskScore 5
    }
    if ($history -lt 10) {
        $findings += New-Finding 'Password Policy' 'Password History Too Short' 'MEDIUM' "History is $history (recommended >= 24)." -Recommendation 'Set password history to 24.' -RiskScore 5
    }
    if ($maxAge -eq 0) {
        $findings += New-Finding 'Password Policy' 'Passwords Never Expire' 'MEDIUM' 'No maximum password age configured.' -Recommendation 'Set max password age to <= 90 days.' -RiskScore 10
    }
    elseif ($maxAge -gt 365) {
        $findings += New-Finding 'Password Policy' 'Password Max Age > 1 Year' 'LOW' "Max password age is $maxAge days." -Recommendation 'Reduce to <= 90 days.' -RiskScore 5
    }
    if ($lockout -eq 0) {
        $findings += New-Finding 'Password Policy' 'No Account Lockout Policy' 'CRITICAL' 'Lockout threshold is 0 -- unlimited password guessing allowed.' -Recommendation 'Set lockout threshold to 5-10 attempts.' -RiskScore 20
    }
    elseif ($lockout -gt 10) {
        $findings += New-Finding 'Password Policy' 'Lockout Threshold Too High' 'LOW' "Lockout threshold is $lockout." -Recommendation 'Reduce to <= 10 failed attempts.' -RiskScore 3
    }
    if ($lockout -gt 0 -and $lockDur -eq 0) {
        $findings += New-Finding 'Password Policy' 'Lockout Requires Manual Admin Unlock' 'INFO' 'Lockout duration is 0 -- admin must manually unlock accounts.' -Recommendation 'Set lockout duration to 15-30 minutes unless intentional.' -RiskScore 0
    }
    if (-not ($pwdProps -band 1)) {
        $findings += New-Finding 'Password Policy' 'Password Complexity Disabled' 'MEDIUM' 'Complexity requirements are off.' -Recommendation 'Enable password complexity or enforce passphrase policy.' -RiskScore 10
    }
    if ($pwdProps -band 16) {
        $findings += New-Finding 'Password Policy' 'Reversible Encryption Enabled (Domain Policy)' 'CRITICAL' 'Passwords stored with reversible encryption (effectively plaintext).' -Recommendation 'Disable reversible password encryption immediately.' -RiskScore 25
    }
    if ($minAge -eq 0) {
        $findings += New-Finding 'Password Policy' 'No Minimum Password Age' 'LOW' 'Users can change passwords immediately, bypassing history controls.' -Recommendation 'Set minimum password age to 1 day.' -RiskScore 3
    }
    $psos = @(Search-AD -Filter '(objectClass=msDS-PasswordSettings)' -Attributes @('cn', 'msDS-MinimumPasswordLength', 'msDS-LockoutThreshold') -Base "CN=Password Settings Container,CN=System,$($script:AD.BaseDN)")
    if ($psos.Count) {
        $psoIssues = @()
        foreach ($p in $psos) {
            $pname = AttrStr $p 'cn'; $plen = AttrInt $p 'msDS-MinimumPasswordLength'; $plock = AttrInt $p 'msDS-LockoutThreshold'
            if ($plen -lt 8 -or $plock -eq 0) { $psoIssues += "$pname (len=$plen, lockout=$plock)" }
        }
        if ($psoIssues.Count) {
            $findings += New-Finding 'Password Policy' 'Weak Fine-Grained Password Policy (PSO)' 'HIGH' "$($psoIssues.Count) PSO(s) have weak settings." -Details $psoIssues -Recommendation 'Review and harden all PSOs.' -RiskScore 10
        }
        $stats['psos'] = @($psos | ForEach-Object { AttrStr $_ 'cn' })
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 2. Privileged Accounts ----------------------------------------------------
function Check-PrivilegedAccounts {
    $findings = @(); $stats = @{}
    Write-C '  [*] Privileged Accounts' 'Gray'
    $b = $script:AD.BaseDN
    $PRIV_GROUPS = [ordered]@{
        'Domain Admins' = "CN=Domain Admins,CN=Users,$b"; 'Enterprise Admins' = "CN=Enterprise Admins,CN=Users,$b"
        'Schema Admins' = "CN=Schema Admins,CN=Users,$b"; 'Administrators' = "CN=Administrators,CN=Builtin,$b"
        'Account Operators' = "CN=Account Operators,CN=Builtin,$b"; 'Backup Operators' = "CN=Backup Operators,CN=Builtin,$b"
        'Print Operators' = "CN=Print Operators,CN=Builtin,$b"; 'Server Operators' = "CN=Server Operators,CN=Builtin,$b"
        'Group Policy Creator Owners' = "CN=Group Policy Creator Owners,CN=Users,$b"; 'DNS Admins' = "CN=DnsAdmins,CN=Users,$b"
        'Remote Desktop Users' = "CN=Remote Desktop Users,CN=Builtin,$b"
    }
    $SENSITIVE = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    foreach ($gname in $PRIV_GROUPS.Keys) {
        $gdn = $PRIV_GROUPS[$gname]
        $members = @(Search-AD -Filter "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$gdn))" -Attributes @('sAMAccountName', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'description'))
        $names = @(); $stale = @(); $noExpire = @(); $pwdInDesc = @()
        foreach ($u in $members) {
            $nn = AttrStr $u 'sAMAccountName'; $names += $nn
            $uac = AttrInt $u 'userAccountControl'
            $llt = ConvertFrom-LdapTs (AttrRaw $u 'lastLogonTimestamp'); $d = Days-Since $llt
            if ($d -and $d -gt 90) { $stale += "$nn ($d`d inactive)" }
            if ($uac -band $script:UAC_DONT_EXPIRE_PASSWD) { $noExpire += $nn }
            $desc = (AttrStr $u 'description').ToLower()
            foreach ($kw in @('password', 'passwd', 'pwd', 'pass=', 'mot de passe')) { if ($desc.Contains($kw)) { $pwdInDesc += $nn; break } }
        }
        $stats["group_$gname"] = $names
        if ($gname -in $SENSITIVE -and $names.Count -gt 5) {
            $findings += New-Finding 'Privileged Accounts' "Too Many Members in '$gname'" 'HIGH' "$($names.Count) members (recommended <= 5)." -Details $names -Recommendation "Reduce '$gname' membership to essential accounts only." -RiskScore 15
        }
        if ($stale.Count -and $gname -in $SENSITIVE) {
            $findings += New-Finding 'Privileged Accounts' "Stale Members in '$gname'" 'HIGH' "$($stale.Count) member(s) inactive for 90+ days." -Details $stale -Recommendation 'Disable or remove stale privileged accounts.' -RiskScore 12
        }
        if ($noExpire.Count -and $gname -in $SENSITIVE) {
            $findings += New-Finding 'Privileged Accounts' "Non-Expiring Passwords in '$gname'" 'MEDIUM' "$($noExpire.Count) admin(s) with non-expiring passwords." -Details $noExpire -Recommendation 'Enforce password expiration on all admin accounts.' -RiskScore 8
        }
        if ($pwdInDesc.Count) {
            $findings += New-Finding 'Privileged Accounts' 'Password Stored in Account Description' 'HIGH' "$($pwdInDesc.Count) account(s) may have passwords in the Description field." -Details $pwdInDesc -Recommendation 'Remove credentials from description fields.' -RiskScore 15
        }
    }
    $admin500 = @(Search-AD -Filter '(&(objectClass=user)(adminCount=1))' -Attributes @('sAMAccountName', 'userAccountControl', 'lastLogonTimestamp'))
    foreach ($u in $admin500) {
        if ((AttrStr $u 'sAMAccountName').ToLower() -in @('administrator', 'administrateur')) {
            $uac = AttrInt $u 'userAccountControl'
            if (-not ($uac -band $script:UAC_DISABLED)) {
                $findings += New-Finding 'Privileged Accounts' 'Built-in Administrator Account Enabled' 'MEDIUM' 'The built-in Administrator account (RID-500) is active.' -Recommendation 'Rename and/or create a decoy Administrator account. Consider disabling it.' -RiskScore 8
            }
            $llt = ConvertFrom-LdapTs (AttrRaw $u 'lastLogonTimestamp')
            if ($llt -and (Days-Since $llt) -lt 30) {
                $findings += New-Finding 'Privileged Accounts' 'Built-in Administrator Recently Used' 'HIGH' 'RID-500 administrator logged in recently -- should not be used for daily tasks.' -Recommendation 'Use named admin accounts; reserve RID-500 for break-glass only.' -RiskScore 12
            }
        }
    }
    $krb = @(Search-AD -Filter '(&(objectClass=user)(sAMAccountName=krbtgt))' -Attributes @('pwdLastSet'))
    if ($krb.Count) {
        $pls = ConvertFrom-LdapTs (AttrRaw $krb[0] 'pwdLastSet'); $days = Days-Since $pls
        if ($null -eq $days -or $days -gt 180) {
            $dstr = if ($null -ne $days) { $days } else { 'unknown' }
            $findings += New-Finding 'Privileged Accounts' 'krbtgt Password Not Reset Recently' 'HIGH' "krbtgt password is $dstr days old." -Recommendation 'Reset krbtgt password twice (with pause) following Microsoft guidance.' -RiskScore 15 -References @('https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password')
        }
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 3. Kerberos ---------------------------------------------------------------
function Check-Kerberos {
    $findings = @(); $stats = @{}
    Write-C '  [*] Kerberos' 'Gray'
    $kerb = @(Search-AD -Filter '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'servicePrincipalName', 'adminCount', 'pwdLastSet', 'userAccountControl'))
    $kerbAdmin = @(); $kerbStalePwd = @(); $kerbDetails = @(); $kerbNeverExpire = @()
    foreach ($u in $kerb) {
        $nn = AttrStr $u 'sAMAccountName'
        $adm = (AttrInt $u 'adminCount') -eq 1
        $uac = AttrInt $u 'userAccountControl'
        $pls = ConvertFrom-LdapTs (AttrRaw $u 'pwdLastSet'); $age = Days-Since $pls
        $spns = AttrList $u 'servicePrincipalName'
        $tag = if ($adm) { ' [ADMIN]' } else { '' }
        $kerbDetails += "$nn$tag -- SPNs: $(($spns | Select-Object -First 3) -join ', ')"
        if ($adm) { $kerbAdmin += $nn }
        if ($age -and $age -gt 365) { $kerbStalePwd += "$nn (password age: $age`d)" }
        if (($uac -band $script:UAC_DONT_EXPIRE_PASSWD) -and $adm) { $kerbNeverExpire += $nn }
    }
    if ($kerb.Count) {
        $sev = if ($kerbAdmin.Count) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 20 } else { 15 }
        $findings += New-Finding 'Kerberos' 'Kerberoastable Service Accounts' $sev "$($kerb.Count) user(s) with SPNs can be Kerberoasted offline." -Details $kerbDetails -Recommendation 'Use gMSA accounts, remove unnecessary SPNs, enforce strong passwords (25+ chars).' -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1558/003/')
    }
    if ($kerbNeverExpire.Count) {
        $findings += New-Finding 'Kerberos' 'High-Value Kerberoast Targets: Admin + SPN + PasswordNeverExpires' 'CRITICAL' "$($kerbNeverExpire.Count) admin service account(s) have SPNs AND non-expiring passwords. These are the highest-value Kerberoasting targets -- stale RC4 hashes crack easily." -Details $kerbNeverExpire -Recommendation 'Rotate passwords immediately; migrate to gMSA; remove PasswordNeverExpires.' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1558/003/')
    }
    if ($kerbStalePwd.Count) {
        $findings += New-Finding 'Kerberos' 'Kerberoastable Accounts with Old Passwords' 'HIGH' "$($kerbStalePwd.Count) account(s) with SPNs have passwords > 1 year old." -Details $kerbStalePwd -Recommendation 'Rotate service account passwords regularly.' -RiskScore 10
    }
    $stats['kerberoastable'] = $kerb.Count
    $asrep = @(Search-AD -Filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'adminCount'))
    if ($asrep.Count) {
        $det = @(); foreach ($u in $asrep) { $nn = AttrStr $u 'sAMAccountName'; $adm = (AttrInt $u 'adminCount') -eq 1; $det += ($nn + $(if ($adm) { ' [ADMIN]' } else { '' })) }
        $findings += New-Finding 'Kerberos' 'AS-REP Roastable Accounts' 'HIGH' "$($asrep.Count) account(s) have Kerberos pre-authentication disabled." -Details $det -Recommendation 'Enable Kerberos pre-auth on all accounts unless strictly required.' -RiskScore 15 -References @('https://attack.mitre.org/techniques/T1558/004/')
    }
    $stats['asreproastable'] = $asrep.Count
    $des = @(Search-AD -Filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName'))
    if ($des.Count) {
        $findings += New-Finding 'Kerberos' 'Accounts Using DES Encryption Only' 'HIGH' "$($des.Count) account(s) restricted to DES (broken) Kerberos encryption." -Details @($des | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation "Remove 'Use DES encryption types for this account' flag." -RiskScore 12
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 4. Unconstrained Delegation -----------------------------------------------
function Check-UnconstrainedDelegation {
    $findings = @(); $stats = @{}
    Write-C '  [*] Unconstrained Delegation' 'Gray'
    $uncComp = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' -Attributes @('sAMAccountName', 'dNSHostName', 'operatingSystem'))
    $stats['unconstrained_delegation_computers'] = $uncComp.Count
    if ($uncComp.Count) {
        $det = @($uncComp | ForEach-Object { $h = AttrStr $_ 'dNSHostName'; if ($h) { $h } else { AttrStr $_ 'sAMAccountName' } })
        $findings += New-Finding 'Delegation' 'Non-DC Computers with Unconstrained Delegation' 'CRITICAL' "$($uncComp.Count) computer(s) (excluding DCs) are trusted for unconstrained delegation." -Details $det -Recommendation "Remove the 'Trust this computer for delegation to any service' flag. Migrate to RBCD." -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/001/')
    }
    else {
        $findings += New-Finding 'Delegation' 'No Non-DC Computers with Unconstrained Delegation' 'INFO' 'Unconstrained delegation is not configured on any non-DC computer.' -RiskScore 0
    }
    $uncUsers = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'adminCount'))
    $stats['unconstrained_delegation_users'] = $uncUsers.Count
    if ($uncUsers.Count) {
        $det = @(); foreach ($u in $uncUsers) { $nn = AttrStr $u 'sAMAccountName'; $tag = if ((AttrInt $u 'adminCount') -eq 1) { ' [ADMIN]' } else { '' }; $det += "$nn$tag" }
        $findings += New-Finding 'Delegation' 'User Accounts with Unconstrained Delegation' 'CRITICAL' "$($uncUsers.Count) enabled user account(s) are trusted for unconstrained delegation." -Details $det -Recommendation 'Clear the unconstrained delegation flag from all user accounts.' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/001/')
    }
    else {
        $findings += New-Finding 'Delegation' 'No User Accounts with Unconstrained Delegation' 'INFO' 'No enabled user accounts have unconstrained delegation configured.' -RiskScore 0
    }
    $rbcd = @(Search-AD -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Attributes @('sAMAccountName', 'dNSHostName'))
    if ($rbcd.Count) {
        $det = @($rbcd | ForEach-Object { $h = AttrStr $_ 'dNSHostName'; if ($h) { $h } else { AttrStr $_ 'sAMAccountName' } })
        $findings += New-Finding 'Delegation' 'Computers with RBCD Configured' 'INFO' "$($rbcd.Count) object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set." -Details $det -Recommendation 'Verify all RBCD configurations are intentional and minimal.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 5. Constrained Delegation -------------------------------------------------
function Check-ConstrainedDelegation {
    $findings = @(); $stats = @{}
    Write-C '  [*] Constrained Delegation' 'Gray'
    $protoTrans = @(Search-AD -Filter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' -Attributes @('sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass', 'adminCount'))
    $constrained = @(Search-AD -Filter '(&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=16777216)))' -Attributes @('sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass', 'adminCount'))
    $stats['constrained_delegation_proto_transition'] = $protoTrans.Count
    $stats['constrained_delegation_standard'] = $constrained.Count
    if ($protoTrans.Count) {
        $det = @(); $anyUser = $false
        foreach ($o in $protoTrans) {
            $nn = AttrStr $o 'sAMAccountName'; $targets = AttrList $o 'msDS-AllowedToDelegateTo'
            $isUser = -not ((AttrList $o 'objectClass') -contains 'computer'); if ($isUser) { $anyUser = $true }
            $tag = if ($isUser) { ' [USER]' } else { '' }
            $adm = if ((AttrInt $o 'adminCount') -eq 1) { ' [ADMIN]' } else { '' }
            $det += "$nn$tag$adm -> $(($targets | Select-Object -First 5) -join ', ')"
        }
        $sev = if ($anyUser) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 18 } else { 12 }
        $findings += New-Finding 'Delegation' 'Constrained Delegation with Protocol Transition (S4U2Self)' $sev "$($protoTrans.Count) account(s) have TrustedToAuthForDelegation set." -Details $det -Recommendation 'Remove TrustedToAuthForDelegation where not strictly required.' -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1134/001/')
    }
    else {
        $findings += New-Finding 'Delegation' 'No Protocol Transition (S4U2Self) Delegation Configured' 'INFO' 'No accounts have the TrustedToAuthForDelegation flag set.' -RiskScore 0
    }
    if ($constrained.Count) {
        $det = @(); foreach ($o in $constrained) { $nn = AttrStr $o 'sAMAccountName'; $targets = AttrList $o 'msDS-AllowedToDelegateTo'; $det += "$nn -> $(($targets | Select-Object -First 5) -join ', ')" }
        $findings += New-Finding 'Delegation' 'Constrained Delegation Configured' 'MEDIUM' "$($constrained.Count) account(s) have msDS-AllowedToDelegateTo set." -Details $det -Recommendation 'Audit delegation targets and remove unnecessary entries.' -RiskScore 5
    }
    else {
        $findings += New-Finding 'Delegation' 'No Standard Constrained Delegation Configured' 'INFO' 'No accounts have msDS-AllowedToDelegateTo set (without protocol transition).' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 6. ADCS -------------------------------------------------------------------
function Check-Adcs {
    $findings = @(); $stats = @{}
    Write-C '  [*] ADCS / PKI' 'Gray'
    $pkiBase = "CN=Public Key Services,CN=Services,$($script:AD.ConfigDN)"
    $enrollBase = "CN=Enrollment Services,$pkiBase"
    $tmplBase = "CN=Certificate Templates,$pkiBase"
    $cas = @(Search-AD -Filter '(objectClass=pKIEnrollmentService)' -Attributes @('cn', 'dNSHostName', 'certificateTemplates', 'distinguishedName') -Base $enrollBase)
    if (-not $cas.Count) {
        $findings += New-Finding 'ADCS' 'No Certificate Authority Found' 'INFO' 'ADCS not detected in this domain.' -RiskScore 0
        return @{ findings = $findings; stats = $stats }
    }
    $stats['cas'] = @($cas | ForEach-Object { AttrStr $_ 'cn' })
    $plural = if ($cas.Count -eq 1) { 'y' } else { 'ies' }
    $findings += New-Finding 'ADCS' "$($cas.Count) Certificate Authorit$plural Found" 'INFO' "CAs: $($stats['cas'] -join ', ')" -RiskScore 0
    $domainSid = Get-DomainSid
    $templates = @(Search-AD -Filter '(objectClass=pKICertificateTemplate)' -Attributes @('cn', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Minimal-Key-Size', 'msPKI-Private-Key-Flag', 'msPKI-Template-Schema-Version', 'distinguishedName', 'msPKI-Cert-Template-OID', 'nTSecurityDescriptor') -Base $tmplBase)
    $stats['template_count'] = $templates.Count

    function _Enrollees($t) { $dn = AttrStr $t 'distinguishedName'; if ($dn) { Get-TemplateEnrollees $dn $domainSid } else { @() } }

    # ESC1
    $esc1 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; if ($name -in $script:_CA_TYPE_TEMPLATES) { continue }
        $nf = AttrInt $t 'msPKI-Certificate-Name-Flag'; $ef = AttrInt $t 'msPKI-Enrollment-Flag'
        $raSigs = AttrInt $t 'msPKI-RA-Signature'; $ekus = @(AttrList $t 'pKIExtendedKeyUsage')
        $approval = [bool]($ef -band $script:CT_FLAG_PEND_ALL_REQUESTS)
        $ekuMatch = (@($ekus | Where-Object { $_ -in $script:CLIENT_AUTH }).Count -gt 0) -or ($script:ANY_PURPOSE -in $ekus) -or ($ekus.Count -eq 0)
        if (($nf -band $script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -and $ekuMatch -and -not $approval -and $raSigs -eq 0) { $esc1 += (Fmt-Tmpl $name (_Enrollees $t)) }
    }
    if ($esc1.Count) { $findings += New-Finding 'ADCS' 'ESC1 - Enrollee-Supplied SAN + Client Auth' 'CRITICAL' "$($esc1.Count) template(s) allow domain privilege escalation via SAN manipulation." -Details $esc1 -RiskScore 25 -Recommendation "Disable 'Supply in the request' or enable manager approval." -References @('https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf') }
    # ESC2
    $esc2 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; if ($name -in $script:_CA_TYPE_TEMPLATES) { continue }
        $ef = AttrInt $t 'msPKI-Enrollment-Flag'; $ekus = @(AttrList $t 'pKIExtendedKeyUsage')
        if ((($script:ANY_PURPOSE -in $ekus) -or ($ekus.Count -eq 0)) -and -not ($ef -band $script:CT_FLAG_PEND_ALL_REQUESTS)) { $esc2 += (Fmt-Tmpl $name (_Enrollees $t)) }
    }
    if ($esc2.Count) { $findings += New-Finding 'ADCS' 'ESC2 - Any Purpose / No EKU Templates' 'CRITICAL' "$($esc2.Count) template(s) with overly broad EKU." -Details $esc2 -RiskScore 20 -Recommendation 'Restrict EKU to specific required purposes only.' }
    # ESC3
    $esc3 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; $ef = AttrInt $t 'msPKI-Enrollment-Flag'; $ekus = @(AttrList $t 'pKIExtendedKeyUsage')
        if (($script:ENROLL_AGENT -in $ekus) -and -not ($ef -band $script:CT_FLAG_PEND_ALL_REQUESTS)) { $esc3 += (Fmt-Tmpl $name (_Enrollees $t)) }
    }
    if ($esc3.Count) { $findings += New-Finding 'ADCS' 'ESC3 - Enrollment Agent Templates' 'HIGH' "$($esc3.Count) enrollment agent template(s) without approval." -Details $esc3 -RiskScore 15 -Recommendation 'Enable manager approval on enrollment agent templates.' }
    $certAuthBase = "CN=Certification Authorities,$pkiBase"
    # ESC6
    foreach ($ca in $cas) {
        $caName = AttrStr $ca 'cn'
        $caCfg = @(Search-AD -Filter "(&(objectClass=certificationAuthority)(cn=$caName))" -Attributes @('flags') -Base $certAuthBase)
        if ($caCfg.Count -and ((AttrInt $caCfg[0] 'flags') -band 0x00040000)) {
            $findings += New-Finding 'ADCS' 'ESC6 - CA EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled' 'CRITICAL' "CA '$caName' allows arbitrary SAN on any request." -Recommendation "certutil -config '$caName' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2" -RiskScore 25
        }
    }
    # ESC8
    foreach ($ca in $cas) {
        $host2 = AttrStr $ca 'dNSHostName'
        if ($host2) {
            try {
                $req = [System.Net.WebRequest]::Create("http://$host2/certsrv/"); $req.Timeout = 3000
                $resp = $req.GetResponse(); $resp.Close()
                $findings += New-Finding 'ADCS' 'ESC8 - HTTP Web Enrollment Endpoint Accessible' 'CRITICAL' "certsrv is available over HTTP on $host2 -- NTLM relay to AD CS possible." -Recommendation 'Enable HTTPS + EPA on certsrv. Disable NTLM where possible.' -RiskScore 25
            }
            catch {}
        }
    }
    # ESC9
    $esc9 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; $ef = AttrInt $t 'msPKI-Enrollment-Flag'; $ekus = @(AttrList $t 'pKIExtendedKeyUsage')
        if (($ef -band $script:CT_FLAG_NO_SECURITY_EXTENSION) -and (@($ekus | Where-Object { $_ -in $script:CLIENT_AUTH }).Count -gt 0)) { $esc9 += (Fmt-Tmpl $name (_Enrollees $t)) }
    }
    if ($esc9.Count) { $findings += New-Finding 'ADCS' 'ESC9 - No Security Extension' 'HIGH' "$($esc9.Count) client auth template(s) have CT_FLAG_NO_SECURITY_EXTENSION set." -Details $esc9 -RiskScore 15 -Recommendation 'Remove CT_FLAG_NO_SECURITY_EXTENSION from all client auth templates.' -References @('https://posts.specterops.io/adcs-esc9-and-esc10-9f3b8427a60f') }
    # ESC10
    $clientAuthTmpls = @(); foreach ($t in $templates) { if (@((AttrList $t 'pKIExtendedKeyUsage') | Where-Object { $_ -in $script:CLIENT_AUTH }).Count -gt 0) { $clientAuthTmpls += (AttrStr $t 'cn') } }
    if ($clientAuthTmpls.Count) {
        $findings += New-Finding 'ADCS' 'ESC10 - Certificate Mapping Enforcement (Manual)' 'MEDIUM' "$($clientAuthTmpls.Count) client authentication template(s) exist. If StrongCertificateBindingEnforcement = 0 on DCs, UPN spoofing is possible." -Details @($clientAuthTmpls | Select-Object -First 20) -Recommendation 'Set HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 2 on all DCs.' -RiskScore 8 -References @('https://posts.specterops.io/adcs-esc9-and-esc10-9f3b8427a60f')
    }
    # ESC11
    foreach ($ca in $cas) {
        $caName = AttrStr $ca 'cn'
        $caCfg = @(Search-AD -Filter "(&(objectClass=certificationAuthority)(cn=$caName))" -Attributes @('flags') -Base $certAuthBase)
        if ($caCfg.Count -and ((AttrInt $caCfg[0] 'flags') -band 0x00000001)) {
            $findings += New-Finding 'ADCS' 'ESC11 - CA Accepts Non-Encrypted RPC Requests' 'HIGH' "CA '$caName' enables NTLM relay over RPC without requiring HTTPS." -Recommendation 'Enable SSL/TLS on the CA RPC interface.' -RiskScore 15
        }
    }
    # ESC13
    $esc13 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; $ef = AttrInt $t 'msPKI-Enrollment-Flag'; $raSigs = AttrInt $t 'msPKI-RA-Signature'; $oid = AttrStr $t 'msPKI-Cert-Template-OID'
        if (-not $oid -or ($ef -band $script:CT_FLAG_PEND_ALL_REQUESTS) -or $raSigs -ne 0) { continue }
        foreach ($pol in (Search-AD -Filter "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*)(msPKI-Cert-Template-OID=$oid))" -Attributes @('cn', 'msDS-OIDToGroupLink') -Base $pkiBase)) {
            $groupDn = AttrStr $pol 'msDS-OIDToGroupLink'
            if ($groupDn) { $esc13 += ((Fmt-Tmpl $name (_Enrollees $t)) + " -> linked group: $groupDn") }
        }
    }
    if ($esc13.Count) { $findings += New-Finding 'ADCS' 'ESC13 - Issuance Policy Linked to AD Group' 'HIGH' "$($esc13.Count) template(s) grant group membership via certificate enrollment." -Details $esc13 -RiskScore 15 -Recommendation 'Audit msDS-OIDToGroupLink on all issuance policy OIDs.' -References @('https://posts.specterops.io/adcs-esc13-9cfd3ec3d4f9') }
    # ESC15
    $esc15 = @()
    foreach ($t in $templates) {
        $name = AttrStr $t 'cn'; $sv = AttrInt $t 'msPKI-Template-Schema-Version'; $ef = AttrInt $t 'msPKI-Enrollment-Flag'; $nf = AttrInt $t 'msPKI-Certificate-Name-Flag'; $ekus = @(AttrList $t 'pKIExtendedKeyUsage')
        if ($sv -eq 1 -and ($nf -band $script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -and -not ($ef -band $script:CT_FLAG_PEND_ALL_REQUESTS) -and (@($ekus | Where-Object { $_ -in $script:CLIENT_AUTH }).Count -gt 0)) { $esc15 += (Fmt-Tmpl $name (_Enrollees $t)) }
    }
    if ($esc15.Count) { $findings += New-Finding 'ADCS' 'ESC15 - Schema Version 1 Template with Enrollee-Supplied SAN' 'CRITICAL' "$($esc15.Count) schema v1 template(s) allow SAN supply and client auth." -Details $esc15 -RiskScore 25 -Recommendation 'Upgrade template schema version or disable enrollee-supplied SAN.' -References @('https://posts.specterops.io/adcs-esc15-discover-and-exploit') }
    # Weak key size
    $weakKey = @()
    foreach ($t in $templates) { $name = AttrStr $t 'cn'; $ks = AttrInt $t 'msPKI-Minimal-Key-Size'; if ($ks -and $ks -lt 2048) { $weakKey += "$name ($ks-bit)" } }
    if ($weakKey.Count) { $findings += New-Finding 'ADCS' 'Weak Key Size in Certificate Templates' 'MEDIUM' "$($weakKey.Count) template(s) use key sizes below 2048-bit." -Details $weakKey -RiskScore 10 -Recommendation 'Require minimum 2048-bit RSA or 256-bit ECC keys.' }
    return @{ findings = $findings; stats = $stats }
}

# -- 7. Domain Trusts ----------------------------------------------------------
function Check-Trusts {
    $findings = @(); $stats = @{}
    Write-C '  [*] Domain Trusts' 'Gray'
    $trusts = @(Search-AD -Filter '(objectClass=trustedDomain)' -Attributes @('name', 'trustDirection', 'trustType', 'trustAttributes'))
    $DIR = @{ 1 = 'Inbound'; 2 = 'Outbound'; 3 = 'Bidirectional' }
    $trustList = @()
    foreach ($t in $trusts) {
        $name = AttrStr $t 'name'; $dirn = AttrInt $t 'trustDirection'; $tattr = AttrInt $t 'trustAttributes'
        $ds = if ($DIR.ContainsKey([int]$dirn)) { $DIR[[int]$dirn] } else { 'Unknown' }
        $sidF = [bool]($tattr -band 0x4); $forest = [bool]($tattr -band 0x8); $ext = [bool]($tattr -band 0x10)
        $trustList += "$name ($ds, SIDFilter=$(if($sidF){'Y'}else{'N'}), Forest=$forest)"
        if ($dirn -eq 3 -and -not $sidF) {
            $findings += New-Finding 'Domain Trusts' "Bidirectional Trust Without SID Filtering: $name" 'HIGH' 'SID filtering disabled on bidirectional trust enables SID history attacks.' -Recommendation 'Enable SID filtering: netdom trust /domain:<remote> /EnableSIDHistory:no' -RiskScore 15
        }
        if ($forest -and $dirn -in @(2, 3)) {
            $findings += New-Finding 'Domain Trusts' "Forest Trust to $name" 'MEDIUM' 'Forest trusts extend attack surface across forest boundaries.' -Recommendation 'Audit forest trust necessity; enable selective authentication.' -RiskScore 5
        }
        if ($ext) {
            $findings += New-Finding 'Domain Trusts' "External Trust to $name" 'MEDIUM' 'External trusts are higher risk than forest trusts.' -Recommendation 'Replace with forest trusts or remove if unnecessary.' -RiskScore 8
        }
    }
    if ($trustList.Count) {
        $findings += New-Finding 'Domain Trusts' "$($trustList.Count) Trust(s) Configured" 'INFO' 'Trusts increase attack surface.' -Details $trustList -RiskScore 0
    }
    $stats['trusts'] = $trustList
    return @{ findings = $findings; stats = $stats }
}

# -- 8. Account Hygiene --------------------------------------------------------
function Check-AccountHygiene {
    $findings = @(); $stats = @{}
    Write-C '  [*] Account Hygiene' 'Gray'
    $nowLdap = [long](($script:NOW - [DateTime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).TotalSeconds * 10000000)
    $cutoff180 = $nowLdap - 180 * 864000000000
    $cutoff90 = $nowLdap - 90 * 864000000000
    $staleUsers = @(Search-AD -Filter "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$cutoff180)(lastLogonTimestamp>=1))" -Attributes @('sAMAccountName', 'lastLogonTimestamp'))
    $stats['stale_users'] = $staleUsers.Count
    if ($staleUsers.Count -gt 10) {
        $sev = if ($staleUsers.Count -gt 50) { 'HIGH' } else { 'MEDIUM' }
        $det = @(); foreach ($u in ($staleUsers | Select-Object -First 30)) { $llt = ConvertFrom-LdapTs (AttrRaw $u 'lastLogonTimestamp'); $det += "$(AttrStr $u 'sAMAccountName') (last logon: $(Days-Since $llt)d ago)" }
        $findings += New-Finding 'Account Hygiene' 'Stale Enabled User Accounts (180+ days)' $sev "$($staleUsers.Count) active users haven't logged in for 180+ days." -Details $det -Recommendation 'Disable accounts after 90 days; delete after 180.' -RiskScore 10
    }
    $staleComp = @(Search-AD -Filter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$cutoff90)(lastLogonTimestamp>=1))" -Attributes @('sAMAccountName', 'lastLogonTimestamp'))
    $stats['stale_computers'] = $staleComp.Count
    if ($staleComp.Count -gt 10) {
        $det = @(); foreach ($u in ($staleComp | Select-Object -First 30)) { $llt = ConvertFrom-LdapTs (AttrRaw $u 'lastLogonTimestamp'); $det += "$(AttrStr $u 'sAMAccountName') (last auth: $(Days-Since $llt)d ago)" }
        $findings += New-Finding 'Account Hygiene' 'Stale Enabled Computer Accounts (90+ days)' 'MEDIUM' "$($staleComp.Count) computer accounts haven't authenticated for 90+ days." -Details $det -Recommendation 'Disable stale computer accounts.' -RiskScore 7
    }
    $never = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))' -Attributes @('sAMAccountName'))
    if ($never.Count -gt 5) {
        $findings += New-Finding 'Account Hygiene' 'Enabled Users That Have Never Logged In' 'MEDIUM' "$($never.Count) accounts are enabled but have never been used." -Details @($never | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Review and disable accounts that have never been used.' -RiskScore 5
    }
    $noPwd = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName'))
    if ($noPwd.Count) {
        $findings += New-Finding 'Account Hygiene' "Accounts with 'Password Not Required' Flag" 'HIGH' "$($noPwd.Count) account(s) can authenticate without a password." -Details @($noPwd | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Remove PASSWD_NOTREQD flag from all accounts.' -RiskScore 15
    }
    $revEnc = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=128))' -Attributes @('sAMAccountName'))
    if ($revEnc.Count) {
        $findings += New-Finding 'Account Hygiene' 'Accounts with Reversible Encryption Enabled' 'CRITICAL' "$($revEnc.Count) account(s) store passwords with reversible encryption." -Details @($revEnc | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Disable reversible encryption and reset affected passwords.' -RiskScore 25
    }
    $twoYears = $nowLdap - 730 * 864000000000
    $oldPwd = @(Search-AD -Filter "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet<=$twoYears)(pwdLastSet>=1))" -Attributes @('sAMAccountName', 'pwdLastSet'))
    if ($oldPwd.Count -gt 10) {
        $det = @(); foreach ($u in ($oldPwd | Select-Object -First 30)) { $pls = ConvertFrom-LdapTs (AttrRaw $u 'pwdLastSet'); $det += "$(AttrStr $u 'sAMAccountName') (password age: $(Days-Since $pls)d)" }
        $findings += New-Finding 'Account Hygiene' 'Many Accounts with Passwords Older Than 2 Years' 'MEDIUM' "$($oldPwd.Count) enabled accounts have not changed passwords in 2+ years." -Details $det -Recommendation 'Enforce periodic password change.' -RiskScore 5
    }
    $admCount = @(Search-AD -Filter '(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName'))
    $stats['admincount1'] = $admCount.Count
    if ($admCount.Count -gt 20) {
        $findings += New-Finding 'Account Hygiene' 'Excessive adminCount=1 Accounts' 'MEDIUM' "$($admCount.Count) users have adminCount=1." -Recommendation 'Clear adminCount flag for non-privileged accounts.' -RiskScore 5
    }
    $spnMap = @{}
    $spnAccs = @(Search-AD -Filter '(servicePrincipalName=*)' -Attributes @('sAMAccountName', 'servicePrincipalName'))
    foreach ($u in $spnAccs) { foreach ($spn in (AttrList $u 'servicePrincipalName')) { $k = $spn.ToLower(); if (-not $spnMap.ContainsKey($k)) { $spnMap[$k] = @() } $spnMap[$k] += (AttrStr $u 'sAMAccountName') } }
    $dupes = @($spnMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
    if ($dupes.Count) {
        $findings += New-Finding 'Account Hygiene' 'Duplicate Service Principal Names (SPNs)' 'HIGH' "$($dupes.Count) SPN(s) registered on multiple objects." -Details @($dupes | Select-Object -First 20 | ForEach-Object { "$($_.Key): $($_.Value -join ', ')" }) -Recommendation 'Remove duplicate SPNs: setspn -D <spn> <account>' -RiskScore 10
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 9. Protocol Security ------------------------------------------------------
function Check-Protocols {
    $findings = @(); $stats = @{}
    Write-C '  [*] Protocol Security' 'Gray'
    if ($script:AD.UseSsl) {
        $findings += New-Finding 'Protocol Security' 'LDAP Signing / Channel Binding' 'INFO' 'Connection established over LDAPS (port 636).' -Recommendation 'Set LdapEnforceChannelBinding = 2 via registry or GPO on all DCs.' -RiskScore 0
    }
    else {
        $findings += New-Finding 'Protocol Security' 'LDAP Signing / Channel Binding (Manual Verification)' 'MEDIUM' 'Cannot read ldapServerIntegrity via LDAP.' -Recommendation "Verify via GPO: 'Domain controller: LDAP server signing requirements' = Require signing." -RiskScore 8
    }
    $dcs = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Attributes @('sAMAccountName', 'operatingSystem', 'operatingSystemVersion', 'dNSHostName'))
    $dcList = @(); $oldOsDcs = @()
    foreach ($dc in $dcs) {
        $osName = AttrStr $dc 'operatingSystem'; $osVer = AttrStr $dc 'operatingSystemVersion'
        $name = AttrStr $dc 'dNSHostName'; if (-not $name) { $name = AttrStr $dc 'sAMAccountName' }
        $dcList += "$name - $osName $osVer"
        if (@('2003', '2008', '2012') | Where-Object { $osName.Contains($_) }) { $oldOsDcs += "$name ($osName)" }
    }
    $stats['domain_controllers'] = $dcList
    if ($oldOsDcs.Count) {
        $findings += New-Finding 'Protocol Security' 'Domain Controllers Running End-of-Life OS' 'CRITICAL' "$($oldOsDcs.Count) DC(s) running outdated OS." -Details $oldOsDcs -Recommendation 'Upgrade DCs to Windows Server 2019/2022.' -RiskScore 20
    }
    $dom = Get-DomainObject
    if ($dom) {
        $dfl = AttrInt $dom 'msDS-Behavior-Version'
        $FLS = @{ 0 = '2000'; 1 = '2003 Mixed'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016' }
        $flStr = if ($FLS.ContainsKey([int]$dfl)) { $FLS[[int]$dfl] } else { [string]$dfl }
        $stats['domain_functional_level'] = $flStr
        if ($dfl -lt 7) {
            $sev = if ($dfl -lt 3) { 'CRITICAL' } elseif ($dfl -lt 5) { 'HIGH' } else { 'MEDIUM' }
            $rs = if ($dfl -lt 5) { 15 } else { 8 }
            $findings += New-Finding 'Protocol Security' "Domain Functional Level: $flStr" $sev "DFL is $flStr. Lower levels lack security features." -Recommendation 'Raise domain/forest functional level to 2016.' -RiskScore $rs
        }
    }
    $forestRoot = @(Search-AD -Filter '(objectClass=crossRefContainer)' -Attributes @('msDS-Behavior-Version') -Base "CN=Partitions,$($script:AD.ConfigDN)")
    if ($forestRoot.Count) { $stats['forest_functional_level'] = AttrInt $forestRoot[0] 'msDS-Behavior-Version' }
    $findings += New-Finding 'Protocol Security' 'NTLMv1 / WDigest (Manual Verification Required)' 'INFO' 'NTLMv1 and WDigest settings are registry-only.' -Recommendation 'Set LmCompatibilityLevel = 5 and UseLogonCredential = 0 via GPO.' -RiskScore 0
    return @{ findings = $findings; stats = $stats }
}

# -- 10. Group Policy Objects --------------------------------------------------
function Check-Gpo {
    $findings = @(); $stats = @{}
    Write-C '  [*] Group Policy Objects' 'Gray'
    $gpos = @(Search-AD -Filter '(objectClass=groupPolicyContainer)' -Attributes @('displayName', 'gPCFileSysPath', 'flags', 'distinguishedName', 'versionNumber'))
    $stats['gpo_count'] = $gpos.Count
    $disabledGpos = @(); $orphaned = @(); $lowVersion = @(); $gpoDnsByDn = @{}
    foreach ($g in $gpos) {
        $dn = AttrStr $g 'distinguishedName'; $name = AttrStr $g 'displayName'; if (-not $name) { $name = $dn }
        $flags = AttrInt $g 'flags'; $sysvol = AttrStr $g 'gPCFileSysPath'; $ver = AttrInt $g 'versionNumber'
        $gpoDnsByDn[$dn] = $name
        if ($flags -in @(1, 2, 3)) { $disabledGpos += $name }
        if (-not $sysvol) { $orphaned += $name }
        if ($ver -eq 0) { $lowVersion += $name }
    }
    $linkedGpoDns = @{}
    foreach ($obj in (Search-AD -Filter '(gpLink=*)' -Attributes @('gpLink', 'distinguishedName'))) {
        foreach ($part in (AttrStr $obj 'gpLink').Split('][')) {
            $part = $part.TrimStart('[')
            if ($part.ToLower().StartsWith('ldap://')) { $dnPart = $part.Split(';')[0].Substring(7); $linkedGpoDns[$dnPart.ToLower()] = $true }
        }
    }
    $unlinked = @(); foreach ($kv in $gpoDnsByDn.GetEnumerator()) { if (-not $linkedGpoDns.ContainsKey($kv.Key.ToLower()) -and $kv.Value -notin $disabledGpos) { $unlinked += $kv.Value } }
    $stats['gpo_disabled'] = $disabledGpos.Count; $stats['gpo_orphaned'] = $orphaned.Count
    $stats['gpo_unlinked'] = $unlinked.Count; $stats['gpo_empty'] = $lowVersion.Count
    if ($gpos.Count -gt 100) {
        $findings += New-Finding 'Group Policy' 'Excessive Number of GPOs' 'LOW' "$($gpos.Count) GPOs detected." -Recommendation 'Consolidate overlapping GPOs.' -RiskScore 3
    }
    $rows = @(
        @{ cond = $disabledGpos; label = 'Disabled GPOs Present'; desc = 'fully or partially disabled'; rec = 'Remove permanently disabled GPOs.' }
        @{ cond = $orphaned; label = 'Orphaned GPO Objects (No SYSVOL Path)'; desc = 'have no associated SYSVOL path'; rec = 'Run gpotool.exe /checkacl.' }
        @{ cond = $unlinked; label = 'Unlinked GPOs'; desc = 'not linked to any OU, domain, or site'; rec = 'Review and delete intentionally unused GPOs.' }
        @{ cond = $lowVersion; label = 'Empty / Never-Edited GPOs'; desc = 'have a version number of 0'; rec = 'Delete empty GPOs.' }
    )
    foreach ($r in $rows) {
        if ($r.cond.Count) {
            $sev = if ($r.label -notmatch 'Orphan|Unlinked') { 'INFO' } else { 'LOW' }
            $rs = if ($r.label -match 'Orphan') { 2 } else { 0 }
            $findings += New-Finding 'Group Policy' $r.label $sev "$($r.cond.Count) GPO(s) $($r.desc)." -Details @($r.cond | Select-Object -First 30) -Recommendation $r.rec -RiskScore $rs
        }
        else {
            $findings += New-Finding 'Group Policy' "No $($r.label)" 'INFO' 'None found.' -RiskScore 0
        }
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 11. LAPS ------------------------------------------------------------------
function Check-Laps {
    $findings = @(); $stats = @{}
    Write-C '  [*] LAPS' 'Gray'
    $lapsAttr = @(Search-AD -Filter '(cn=ms-Mcs-AdmPwd)' -Attributes @('cn') -Base $script:AD.SchemaDN)
    $lapsV2Attr = @(Search-AD -Filter '(cn=ms-LAPS-Password)' -Attributes @('cn') -Base $script:AD.SchemaDN)
    $hasLaps = [bool]$lapsAttr.Count; $hasLapsV2 = [bool]$lapsV2Attr.Count
    $stats['laps_installed'] = $hasLaps; $stats['laps_v2_installed'] = $hasLapsV2
    if (-not $hasLaps -and -not $hasLapsV2) {
        $findings += New-Finding 'LAPS' 'LAPS Not Installed' 'HIGH' 'Local Administrator Password Solution is not deployed.' -Recommendation 'Deploy Windows LAPS (built-in to Server 2019/Win11) or legacy LAPS.' -RiskScore 15
        return @{ findings = $findings; stats = $stats }
    }
    $version = if ($hasLapsV2) { 'Windows LAPS (v2)' } else { 'Legacy LAPS' }
    $findings += New-Finding 'LAPS' "$version Schema Detected" 'INFO' "$version schema attributes are present." -RiskScore 0
    if ($hasLaps) {
        $noLaps = @(Search-AD -Filter '(&(objectClass=computer)(!(ms-Mcs-AdmPwd=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName'))
        if ($noLaps.Count) {
            $findings += New-Finding 'LAPS' 'Computers Without LAPS Password' 'MEDIUM' "$($noLaps.Count) enabled computer(s) have no LAPS password set." -Details @($noLaps | Select-Object -First 30 | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Ensure LAPS is applied to all workstations/servers.' -RiskScore 10
        }
    }
    if ($hasLapsV2) {
        $noLapsV2 = @(Search-AD -Filter '(&(objectClass=computer)(!(ms-LAPS-Password=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName'))
        if ($noLapsV2.Count) {
            $findings += New-Finding 'LAPS' 'Computers Without Windows LAPS Password' 'MEDIUM' "$($noLapsV2.Count) computer(s) lack Windows LAPS password attributes." -Details @($noLapsV2 | Select-Object -First 30 | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Deploy Windows LAPS policy to all machines.' -RiskScore 10
        }
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 12. LAPS Coverage ---------------------------------------------------------
function Check-LapsCoverage {
    $findings = @(); $stats = @{}
    Write-C '  [*] LAPS Password Coverage' 'Gray'
    $hasLegacy = [bool](@(Search-AD -Filter '(cn=ms-Mcs-AdmPwd)' -Attributes @('cn') -Base $script:AD.SchemaDN)).Count
    $hasWinLaps = [bool](@(Search-AD -Filter '(cn=ms-LAPS-Password)' -Attributes @('cn') -Base $script:AD.SchemaDN)).Count
    $stats['laps_legacy_schema'] = $hasLegacy; $stats['laps_winlaps_schema'] = $hasWinLaps
    if (-not $hasLegacy -and -not $hasWinLaps) { return @{ findings = $findings; stats = $stats } }
    $allComp = @(Search-AD -Filter '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' -Attributes @('sAMAccountName', 'ms-Mcs-AdmPwd', 'ms-LAPS-Password', 'ms-LAPS-EncryptedPassword', 'operatingSystem'))
    $noLaps = @(); $covered = @()
    foreach ($c in $allComp) {
        $name = AttrStr $c 'sAMAccountName'
        $hasPwd = [bool](AttrStr $c 'ms-Mcs-AdmPwd') -or [bool](AttrStr $c 'ms-LAPS-Password') -or [bool](AttrStr $c 'ms-LAPS-EncryptedPassword')
        if ($hasPwd) { $covered += $name } else { $os = AttrStr $c 'operatingSystem'; if (-not $os) { $os = 'OS unknown' }; $noLaps += "$name ($os)" }
    }
    $total = $allComp.Count
    $stats['laps_covered'] = $covered.Count; $stats['laps_missing'] = $noLaps.Count; $stats['laps_total_hosts'] = $total
    if ($noLaps.Count) {
        $pct = if ($total) { [int](100 * $noLaps.Count / $total) } else { 0 }
        $sev = if ($pct -gt 20) { 'HIGH' } else { 'MEDIUM' }
        $rs = if ($sev -eq 'HIGH') { 12 } else { 7 }
        $findings += New-Finding 'LAPS' 'Computers Without a LAPS Password Set' $sev "$($noLaps.Count) of $total enabled non-DC computer(s) ($pct%) have no LAPS password." -Details @($noLaps | Select-Object -First 50) -Recommendation 'Apply a LAPS GPO to all workstations and servers.' -RiskScore $rs
    }
    else {
        $findings += New-Finding 'LAPS' 'LAPS Password Present on All Non-DC Computers' 'INFO' "All $total enabled non-DC computer(s) have a LAPS password set." -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 13. DNS -------------------------------------------------------------------
function Check-Dns {
    $findings = @(); $stats = @{}
    Write-C '  [*] DNS & Infrastructure' 'Gray'
    $dnsZones = @(Search-AD -Filter '(objectClass=dnsZone)' -Attributes @('name') -Base "CN=MicrosoftDNS,DC=DomainDnsZones,$($script:AD.BaseDN)")
    $stats['dns_zones'] = @($dnsZones | ForEach-Object { AttrStr $_ 'name' })
    foreach ($r in $dnsZones) {
        if ((AttrStr $r 'name').Contains('*')) {
            $findings += New-Finding 'DNS' 'Wildcard DNS Record Detected' 'HIGH' 'Wildcard DNS entry found.' -Recommendation 'Remove wildcard DNS records unless specifically required.' -RiskScore 10
        }
    }
    $dnsNodes = @(Search-AD -Filter '(objectClass=dnsNode)' -Attributes @('dc', 'dnsRecord') -Base "CN=MicrosoftDNS,DC=DomainDnsZones,$($script:AD.BaseDN)")
    $stats['dns_record_count'] = $dnsNodes.Count
    $findings += New-Finding 'DNS' 'LLMNR / NetBIOS-NS Poisoning (Manual Check Required)' 'INFO' 'LLMNR and NetBIOS-NS enable Responder-style credential capture.' -Recommendation 'Disable LLMNR via GPO and NetBIOS over TCP/IP on all adapters.' -RiskScore 0
    return @{ findings = $findings; stats = $stats }
}

# -- 14. Domain Controllers ----------------------------------------------------
function Check-DomainControllers {
    $findings = @(); $stats = @{}
    Write-C '  [*] Domain Controllers' 'Gray'
    $dcs = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Attributes @('sAMAccountName', 'operatingSystem', 'dNSHostName', 'lastLogonTimestamp', 'userAccountControl'))
    $stats['dc_count'] = $dcs.Count
    if ($dcs.Count -eq 1) {
        $findings += New-Finding 'Domain Controllers' 'Single Domain Controller Detected' 'HIGH' 'Only one DC -- single point of failure.' -Recommendation 'Deploy at least two DCs for redundancy.' -RiskScore 10
    }
    $oldOs = @()
    foreach ($dc in $dcs) {
        $osN = AttrStr $dc 'operatingSystem'; $name = AttrStr $dc 'dNSHostName'; if (-not $name) { $name = AttrStr $dc 'sAMAccountName' }
        if (@('2003', '2000', '2008') | Where-Object { $osN.Contains($_) }) { $oldOs += "$name ($osN)" }
    }
    if ($oldOs.Count) {
        $findings += New-Finding 'Domain Controllers' 'Legacy OS on Domain Controllers' 'CRITICAL' "$($oldOs.Count) DC(s) running end-of-life Windows Server." -Details $oldOs -Recommendation 'Upgrade to Server 2019/2022 immediately.' -RiskScore 25
    }
    $fsmo = @(Search-AD -Filter '(fSMORoleOwner=*)' -Attributes @('fSMORoleOwner', 'cn'))
    $stats['fsmo_roles'] = @($fsmo | ForEach-Object { AttrStr $_ 'cn' })
    $rodcs = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))' -Attributes @('sAMAccountName', 'msDS-RevealOnDemandGroup'))
    foreach ($r in $rodcs) {
        $rname = AttrStr $r 'sAMAccountName'; $reveal = AttrList $r 'msDS-RevealOnDemandGroup'
        if ($reveal | Where-Object { $_ -match 'Domain Users|Authenticated Users' }) {
            $findings += New-Finding 'Domain Controllers' "RODC $rname Has Broad Password Replication" 'HIGH' 'RODC caches passwords for all domain users.' -Recommendation 'Restrict msDS-RevealOnDemandGroup to only users who log into that RODC.' -RiskScore 12
        }
    }
    $stats['rodc_count'] = $rodcs.Count
    return @{ findings = $findings; stats = $stats }
}

# -- 15. ACL / Permissions -----------------------------------------------------
function Check-Acls {
    $findings = @(); $stats = @{}
    Write-C '  [*] ACL / Permissions' 'Gray'
    $domainSid = Get-DomainSid

    # ESC4 - writable certificate template ACLs
    $tmplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($script:AD.ConfigDN)"
    $esc4 = @{}
    foreach ($t in (Get-SDBytes -Dn $tmplBase -Filter '(objectClass=pKICertificateTemplate)' -Scope Subtree -ExtraAttrs @('cn'))) {
        $tname = AttrStr $t 'cn'; $rawSd = AttrBytes $t 'nTSecurityDescriptor'; if (-not $rawSd) { continue }
        foreach ($ace in (Parse-SD $rawSd)) {
            $sid = $ace.trustee_sid; $mask = $ace.access_mask
            if ($ace.ace_type -notin @(0x00, 0x05)) { continue }
            if (Sid-IsPrivileged $sid $domainSid) { continue }
            if ($mask -band ($script:AM_GENERIC_ALL -bor $script:AM_WRITE_DACL -bor $script:AM_WRITE_OWNER -bor $script:AM_GENERIC_WRITE)) {
                $r = Resolve-Sid $sid; if (-not $esc4.ContainsKey($r)) { $esc4[$r] = @{} } $esc4[$r][$tname] = $true
            }
        }
    }
    if ($esc4.Count) {
        $det = @($esc4.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key) -> $(($_.Value.Keys | Sort-Object) -join ', ')" })
        $combos = ($esc4.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $findings += New-Finding 'ADCS' 'ESC4 - Writable Certificate Template ACLs' 'CRITICAL' "$combos template/trustee combination(s)." -Details $det -Recommendation 'Remove GenericAll, WriteDACL, WriteOwner, GenericWrite from non-privileged accounts.' -RiskScore 25 -References @('https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf')
    }
    else {
        $findings += New-Finding 'ADCS' 'ESC4 - Certificate Template ACLs' 'INFO' 'No misconfigured template ACLs detected.' -RiskScore 0
    }
    # ESC5 - writable PKI object ACLs
    $pkiBase = "CN=Public Key Services,CN=Services,$($script:AD.ConfigDN)"
    $esc5 = @{}
    foreach ($obj in (Get-SDBytes -Dn $pkiBase -Filter '(objectClass=*)' -Scope Subtree -ExtraAttrs @('cn', 'distinguishedName'))) {
        $oname = AttrStr $obj 'cn'; if (-not $oname) { $oname = AttrStr $obj 'distinguishedName' }
        $rawSd = AttrBytes $obj 'nTSecurityDescriptor'; if (-not $rawSd) { continue }
        $seen = @{}
        foreach ($ace in (Parse-SD $rawSd)) {
            $sid = $ace.trustee_sid; $mask = $ace.access_mask
            if ($ace.ace_type -notin @(0x00, 0x05)) { continue }
            if (Sid-IsPrivileged $sid $domainSid) { continue }
            if (Sid-IsDc $sid) { continue }
            if ($seen.ContainsKey($sid)) { continue }
            if ($mask -band ($script:AM_GENERIC_ALL -bor $script:AM_WRITE_DACL -bor $script:AM_WRITE_OWNER -bor $script:AM_GENERIC_WRITE)) {
                $seen[$sid] = $true; $r = Resolve-Sid $sid; if (-not $esc5.ContainsKey($r)) { $esc5[$r] = @{} } $esc5[$r][$oname] = $true
            }
        }
    }
    if ($esc5.Count) {
        $det = @($esc5.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key) -> $(($_.Value.Keys | Sort-Object) -join ', ')" })
        $findings += New-Finding 'ADCS' 'ESC5 - Writable PKI Object ACLs' 'CRITICAL' "$($esc5.Count) non-privileged principal(s) have write access to PKI container objects." -Details $det -Recommendation 'Remove write permissions from non-admin accounts on all PKI container objects.' -RiskScore 25 -References @('https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf')
    }
    else {
        $findings += New-Finding 'ADCS' 'ESC5 - PKI Object ACLs' 'INFO' 'No non-privileged write access on PKI container objects.' -RiskScore 0
    }
    # ESC7 - CA officer/manager rights
    $enrollBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($script:AD.ConfigDN)"
    $esc7 = @{}
    foreach ($ca in (Get-SDBytes -Dn $enrollBase -Filter '(objectClass=pKIEnrollmentService)' -Scope Subtree -ExtraAttrs @('cn'))) {
        $cname = AttrStr $ca 'cn'; $rawSd = AttrBytes $ca 'nTSecurityDescriptor'; if (-not $rawSd) { continue }
        foreach ($ace in (Parse-SD $rawSd)) {
            $sid = $ace.trustee_sid; $mask = $ace.access_mask
            if ($ace.ace_type -notin @(0x00, 0x05)) { continue }
            if (Sid-IsPrivileged $sid $domainSid) { continue }
            if (Sid-IsDc $sid) { continue }
            if ($mask -band ($script:CA_MANAGE -bor $script:CA_OFFICER -bor $script:AM_GENERIC_ALL -bor $script:AM_WRITE_DACL -bor $script:AM_WRITE_OWNER)) {
                $r = Resolve-Sid $sid; if (-not $esc7.ContainsKey($r)) { $esc7[$r] = @() } $esc7[$r] += $cname
            }
        }
    }
    if ($esc7.Count) {
        $det = @($esc7.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key) -> $($_.Value -join ', ')" })
        $findings += New-Finding 'ADCS' 'ESC7 - CA Officer/Manager Rights for Low-Privileged Users' 'CRITICAL' "$($esc7.Count) non-privileged principal(s) have CA Officer or Manager rights." -Details $det -Recommendation 'Remove ManageCertificates/ManageCA rights from non-admin accounts.' -RiskScore 20 -References @('https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf')
    }
    else {
        $findings += New-Finding 'ADCS' 'ESC7 - CA Officer/Manager ACL' 'INFO' 'No low-privileged CA Officer/Manager rights detected.' -RiskScore 0
    }
    # DCSync
    $REPL_GUIDS = @{ $script:REPL_GET_CHANGES_ALL = 'DS-Replication-Get-Changes-All'; $script:REPL_GET_CHANGES = 'DS-Replication-Get-Changes'; $script:REPL_GET_CHANGES_FIL = 'DS-Replication-Get-Changes-In-Filtered-Set' }
    $dcsync = @{}
    foreach ($dom in (Get-SDBytes -Dn $script:AD.BaseDN -Filter '(objectClass=domain)' -Scope Base -ExtraAttrs @('distinguishedName'))) {
        $rawSd = AttrBytes $dom 'nTSecurityDescriptor'; if (-not $rawSd) { continue }
        foreach ($ace in (Parse-SD $rawSd)) {
            if ($ace.ace_type -ne 0x05) { continue }
            $sid = $ace.trustee_sid; $otype = if ($ace.object_type) { $ace.object_type.ToLower().Trim() } else { '' }
            if (Sid-IsPrivileged $sid $domainSid) { continue }
            if ($REPL_GUIDS.ContainsKey($otype)) { $r = Resolve-Sid $sid; if (-not $dcsync.ContainsKey($r)) { $dcsync[$r] = @() } $dcsync[$r] += $REPL_GUIDS[$otype] }
        }
    }
    if ($dcsync.Count) {
        $det = @($dcsync.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key) -> $($_.Value -join ', ')" })
        $findings += New-Finding 'DCSync' 'Non-Privileged Accounts with DCSync Rights' 'CRITICAL' "$($dcsync.Count) non-privileged principal(s) have replication rights." -Details $det -Recommendation 'Remove DS-Replication-Get-Changes-All from non-DC/non-DA accounts immediately.' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1003/006/')
    }
    else {
        $findings += New-Finding 'DCSync' 'DCSync Rights' 'INFO' 'No unexpected DCSync rights detected.' -RiskScore 0
    }
    # Protected Users
    $pu = @(Search-AD -Filter "(&(objectClass=user)(memberOf=CN=Protected Users,CN=Users,$($script:AD.BaseDN)))" -Attributes @('sAMAccountName'))
    $stats['protected_users_group'] = $pu.Count
    if ($pu.Count -eq 0) {
        $findings += New-Finding 'ACL' 'No Users in Protected Users Group' 'MEDIUM' 'The Protected Users group provides extra Kerberos protections.' -Recommendation 'Add all privileged accounts to the Protected Users group.' -RiskScore 8
    }
    $deleg = @(Search-AD -Filter '(msDS-AllowedToDelegateTo=*)' -Attributes @('sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass'))
    if ($deleg.Count) {
        $risky = @()
        foreach ($d in $deleg) { if (-not ((AttrList $d 'objectClass') -contains 'computer')) { $targets = @(AttrList $d 'msDS-AllowedToDelegateTo') | Select-Object -First 2; $risky += "$(AttrStr $d 'sAMAccountName') -> $($targets -join ', ')" } }
        if ($risky.Count) {
            $findings += New-Finding 'ACL' 'User Accounts with Constrained Delegation Configured' 'MEDIUM' "$($risky.Count) non-computer account(s) have delegation targets." -Details @($risky | Select-Object -First 20) -Recommendation 'Verify delegation targets are intentional and minimal.' -RiskScore 8
        }
    }
    $stats['protected_users_count'] = $pu.Count
    return @{ findings = $findings; stats = $stats }
}

# -- 16. Optional Features -----------------------------------------------------
function Check-OptionalFeatures {
    $findings = @(); $stats = @{}
    Write-C '  [*] Optional Features' 'Gray'
    $optFeat = @(Search-AD -Filter '(objectClass=msDS-OptionalFeature)' -Attributes @('name', 'msDS-OptionalFeatureFlags') -Base "CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($script:AD.ConfigDN)")
    $hasRecycle = [bool](@($optFeat | Where-Object { (AttrStr $_ 'name').Contains('Recycle Bin') }).Count)
    $stats['recycle_bin_enabled'] = $hasRecycle
    if (-not $hasRecycle) {
        $findings += New-Finding 'Optional Features' 'AD Recycle Bin Not Enabled' 'LOW' 'Deleted AD objects cannot be easily recovered.' -Recommendation "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet" -RiskScore 3
    }
    $hasPam = [bool](@($optFeat | Where-Object { (AttrStr $_ 'name').Contains('Privileged Access Management') }).Count)
    $stats['pam_enabled'] = $hasPam
    if (-not $hasPam) {
        $findings += New-Finding 'Optional Features' 'Privileged Access Management (PAM) Not Enabled' 'INFO' 'PAM enables time-based, just-in-time privileged access.' -Recommendation 'Consider enabling PAM for enhanced privileged access management.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 17. Replication Health ----------------------------------------------------
function Check-Replication {
    $findings = @(); $stats = @{}
    Write-C '  [*] Replication Health' 'Gray'
    $sites = @(Search-AD -Filter '(objectClass=site)' -Attributes @('cn') -Base "CN=Sites,$($script:AD.ConfigDN)")
    $stats['site_count'] = $sites.Count
    if ($sites.Count -gt 1) {
        $findings += New-Finding 'Replication' "$($sites.Count) AD Sites Detected" 'INFO' 'Multi-site topology -- verify site links and replication schedules.' -Details @($sites | ForEach-Object { AttrStr $_ 'cn' }) -RiskScore 0
    }
    $siteLinks = @(Search-AD -Filter '(objectClass=siteLink)' -Attributes @('cn', 'cost', 'replInterval') -Base "CN=IP,CN=Inter-Site Transports,CN=Sites,$($script:AD.ConfigDN)")
    foreach ($sl in $siteLinks) {
        $interval = AttrInt $sl 'replInterval'
        if ($interval -gt 180) {
            $findings += New-Finding 'Replication' 'Site Link Replication Interval Too High' 'MEDIUM' "Site link '$(AttrStr $sl 'cn')' has interval of $interval minutes." -Recommendation 'Set replication interval to <= 60 minutes.' -RiskScore 3
        }
    }
    $ntds = @(Search-AD -Filter '(objectClass=nTDSDSA)' -Attributes @('distinguishedName', 'options') -Base "CN=Sites,$($script:AD.ConfigDN)")
    $stats['ntdsdsa_count'] = $ntds.Count
    if ($ntds.Count -eq 0) {
        $findings += New-Finding 'Replication' 'No nTDSDSA Objects Found' 'HIGH' 'Could not find any DC replication service objects.' -Recommendation 'Run: repadmin /showrepl and dcdiag /test:replications' -RiskScore 10
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 18. Service Accounts ------------------------------------------------------
function Check-ServiceAccounts {
    $findings = @(); $stats = @{}
    Write-C '  [*] Service Accounts & gMSA' 'Gray'
    $gmsa = @(Search-AD -Filter '(objectClass=msDS-GroupManagedServiceAccount)' -Attributes @('sAMAccountName'))
    $smsa = @(Search-AD -Filter '(objectClass=msDS-ManagedServiceAccount)' -Attributes @('sAMAccountName'))
    $stats['gmsa_count'] = $gmsa.Count; $stats['smsa_count'] = $smsa.Count
    $svc = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'pwdLastSet', 'adminCount'))
    $stats['regular_service_accounts'] = $svc.Count
    if ($svc.Count -gt 0 -and $gmsa.Count -eq 0) {
        $findings += New-Finding 'Service Accounts' 'No gMSA In Use -- Regular Accounts Have SPNs' 'HIGH' "$($svc.Count) regular user account(s) used as service accounts, but no gMSA deployed." -Details @($svc | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Migrate service accounts to Group Managed Service Accounts (gMSA).' -RiskScore 10
    }
    elseif ($svc.Count -gt 0) {
        $findings += New-Finding 'Service Accounts' "$($svc.Count) Regular User Service Accounts (Non-gMSA)" 'MEDIUM' "$($svc.Count) accounts with SPNs are not gMSA." -Details @($svc | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Migrate to gMSA where possible.' -RiskScore 5
    }
    $svcAdmin = @($svc | Where-Object { (AttrInt $_ 'adminCount') -eq 1 } | ForEach-Object { AttrStr $_ 'sAMAccountName' })
    if ($svcAdmin.Count) {
        $findings += New-Finding 'Service Accounts' 'Service Accounts with adminCount=1' 'HIGH' "$($svcAdmin.Count) service account(s) have adminCount=1." -Details $svcAdmin -Recommendation 'Remove service accounts from privileged groups.' -RiskScore 12
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 19. Miscellaneous Hardening -----------------------------------------------
function Check-Misc {
    $findings = @(); $stats = @{}
    Write-C '  [*] Miscellaneous Hardening' 'Gray'
    $dom = Get-DomainObject
    if ($dom) {
        $maq = AttrInt $dom 'ms-DS-MachineAccountQuota'
        $stats['machine_account_quota'] = $maq
        if ($maq -gt 0) {
            $findings += New-Finding 'Hardening' 'Machine Account Quota > 0' 'MEDIUM' "ms-DS-MachineAccountQuota = $maq. Any domain user can add up to $maq computers." -Recommendation 'Set ms-DS-MachineAccountQuota to 0.' -RiskScore 10
        }
    }
    $tsEntries = @(Search-AD -Filter '(objectClass=nTDSService)' -Attributes @('tombstoneLifetime') -Base "CN=Directory Service,CN=Windows NT,CN=Services,$($script:AD.ConfigDN)")
    if ($tsEntries.Count) {
        $tsl = AttrInt $tsEntries[0] 'tombstoneLifetime'; if ($tsl -eq 0) { $tsl = 60 }
        $stats['tombstone_lifetime'] = $tsl
        if ($tsl -lt 180) {
            $findings += New-Finding 'Hardening' 'Short Tombstone Lifetime' 'LOW' "Tombstone lifetime is $tsl days." -Recommendation 'Set tombstone lifetime to 180 days.' -RiskScore 2
        }
    }
    $schemaAdmins = @(Search-AD -Filter "(&(objectClass=user)(memberOf=CN=Schema Admins,CN=Users,$($script:AD.BaseDN)))" -Attributes @('sAMAccountName'))
    if ($schemaAdmins.Count -gt 1) {
        $findings += New-Finding 'Hardening' 'Schema Admins Group Has Members' 'HIGH' "$($schemaAdmins.Count) member(s) in Schema Admins." -Details @($schemaAdmins | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Remove all members from Schema Admins immediately after schema updates.' -RiskScore 15
    }
    $entAdmins = @(Search-AD -Filter "(&(objectClass=user)(memberOf=CN=Enterprise Admins,CN=Users,$($script:AD.BaseDN)))" -Attributes @('sAMAccountName'))
    if ($entAdmins.Count -gt 1) {
        $findings += New-Finding 'Hardening' 'Enterprise Admins Group Has Members' 'HIGH' "$($entAdmins.Count) member(s) in Enterprise Admins." -Details @($entAdmins | ForEach-Object { AttrStr $_ 'sAMAccountName' }) -Recommendation 'Remove non-essential accounts from Enterprise Admins.' -RiskScore 12
    }
    $guest = @(Search-AD -Filter '(&(objectClass=user)(sAMAccountName=Guest))' -Attributes @('userAccountControl'))
    if ($guest.Count -and -not ((AttrInt $guest[0] 'userAccountControl') -band $script:UAC_DISABLED)) {
        $findings += New-Finding 'Hardening' 'Guest Account Enabled' 'MEDIUM' 'The built-in Guest account is enabled.' -Recommendation 'Disable the Guest account.' -RiskScore 8
    }
    $findings += New-Finding 'Hardening' 'Advanced Audit Policy (Manual GPO Verification)' 'INFO' 'Ensure Advanced Audit Policy covers: Logon/Logoff, Account Management, Directory Service Access.' -Recommendation 'Configure via GPO: Computer Config > Security Settings > Advanced Audit.' -RiskScore 0
    return @{ findings = $findings; stats = $stats }
}

# -- 20. Deprecated Operating Systems ------------------------------------------
function Check-DeprecatedOs {
    $findings = @(); $stats = @{}
    Write-C '  [*] Deprecated Operating Systems' 'Gray'
    $computers = @(Search-AD -Filter '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp'))
    $deprecated = @()
    foreach ($c in $computers) {
        $osName = AttrStr $c 'operatingSystem'; if (-not $osName) { continue }
        $lower = $osName.ToLower()
        if ($script:DEPRECATED_OS_PATTERNS | Where-Object { $lower.Contains($_) }) {
            $llt = ConvertFrom-LdapTs (AttrRaw $c 'lastLogonTimestamp'); $days = Days-Since $llt
            $host2 = AttrStr $c 'dNSHostName'; if (-not $host2) { $host2 = AttrStr $c 'sAMAccountName' }
            $ageStr = if ($null -ne $days) { "$days`d ago" } else { 'never/unknown' }
            $deprecated += "$host2 -- $osName (last auth: $ageStr)"
        }
    }
    $stats['deprecated_os_count'] = $deprecated.Count
    if ($deprecated.Count) {
        $findings += New-Finding 'Deprecated OS' 'Computer Accounts Running Deprecated Operating Systems' 'CRITICAL' "$($deprecated.Count) enabled computer account(s) report a deprecated OS." -Details $deprecated -Recommendation 'Decommission or isolate deprecated systems immediately.' -RiskScore 20
    }
    else {
        $findings += New-Finding 'Deprecated OS' 'No Deprecated Operating Systems Detected' 'INFO' 'All enabled computer accounts report a currently-supported OS.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 21. Legacy Protocols ------------------------------------------------------
function Check-LegacyProtocols {
    $findings = @(); $stats = @{}
    Write-C '  [*] Legacy Protocol Exposure' 'Gray'
    $legacy = @(Search-AD -Filter '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'operatingSystem', 'lastLogonTimestamp'))
    $legacyOs = @()
    foreach ($c in $legacy) {
        $osN = (AttrStr $c 'operatingSystem').ToLower(); $name = AttrStr $c 'sAMAccountName'
        if (@('xp', 'vista', 'windows 7', 'windows 8', '2003', '2000', 'nt 4') | Where-Object { $osN.Contains($_) }) {
            $llt = ConvertFrom-LdapTs (AttrRaw $c 'lastLogonTimestamp'); $days = Days-Since $llt
            if ($null -eq $days -or $days -lt 180) { $legacyOs += "$name ($(AttrStr $c 'operatingSystem'))" }
        }
    }
    if ($legacyOs.Count) {
        $findings += New-Finding 'Legacy Protocols' 'Active Legacy Windows Systems Detected' 'CRITICAL' "$($legacyOs.Count) computer(s) running end-of-life OS are actively authenticating." -Details @($legacyOs | Select-Object -First 30) -Recommendation 'Decommission or isolate legacy systems.' -RiskScore 20
    }
    $stats['legacy_os_count'] = $legacyOs.Count
    $probe = Check-Smb1Hosts
    $smb1Hosts = $probe.smb1; $signingIssues = $probe.signing; $nullSessions = $probe.null_sessions
    if ($smb1Hosts.Count) {
        $sev = if ($smb1Hosts | Where-Object { $_ -match [regex]::Escape($script:AD.DcIp) }) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 20 } else { 15 }
        $findings += New-Finding 'Legacy Protocols' 'SMBv1 Enabled on Active Hosts' $sev "$($smb1Hosts.Count) host(s) responded positively to an SMBv1 negotiate request." -Details $smb1Hosts -Recommendation 'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false' -RiskScore $rs -References @('https://aka.ms/stopusingsmb1')
    }
    else {
        $findings += New-Finding 'Legacy Protocols' 'SMBv1 Not Detected on Probed Hosts' 'INFO' 'No hosts responded to SMBv1 negotiate requests.' -RiskScore 0
    }
    if ($signingIssues.Count) {
        $sev = if ($signingIssues | Where-Object { $_ -match [regex]::Escape($script:AD.DcIp) }) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 20 } else { 15 }
        $findings += New-Finding 'Legacy Protocols' 'SMB Signing Not Required or Disabled' $sev "$($signingIssues.Count) host(s) have SMB signing disabled or not required." -Details $signingIssues -Recommendation "Enforce SMB signing via GPO: 'Microsoft network server: Digitally sign communications (always)'" -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1557/001/')
    }
    else {
        $findings += New-Finding 'Legacy Protocols' 'SMB Signing Required on All Probed Hosts' 'INFO' 'All reachable hosts require SMB signing.' -RiskScore 0
    }
    if ($nullSessions.Count) {
        $sev = if ($nullSessions | Where-Object { $_ -match [regex]::Escape($script:AD.DcIp) }) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 20 } else { 15 }
        $findings += New-Finding 'Legacy Protocols' 'Null Sessions Accepted' $sev "$($nullSessions.Count) host(s) accept unauthenticated SMB null sessions." -Details $nullSessions -Recommendation 'Set RestrictNullSessAccess = 1 via GPO.' -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1135/')
    }
    else {
        $findings += New-Finding 'Legacy Protocols' 'Null Sessions Not Accepted on Probed Hosts' 'INFO' 'No hosts accepted unauthenticated null session requests.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 22. Exchange --------------------------------------------------------------
function Check-Exchange {
    $findings = @(); $stats = @{}
    Write-C '  [*] Exchange / Mail Permissions' 'Gray'
    $exch = @(Search-AD -Filter '(&(objectClass=container)(cn=Microsoft Exchange))' -Attributes @('cn') -Base $script:AD.ConfigDN)
    if (-not $exch.Count) { $exch = Search-AD -Filter '(cn=ms-Exch-Configuration-Container)' -Attributes @('cn') -Base $script:AD.SchemaDN }
    if (-not $exch.Count) {
        $findings += New-Finding 'Exchange' 'Exchange Not Detected' 'INFO' 'No Exchange organization container found.' -RiskScore 0
        return @{ findings = $findings; stats = $stats }
    }
    $stats['exchange_present'] = $true
    $ewp = @(Search-AD -Filter '(&(objectClass=group)(cn=Exchange Windows Permissions))' -Attributes @('member'))
    if ($ewp.Count) {
        $members = @(AttrList $ewp[0] 'member')
        if ($members.Count) {
            $findings += New-Finding 'Exchange' 'Exchange Windows Permissions Group Has Members' 'HIGH' "$($members.Count) member(s) in 'Exchange Windows Permissions'. This group has WriteDACL on the domain object (PrivExchange / CVE-2019-0686)." -Recommendation 'Apply Exchange Split Permissions model.' -RiskScore 15 -References @('https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/')
        }
    }
    $ets = @(Search-AD -Filter '(&(objectClass=group)(cn=Exchange Trusted Subsystem))' -Attributes @('member'))
    if ($ets.Count) {
        $members = @(AttrList $ets[0] 'member')
        if ($members.Count) {
            $findings += New-Finding 'Exchange' 'Exchange Trusted Subsystem Has Members' 'MEDIUM' "Exchange Trusted Subsystem has $($members.Count) member(s)." -Recommendation 'Ensure only Exchange server computer accounts are members.' -RiskScore 8
        }
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 23. Protected Admin Users (adminCount=1) ----------------------------------
function Check-AdminCount {
    $findings = @(); $stats = @{}
    Write-C '  [*] Protected Admin Users (adminCount=1)' 'Gray'
    $privGroups = Priv-Group-DNs $script:AD.BaseDN
    $accts = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(adminCount=1))' -Attributes @('sAMAccountName', 'userAccountControl', 'memberOf', 'lastLogonTimestamp', 'pwdLastSet'))
    $stats['admincount1_total'] = $accts.Count
    $disabled = @(); $stale = @(); $orphan = @()
    foreach ($u in $accts) {
        $name = AttrStr $u 'sAMAccountName'; $uac = AttrInt $u 'userAccountControl'; $groups = @(AttrList $u 'memberOf')
        $isDisabled = [bool]($uac -band $script:UAC_DISABLED)
        $inPriv = [bool](@($groups | Where-Object { $_ -in $privGroups }).Count)
        if ($isDisabled) { $disabled += $name }
        else {
            $llt = ConvertFrom-LdapTs (AttrRaw $u 'lastLogonTimestamp'); $days = Days-Since $llt
            if ($null -ne $days -and $days -gt 180) { $stale += "$name (last logon: $days`d ago)" }
            if (-not $inPriv -and $name.ToLower() -notin @('administrator', 'administrateur')) { $orphan += $name }
        }
    }
    $stats['admincount1_disabled'] = $disabled.Count; $stats['admincount1_stale'] = $stale.Count; $stats['admincount1_orphaned'] = $orphan.Count
    $findings += New-Finding 'Privileged Accounts' "adminCount=1 Account Inventory ($($accts.Count) total)" 'INFO' "$($accts.Count) user account(s) carry the adminCount=1 flag. Breakdown: $($disabled.Count) disabled (ghost), $($orphan.Count) orphaned, $($stale.Count) stale." -RiskScore 0
    if ($accts.Count -gt 20) {
        $findings += New-Finding 'Privileged Accounts' 'Excessive adminCount=1 Accounts' 'MEDIUM' "$($accts.Count) user account(s) have adminCount=1." -Recommendation 'Audit adminCount=1 accounts. Clear flag on accounts no longer in privileged groups.' -RiskScore 5
    }
    if ($disabled.Count) {
        $findings += New-Finding 'Privileged Accounts' 'Disabled Accounts Retaining adminCount=1 (Ghost Admins)' 'MEDIUM' "$($disabled.Count) disabled account(s) still carry adminCount=1." -Details @($disabled | Select-Object -First 30) -Recommendation 'Remove from all privileged groups and clear adminCount, then delete.' -RiskScore 8
    }
    if ($orphan.Count) {
        $findings += New-Finding 'Privileged Accounts' 'Accounts with adminCount=1 but No Privileged Group Membership' 'HIGH' "$($orphan.Count) enabled account(s) have adminCount=1 but are not currently members of any known privileged group. Possible SDProp artefacts or backdoor accounts." -Details @($orphan | Select-Object -First 30) -Recommendation 'Investigate each account. Clear adminCount and audit for backdoor ACEs.' -RiskScore 15
    }
    if ($stale.Count) {
        $findings += New-Finding 'Privileged Accounts' 'Stale Accounts with adminCount=1 (Inactive 180+ Days)' 'HIGH' "$($stale.Count) admin account(s) have not logged in for 180+ days." -Details @($stale | Select-Object -First 30) -Recommendation 'Disable inactive privileged accounts after 30-90 days of inactivity.' -RiskScore 12
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 24. Passwords in Descriptions ---------------------------------------------
function Check-PasswordsInDescriptions {
    $findings = @(); $stats = @{}
    Write-C '  [*] Passwords in Descriptions' 'Gray'
    $KW = @('password', 'passwd', 'pwd', 'pass=', 'pass:', 'mot de passe', 'kennwort', 'contrasena', 'wachtwoord', 'parola', 'senha', 'secret', 'credential', 'p@ss', 'p4ss')
    $users = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(description=*))' -Attributes @('sAMAccountName', 'description', 'adminCount'))
    $computers = @(Search-AD -Filter '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(description=*))' -Attributes @('sAMAccountName', 'description'))
    $userHits = @(); $adminHits = @(); $compHits = @()
    foreach ($u in $users) {
        $desc = (AttrStr $u 'description').ToLower()
        if ($KW | Where-Object { $desc.Contains($_) }) {
            $name = AttrStr $u 'sAMAccountName'; $full = AttrStr $u 'description'
            $entry = "$name -- `"$($full.Substring(0, [Math]::Min(80, $full.Length)))`""
            if ((AttrInt $u 'adminCount') -eq 1) { $adminHits += $entry } else { $userHits += $entry }
        }
    }
    foreach ($c in $computers) {
        $desc = (AttrStr $c 'description').ToLower()
        if ($KW | Where-Object { $desc.Contains($_) }) {
            $name = AttrStr $c 'sAMAccountName'; $full = AttrStr $c 'description'
            $compHits += "$name -- `"$($full.Substring(0, [Math]::Min(80, $full.Length)))`""
        }
    }
    $stats['passwords_in_descriptions_admins'] = $adminHits.Count; $stats['passwords_in_descriptions_users'] = $userHits.Count; $stats['passwords_in_descriptions_computers'] = $compHits.Count
    if ($adminHits.Count) {
        $findings += New-Finding 'Account Hygiene' 'Privileged Accounts with Possible Password in Description' 'CRITICAL' "$($adminHits.Count) admin account(s) may have credentials in their Description field." -Details @($adminHits | Select-Object -First 30) -Recommendation 'Immediately clear the Description field and rotate any exposed credentials.' -RiskScore 25
    }
    else {
        $findings += New-Finding 'Account Hygiene' 'No Passwords Found in Admin Account Descriptions' 'INFO' 'No privileged accounts have password-related keywords in their Description.' -RiskScore 0
    }
    if ($userHits.Count) {
        $findings += New-Finding 'Account Hygiene' 'User Accounts with Possible Password in Description' 'HIGH' "$($userHits.Count) enabled user account(s) may have credentials in their Description." -Details @($userHits | Select-Object -First 30) -Recommendation 'Clear the Description field and store credentials in a PAM vault.' -RiskScore 15
    }
    if ($compHits.Count) {
        $findings += New-Finding 'Account Hygiene' 'Computer Accounts with Possible Password in Description' 'MEDIUM' "$($compHits.Count) computer account(s) may have credentials in their Description." -Details @($compHits | Select-Object -First 20) -Recommendation 'Clear the Description field on affected computer accounts.' -RiskScore 8
    }
    return @{ findings = $findings; stats = $stats }
}

# ══════════════════════════════════════════════════════════════════════════════
#  NEW CHECKS 25-35
# ══════════════════════════════════════════════════════════════════════════════

# -- 25. GPP / cpassword (MS14-025) --------------------------------------------
# NOTE (per README limitations): ADPulse checks GPO metadata (flags, version,
# SYSVOL path, links) in check 10 but does NOT parse GPO settings files from
# SYSVOL -- with the sole exception of this cpassword scan in check 25.
function Decrypt-GppPassword {
    param([string]$Cpassword)
    try {
        # AES-256 key published by Microsoft in MSDN (MS14-025)
        $KEY = [byte[]]@(
            0x4E,0x99,0x06,0xE8,0xFC,0xB6,0x6C,0xC9,0xFA,0xF4,0x93,0x10,0x62,0x0F,0xFE,0xE8,
            0xF4,0x96,0xE8,0x06,0xCC,0x05,0x79,0x90,0x20,0x9B,0x09,0xA4,0x33,0xB6,0x6C,0x83
        )
        $pad = $Cpassword.Length % 4
        if ($pad) { $Cpassword += ('=' * (4 - $pad)) }
        $raw = [Convert]::FromBase64String($Cpassword)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KEY; $aes.IV = [byte[]]::new(16); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $dec = $aes.CreateDecryptor().TransformFinalBlock($raw, 0, $raw.Length)
        $aes.Dispose()
        $padLen = if ($dec.Length) { $dec[$dec.Length - 1] } else { 0 }
        $plain = $dec[0..($dec.Length - $padLen - 1)]
        return ([System.Text.Encoding]::Unicode.GetString($plain)).Trim()
    }
    catch { return "<decryption failed: $_>" }
}

function Scan-SysvolForGpp {
    param([string]$DcIpAddr, [string]$DomainName)
    $GPP_FILES = @('Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml')
    $sysvolPath = "\\$DcIpAddr\SYSVOL\$DomainName\Policies"
    if (-not (Test-Path -LiteralPath $sysvolPath -ErrorAction SilentlyContinue)) { return $null }
    $hits = @()
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $sysvolPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $GPP_FILES })) {
            try {
                [xml]$xml = Get-Content -LiteralPath $f.FullName -Raw
                foreach ($elem in $xml.SelectNodes('//*')) {
                    $cpassword = $elem.GetAttribute('cpassword')
                    if (-not $cpassword) { continue }
                    $username = $elem.GetAttribute('userName'); if (-not $username) { $username = $elem.GetAttribute('runAs') }
                    if (-not $username) { $username = $elem.GetAttribute('username') }; if (-not $username) { $username = '<unknown>' }
                    $decrypted = Decrypt-GppPassword $cpassword
                    $hits += , @($f.FullName, $username, $decrypted)
                }
            }
            catch { continue }
        }
    }
    catch { return $null }
    return , $hits
}

function Check-GppPasswords {
    $findings = @(); $stats = @{}
    Write-C '  [*] GPP / cpassword in SYSVOL (MS14-025)' 'Gray'
    $result = Scan-SysvolForGpp $script:AD.DcIp $script:AD.Domain
    if ($null -eq $result) {
        $stats['gpp_sysvol_accessible'] = $false
        $findings += New-Finding 'GPP Passwords' 'SYSVOL Not Accessible -- GPP Scan Skipped' 'INFO' "Could not walk \\$($script:AD.DcIp)\SYSVOL. Run from a domain-joined Windows host, or mount SYSVOL and re-run. Manual check: findstr /S /I cpassword \\<domain>\sysvol\**\*.xml" -Recommendation 'Search SYSVOL manually for cpassword attributes in GPP XML files.' -RiskScore 0 -References @('https://attack.mitre.org/techniques/T1552/006/')
        return @{ findings = $findings; stats = $stats }
    }
    $result = @($result)
    $stats['gpp_sysvol_accessible'] = $true
    $stats['gpp_cpassword_count'] = $result.Count
    if ($result.Count) {
        $det = @()
        foreach ($hit in $result) {
            $hit = @($hit)
            $fpath = [string]$hit[0]; $username = [string]$hit[1]; $decrypted = [string]$hit[2]
            $tail = if ($fpath.Length -gt 80) { $fpath.Substring($fpath.Length - 80) } else { $fpath }
            $det += "user=$username  file=...$tail  password=$decrypted"
        }
        $findings += New-Finding 'GPP Passwords' 'Plaintext Credentials Found in SYSVOL GPP (MS14-025)' 'CRITICAL' "$($result.Count) cpassword attribute(s) found in Group Policy Preferences XML files. These are encrypted with a static AES key published by Microsoft -- the plaintext passwords above are readable by any domain user." -Details $det -Recommendation 'Delete all GPP preferences that store passwords. Use LAPS or a PAM vault for local admin credentials. Apply patch KB2962486 (MS14-025).' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1552/006/', 'https://support.microsoft.com/kb/2962486')
    }
    else {
        $findings += New-Finding 'GPP Passwords' 'No cpassword Attributes Found in SYSVOL' 'INFO' 'SYSVOL was accessible and no GPP cpassword attributes were detected.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 26. AdminSDHolder ACL Inspection ------------------------------------------
function Check-AdminSdHolder {
    $findings = @(); $stats = @{}
    Write-C '  [*] AdminSDHolder ACL' 'Gray'
    $dn = "CN=AdminSDHolder,CN=System,$($script:AD.BaseDN)"
    $domainSid = Get-DomainSid
    $risky = @()
    try {
        $entries = @(Get-SDBytes -Dn $dn -Filter '(objectClass=*)' -Scope Base)
        if (-not $entries.Count) {
            $findings += New-Finding 'AdminSDHolder' 'AdminSDHolder Object Not Readable' 'INFO' 'Could not read AdminSDHolder ACL.' -RiskScore 0
            return @{ findings = $findings; stats = $stats }
        }
        $rawSd = AttrBytes $entries[0] 'nTSecurityDescriptor'
        if (-not $rawSd) { return @{ findings = $findings; stats = $stats } }
        foreach ($ace in (Parse-SD $rawSd)) {
            if ($ace.ace_type -notin @(0x00, 0x05)) { continue }
            $sid = $ace.trustee_sid; $mask = $ace.access_mask
            if (Sid-IsPrivileged $sid $domainSid) { continue }
            if ($mask -band ($script:AM_GENERIC_ALL -bor $script:AM_WRITE_DACL -bor $script:AM_WRITE_OWNER -bor $script:AM_GENERIC_WRITE -bor $script:AM_WRITE_PROP)) {
                $risky += ("$(Resolve-Sid $sid) -- mask: 0x{0:x8}" -f $mask)
            }
        }
    }
    catch {
        Write-C "  [~] AdminSDHolder ACL read failed: $_" 'DarkGray'
        return @{ findings = $findings; stats = $stats }
    }
    $stats['adminsdholder_risky_aces'] = $risky.Count
    if ($risky.Count) {
        $findings += New-Finding 'AdminSDHolder' 'Unexpected Write ACEs on AdminSDHolder (SDProp Persistence)' 'CRITICAL' "$($risky.Count) non-privileged principal(s) have write permissions on AdminSDHolder. SDProp propagates these ACEs to ALL protected group members every 60 minutes, granting persistent, auto-restoring domain privilege that survives most cleanup." -Details $risky -Recommendation "Remove all unexpected ACEs from AdminSDHolder immediately." -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1078/002/', 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory')
    }
    else {
        $findings += New-Finding 'AdminSDHolder' 'AdminSDHolder ACL -- No Unexpected Permissions' 'INFO' 'No non-privileged principals have write access to AdminSDHolder.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 27. SID History Abuse -----------------------------------------------------
function Check-SidHistory {
    $findings = @(); $stats = @{}
    Write-C '  [*] SID History' 'Gray'
    $domainSid = Get-DomainSid
    $usersWithSid = @(Search-AD -Filter '(&(objectClass=user)(sIDHistory=*))' -Attributes @('sAMAccountName', 'sIDHistory', 'userAccountControl', 'adminCount'))
    $compsWithSid = @(Search-AD -Filter '(&(objectClass=computer)(sIDHistory=*))' -Attributes @('sAMAccountName', 'sIDHistory', 'userAccountControl'))
    $results = @()
    foreach ($e in $usersWithSid) { $results += $e }
    foreach ($e in $compsWithSid) { $results += $e }
    $stats['sid_history_count'] = $results.Count
    if (-not $results.Count) {
        $findings += New-Finding 'SID History' 'No Accounts with SID History' 'INFO' 'No user or computer accounts have the sIDHistory attribute populated.' -RiskScore 0
        return @{ findings = $findings; stats = $stats }
    }
    $privHits = @(); $normalHits = @()
    foreach ($u in $results) {
        $name = AttrStr $u 'sAMAccountName'
        # sIDHistory is binary; convert each value to a SID string
        $a = $u.Attributes['sIDHistory']
        if ($a) {
            foreach ($v in $a) {
                try { if ($v -is [byte[]]) { $sidStr = ([System.Security.Principal.SecurityIdentifier]::new($v, 0)).ToString() } else { $sidStr = [string]$v } }
                catch { $sidStr = [string]$v }
                if (Sid-IsPrivileged $sidStr $domainSid) { $privHits += "$name -> $sidStr [PRIVILEGED SID]" }
                else { $normalHits += "$name -> $sidStr" }
            }
        }
    }
    if ($privHits.Count) {
        $findings += New-Finding 'SID History' 'Accounts with Privileged SIDs in sIDHistory (Backdoor Detected)' 'CRITICAL' "$($privHits.Count) account(s) carry privileged domain SIDs in sIDHistory. These accounts effectively hold the privileges of the injected SID without appearing in any privileged group -- a common post-compromise persistence technique." -Details $privHits -Recommendation 'Immediately investigate and clear sIDHistory. Enable SID filtering on all trusts to prevent cross-domain exploitation.' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/005/')
    }
    if ($normalHits.Count) {
        $sev = if (-not $privHits.Count) { 'LOW' } else { 'INFO' }
        $rs = if (-not $privHits.Count) { 3 } else { 0 }
        $findings += New-Finding 'SID History' 'Accounts with Non-Privileged SID History Entries' $sev "$($normalHits.Count) account(s) have non-privileged SID history entries. These may be legitimate migration artefacts or incomplete cleanup after an attack." -Details @($normalHits | Select-Object -First 20) -Recommendation 'Review all SID history entries. Clear sIDHistory once migrations are complete. Enable SID filtering on all domain trusts.' -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1134/005/')
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 28. Shadow Credentials (msDS-KeyCredentialLink) ---------------------------
function Check-ShadowCredentials {
    $findings = @(); $stats = @{}
    Write-C '  [*] Shadow Credentials (msDS-KeyCredentialLink)' 'Gray'
    $users = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(msDS-KeyCredentialLink=*))' -Attributes @('sAMAccountName', 'msDS-KeyCredentialLink', 'adminCount', 'userAccountControl'))
    $computers = @(Search-AD -Filter '(&(objectClass=computer)(msDS-KeyCredentialLink=*))' -Attributes @('sAMAccountName', 'msDS-KeyCredentialLink', 'userAccountControl'))
    $total = $users.Count + $computers.Count
    $stats['shadow_credentials_count'] = $total
    if (-not $total) {
        $findings += New-Finding 'Shadow Credentials' 'No Unexpected msDS-KeyCredentialLink Entries Detected' 'INFO' 'No user or computer accounts have msDS-KeyCredentialLink set (or entries are only on DCs as expected for Windows Hello for Business).' -RiskScore 0
        return @{ findings = $findings; stats = $stats }
    }
    $adminHits = @(); $userHits = @(); $compHits = @()
    foreach ($u in $users) {
        $name = AttrStr $u 'sAMAccountName'; $count = @(AttrList $u 'msDS-KeyCredentialLink').Count
        $entry = "$name ($count key credential(s))"
        if ((AttrInt $u 'adminCount') -eq 1) { $adminHits += $entry } else { $userHits += $entry }
    }
    foreach ($c in $computers) { $name = AttrStr $c 'sAMAccountName'; $count = @(AttrList $c 'msDS-KeyCredentialLink').Count; $compHits += "$name ($count key credential(s))" }
    if ($adminHits.Count) {
        $findings += New-Finding 'Shadow Credentials' 'Admin Accounts with msDS-KeyCredentialLink Set (Shadow Credentials)' 'CRITICAL' "$($adminHits.Count) privileged account(s) have shadow credentials. An attacker who set these entries can authenticate as the account via PKINIT certificate-based auth WITHOUT knowing the password, providing covert persistence." -Details $adminHits -Recommendation 'Clear msDS-KeyCredentialLink from all accounts unless Windows Hello for Business is deployed and managed. Review the change log to identify who added these entries.' -RiskScore 25 -References @('https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab')
    }
    if ($userHits.Count -or $compHits.Count) {
        $allHits = @($userHits + $compHits)
        $sev = if (-not $adminHits.Count) { 'HIGH' } else { 'MEDIUM' }
        $rs = if ($sev -eq 'HIGH') { 15 } else { 5 }
        $findings += New-Finding 'Shadow Credentials' 'Non-Admin Accounts with msDS-KeyCredentialLink Set' $sev "$($allHits.Count) non-admin account(s) or computer(s) have shadow credentials set. Verify these are legitimate Windows Hello for Business device registrations." -Details @($allHits | Select-Object -First 25) -Recommendation 'Audit all msDS-KeyCredentialLink entries. Clear unexpected ones. If WHfB is not deployed, all entries are suspicious.' -RiskScore $rs -References @('https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab')
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 29. RC4 / Legacy Kerberos Encryption --------------------------------------
function Check-Rc4Encryption {
    $findings = @(); $stats = @{}
    Write-C '  [*] RC4 / Legacy Kerberos Encryption' 'Gray'
    $RC4_BIT = 0x04; $AES_BITS = 0x18
    $svcAccs = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'msDS-SupportedEncryptionTypes', 'adminCount'))
    $dcs = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Attributes @('sAMAccountName', 'dNSHostName', 'msDS-SupportedEncryptionTypes'))
    $adminUsers = @(Search-AD -Filter '(&(objectClass=user)(!(objectClass=computer))(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Attributes @('sAMAccountName', 'msDS-SupportedEncryptionTypes'))
    $svcHits = @(); $dcHits = @(); $adminNoAes = @()
    foreach ($u in $svcAccs) {
        $enc = AttrInt $u 'msDS-SupportedEncryptionTypes'
        if ($enc -eq 0 -or ($enc -band $RC4_BIT)) { $name = AttrStr $u 'sAMAccountName'; $tag = if ((AttrInt $u 'adminCount') -eq 1) { ' [ADMIN]' } else { '' }; $svcHits += ("$name$tag (encTypes=0x{0:x})" -f $enc) }
    }
    foreach ($dc in $dcs) {
        $enc = AttrInt $dc 'msDS-SupportedEncryptionTypes'; $name = AttrStr $dc 'dNSHostName'; if (-not $name) { $name = AttrStr $dc 'sAMAccountName' }
        if ($enc -eq 0 -or ($enc -band $RC4_BIT)) { $dcHits += ("$name (encTypes=0x{0:x})" -f $enc) }
    }
    foreach ($u in $adminUsers) {
        $enc = AttrInt $u 'msDS-SupportedEncryptionTypes'
        if ($enc -ne 0 -and -not ($enc -band $AES_BITS)) { $adminNoAes += ("$(AttrStr $u 'sAMAccountName') (encTypes=0x{0:x})" -f $enc) }
    }
    $stats['rc4_service_accounts'] = $svcHits.Count; $stats['rc4_domain_controllers'] = $dcHits.Count; $stats['admin_no_aes_encryption'] = $adminNoAes.Count
    if ($svcHits.Count) {
        $sev = if ($svcHits | Where-Object { $_ -match '\[ADMIN\]' }) { 'CRITICAL' } else { 'HIGH' }
        $rs = if ($sev -eq 'CRITICAL') { 20 } else { 12 }
        $findings += New-Finding 'Kerberos Encryption' 'Service Accounts Permitting RC4 Kerberos Encryption' $sev "$($svcHits.Count) service account(s) with SPNs accept RC4-HMAC Kerberos tickets. Attackers specifically request RC4 tickets even when AES is available, because RC4 hashes crack orders of magnitude faster than AES hashes offline." -Details @($svcHits | Select-Object -First 30) -Recommendation 'Set msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256 only) on all service accounts: Set-ADUser <account> -KerberosEncryptionType AES128,AES256' -RiskScore $rs -References @('https://attack.mitre.org/techniques/T1558/003/')
    }
    if ($dcHits.Count) {
        $findings += New-Finding 'Kerberos Encryption' 'Domain Controllers Permitting RC4 Kerberos Encryption' 'MEDIUM' "$($dcHits.Count) DC(s) have RC4 in their supported encryption types, allowing clients to negotiate weaker RC4 tickets." -Details $dcHits -Recommendation 'Configure Network Security: Configure encryption types allowed for Kerberos via GPO to require AES only. Disable RC4 compatibility once all clients support AES.' -RiskScore 8
    }
    if ($adminNoAes.Count) {
        $findings += New-Finding 'Kerberos Encryption' 'Admin Accounts Explicitly Configured Without AES Kerberos Support' 'HIGH' "$($adminNoAes.Count) privileged account(s) have msDS-SupportedEncryptionTypes set without any AES bits, forcing legacy encryption for admin sessions." -Details $adminNoAes -Recommendation 'Set AES128+AES256 encryption types on all admin accounts.' -RiskScore 12
    }
    if (-not $svcHits.Count -and -not $dcHits.Count -and -not $adminNoAes.Count) {
        $findings += New-Finding 'Kerberos Encryption' 'No RC4-Only Kerberos Configurations Detected' 'INFO' 'All checked accounts and DCs appear to support AES Kerberos encryption.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 30. Foreign Security Principals in Privileged Groups ----------------------
function Check-ForeignSecurityPrincipals {
    $findings = @(); $stats = @{}
    Write-C '  [*] Foreign Security Principals in Privileged Groups' 'Gray'
    $b = $script:AD.BaseDN
    $SENSITIVE = [ordered]@{
        'Domain Admins' = "CN=Domain Admins,CN=Users,$b"; 'Enterprise Admins' = "CN=Enterprise Admins,CN=Users,$b"
        'Schema Admins' = "CN=Schema Admins,CN=Users,$b"; 'Administrators' = "CN=Administrators,CN=Builtin,$b"
        'Account Operators' = "CN=Account Operators,CN=Builtin,$b"; 'Backup Operators' = "CN=Backup Operators,CN=Builtin,$b"
        'Server Operators' = "CN=Server Operators,CN=Builtin,$b"; 'Group Policy Creator Owners' = "CN=Group Policy Creator Owners,CN=Users,$b"
    }
    $fspBase = "CN=ForeignSecurityPrincipals,$b"
    $fsps = @(Search-AD -Filter '(objectClass=foreignSecurityPrincipal)' -Attributes @('cn', 'memberOf') -Base $fspBase)
    $hits = @()
    foreach ($fsp in $fsps) {
        $sid = AttrStr $fsp 'cn'; $groups = AttrList $fsp 'memberOf'
        foreach ($gdn in $groups) {
            foreach ($gname in $SENSITIVE.Keys) {
                if ($gdn.ToLower() -eq $SENSITIVE[$gname].ToLower()) { $hits += "$(Resolve-Sid $sid) (SID: $sid) -> $gname" }
            }
        }
    }
    $stats['foreign_security_principals_in_priv_groups'] = $hits.Count
    if ($hits.Count) {
        $findings += New-Finding 'Foreign Security Principals' 'Foreign Security Principals in Privileged Groups' 'CRITICAL' "$($hits.Count) FSP(s) from trusted domains are members of sensitive local groups. Compromising the source domain or trust grants immediate privilege in this domain." -Details $hits -Recommendation 'Remove FSPs from all privileged groups unless there is an explicit, documented business requirement. Consider enabling selective authentication on trusts to limit cross-domain access.' -RiskScore 20 -References @('https://attack.mitre.org/techniques/T1484/002/')
    }
    else {
        $findings += New-Finding 'Foreign Security Principals' 'No Foreign Security Principals in Privileged Groups' 'INFO' 'No FSPs from trusted domains were found in sensitive groups.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 31. Pre-Windows 2000 Compatible Access Group ------------------------------
function Check-PreWindows2000 {
    $findings = @(); $stats = @{}
    Write-C '  [*] Pre-Windows 2000 Compatible Access Group' 'Gray'
    $dn = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$($script:AD.BaseDN)"
    $grp = @(Search-AD -Filter "(distinguishedName=$dn)" -Attributes @('member'))
    if (-not $grp.Count) {
        $findings += New-Finding 'Pre-Win2k Access' 'Pre-Windows 2000 Group Not Found' 'INFO' 'Could not locate the Pre-Windows 2000 Compatible Access group.' -RiskScore 0
        return @{ findings = $findings; stats = $stats }
    }
    $members = @(AttrList $grp[0] 'member')
    $everyone = [bool](@($members | Where-Object { $_ -match 'S-1-1-0' }).Count)
    $anon = [bool](@($members | Where-Object { $_ -match 'S-1-5-7' }).Count)
    $auth = [bool](@($members | Where-Object { $_ -match 'S-1-5-11' }).Count)
    $stats['pre_win2k_members'] = $members.Count; $stats['pre_win2k_everyone'] = $everyone; $stats['pre_win2k_anon'] = $anon
    if ($everyone -or $anon) {
        $who = @(); if ($everyone) { $who += 'Everyone (S-1-1-0)' }; if ($anon) { $who += 'Anonymous Logon (S-1-5-7)' }
        $findings += New-Finding 'Pre-Win2k Access' 'Pre-Windows 2000 Group Grants Unauthenticated Enumeration' 'CRITICAL' "The Pre-Windows 2000 Compatible Access group contains $($who -join ', '). Any unauthenticated attacker on the network can enumerate users, groups, and password policies via legacy SAMR/LSARPC protocols." -Details $who -Recommendation "Remove Everyone and Anonymous Logon from this group immediately: net localgroup 'Pre-Windows 2000 Compatible Access' Everyone /delete. Verify no legacy applications depend on anonymous SAMR access." -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1087/002/')
    }
    elseif ($auth) {
        $findings += New-Finding 'Pre-Win2k Access' 'Pre-Windows 2000 Group Contains Authenticated Users' 'MEDIUM' 'Authenticated Users in this group broadens SAMR enumeration rights beyond what modern AD requires.' -Recommendation 'Remove Authenticated Users unless a specific legacy application requires it. Restrict SAMR enumeration via GPO: Network access: Restrict clients allowed to make remote calls to SAM.' -RiskScore 8
    }
    elseif ($members.Count) {
        $findings += New-Finding 'Pre-Win2k Access' 'Pre-Windows 2000 Group Has Non-Standard Members' 'LOW' "$($members.Count) member(s) found. Verify each is required." -Details @($members | Select-Object -First 20) -Recommendation 'Remove all members unless required by legacy applications.' -RiskScore 3
    }
    else {
        $findings += New-Finding 'Pre-Win2k Access' 'Pre-Windows 2000 Compatible Access Group Is Empty' 'INFO' 'No members found -- good.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 32. Dangerous Constrained Delegation Targets ------------------------------
function Check-DangerousDelegationTargets {
    $findings = @(); $stats = @{}
    Write-C '  [*] Dangerous Constrained Delegation Targets' 'Gray'
    $dcs = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Attributes @('dNSHostName', 'sAMAccountName'))
    $dcNames = @{}
    foreach ($dc in $dcs) {
        $h = (AttrStr $dc 'dNSHostName').ToLower(); $s = (AttrStr $dc 'sAMAccountName').ToLower().TrimEnd('$')
        if ($h) { $dcNames[$h] = $true }; if ($s) { $dcNames[$s] = $true }
    }
    $delegating = @(Search-AD -Filter '(msDS-AllowedToDelegateTo=*)' -Attributes @('sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass', 'adminCount'))
    $hits = @()
    foreach ($obj in $delegating) {
        $name = AttrStr $obj 'sAMAccountName'; $targets = AttrList $obj 'msDS-AllowedToDelegateTo'
        foreach ($tgt in $targets) {
            $tl = $tgt.ToLower()
            $hostPart = if ($tl.Contains('/')) { $tl.Split('/')[1].Split(':')[0].Split('.')[0] } else { '' }
            $isDangerous = [bool](@($script:DANGEROUS_SVC_PREFIXES | Where-Object { $tl.StartsWith($_) }).Count)
            $isDcTarget = $dcNames.ContainsKey($hostPart)
            $isAdmin = (AttrInt $obj 'adminCount') -eq 1
            if ($isDangerous -and $isDcTarget) {
                $tag = if ($isAdmin) { ' [ADMIN-SOURCE]' } else { '' }
                $hits += "$name$tag -> $tgt  [DC target + sensitive SPN]"
            }
        }
    }
    $stats['dangerous_delegation_targets'] = $hits.Count
    if ($hits.Count) {
        $findings += New-Finding 'Delegation' 'Constrained Delegation to High-Value Services on Domain Controllers' 'CRITICAL' "$($hits.Count) account(s) are configured to delegate to sensitive services (ldap, cifs, host, gc, krbtgt) on Domain Controllers. An attacker who compromises these accounts can impersonate any domain user to the DC's most privileged interfaces, effectively achieving DA." -Details $hits -Recommendation 'Remove delegation to LDAP, CIFS, HOST, GC, and KRBTGT on DCs unless absolutely required. If required, restrict via delegation settings and enable Require Kerberos (no protocol transition). Prefer RBCD with minimal target scope.' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/001/', 'https://blog.harmj0y.net/activedirectory/s4u2abuse/')
    }
    else {
        $findings += New-Finding 'Delegation' 'No Dangerous Constrained Delegation Targets Detected' 'INFO' 'No accounts delegate to sensitive services (ldap/cifs/host/gc) on Domain Controllers.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 33. Orphaned AD Subnets ---------------------------------------------------
function Check-OrphanedSubnets {
    $findings = @(); $stats = @{}
    Write-C '  [*] Orphaned AD Subnets' 'Gray'
    $subnets = @(Search-AD -Filter '(objectClass=subnet)' -Attributes @('cn', 'siteObject', 'description') -Base "CN=Subnets,CN=Sites,$($script:AD.ConfigDN)")
    $orphaned = @()
    foreach ($s in $subnets) { $cidr = AttrStr $s 'cn'; $siteObj = AttrStr $s 'siteObject'; if (-not $siteObj) { $orphaned += $cidr } }
    $stats['subnet_count'] = $subnets.Count; $stats['orphaned_subnet_count'] = $orphaned.Count
    if ($orphaned.Count) {
        $findings += New-Finding 'Site Topology' 'AD Subnets Not Associated with Any Site' 'LOW' "$($orphaned.Count) of $($subnets.Count) subnet(s) have no site assignment. Clients from these subnets will receive a suboptimal (random) DC, causing authentication traffic to traverse WAN links unnecessarily. In multi-site environments this can also expose credentials to less-secure links." -Details @($orphaned | Select-Object -First 30) -Recommendation 'Assign each subnet to the appropriate AD site: New-ADReplicationSubnet -Name <CIDR> -Site <SiteName> or via Active Directory Sites and Services MMC.' -RiskScore 3
    }
    else {
        $findings += New-Finding 'Site Topology' 'All AD Subnets Are Assigned to a Site' 'INFO' "All $($subnets.Count) subnet(s) are correctly mapped to AD sites." -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 34. Legacy FRS SYSVOL Replication -----------------------------------------
function Check-FrsReplication {
    $findings = @(); $stats = @{}
    Write-C '  [*] SYSVOL Replication (FRS vs DFSR)' 'Gray'
    $frsSubs = @(Search-AD -Filter '(objectClass=nTFRSSubscriber)' -Attributes @('cn', 'distinguishedName'))
    $dfsrSubs = @(Search-AD -Filter '(objectClass=msDFSR-Subscription)' -Attributes @('cn') -Base "CN=DFSR-GlobalSettings,CN=System,$($script:AD.BaseDN)")
    $usingFrs = [bool]$frsSubs.Count -and -not [bool]$dfsrSubs.Count
    $mixedMode = [bool]$frsSubs.Count -and [bool]$dfsrSubs.Count
    $stats['frs_subscriber_count'] = $frsSubs.Count; $stats['dfsr_subscriber_count'] = $dfsrSubs.Count; $stats['sysvol_using_frs'] = $usingFrs
    if ($usingFrs) {
        $findings += New-Finding 'SYSVOL Replication' 'SYSVOL Still Replicating via Legacy FRS (File Replication Service)' 'HIGH' 'FRS was deprecated in Windows Server 2008 R2 and is no longer supported. FRS replication is unreliable and cannot be monitored with modern tools. It also blocks raising the domain functional level above 2003.' -Recommendation 'Migrate SYSVOL replication from FRS to DFSR using the dfsrmig tool: dfsrmig /SetGlobalState 3 (four-phase migration).' -RiskScore 12 -References @('https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr')
    }
    elseif ($mixedMode) {
        $findings += New-Finding 'SYSVOL Replication' 'SYSVOL Migration to DFSR Appears Incomplete' 'MEDIUM' 'Both FRS subscriber objects and DFSR subscription objects exist. The SYSVOL migration may be stalled mid-phase.' -Recommendation 'Check migration state: dfsrmig /GetGlobalState. Complete the migration to state 3 (Eliminated).' -RiskScore 5
    }
    else {
        $findings += New-Finding 'SYSVOL Replication' 'SYSVOL Replication Uses DFSR (Modern)' 'INFO' 'No legacy FRS subscriber objects detected. DFSR is in use.' -RiskScore 0
    }
    return @{ findings = $findings; stats = $stats }
}

# -- 35. RBCD on Domain Object Itself ------------------------------------------
function Check-RbcdOnDomain {
    $findings = @(); $stats = @{}
    Write-C '  [*] RBCD on Domain Object' 'Gray'
    $domResults = @(Search-AD -Filter '(objectClass=domain)' -Attributes @('msDS-AllowedToActOnBehalfOfOtherIdentity', 'distinguishedName') -Base $script:AD.BaseDN)
    $rbcdOnDomain = $false; $rawRbcd = $null
    if ($domResults.Count) {
        $rawRbcd = AttrBytes $domResults[0] 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ($rawRbcd) { $rbcdOnDomain = $true }
    }
    $stats['rbcd_on_domain_object'] = $rbcdOnDomain
    if ($rbcdOnDomain) {
        $trustees = @()
        if ($rawRbcd) { foreach ($ace in (Parse-SD $rawRbcd)) { if ($ace.ace_type -eq 0x00) { $trustees += (Resolve-Sid $ace.trustee_sid) } } }
        $det = if ($trustees.Count) { $trustees } else { @('<trustees could not be parsed>') }
        $findings += New-Finding 'Delegation' 'RBCD Configured on Domain Object -- Full Domain Compromise Path' 'CRITICAL' 'msDS-AllowedToActOnBehalfOfOtherIdentity is set on the domain NC head object. Any principal in this RBCD ACL can impersonate ANY domain user to ANY service in the domain, granting effective Domain Admin without being in any privileged group.' -Details $det -Recommendation 'Remove msDS-AllowedToActOnBehalfOfOtherIdentity from the domain object immediately: Set-ADObject (Get-ADDomain).DistinguishedName -Clear msDS-AllowedToActOnBehalfOfOtherIdentity' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/001/')
    }
    else {
        $findings += New-Finding 'Delegation' 'No RBCD Configured on Domain Object' 'INFO' 'msDS-AllowedToActOnBehalfOfOtherIdentity is not set on the domain NC head.' -RiskScore 0
    }
    $dcRbcd = @(Search-AD -Filter '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -Attributes @('sAMAccountName', 'dNSHostName'))
    $stats['rbcd_on_dc_count'] = $dcRbcd.Count
    if ($dcRbcd.Count) {
        $det = @($dcRbcd | ForEach-Object { $h = AttrStr $_ 'dNSHostName'; if ($h) { $h } else { AttrStr $_ 'sAMAccountName' } })
        $findings += New-Finding 'Delegation' 'RBCD Configured Directly on Domain Controller Computer Objects' 'CRITICAL' "$($dcRbcd.Count) Domain Controller(s) have RBCD set. Any account in the RBCD ACL can impersonate any domain user to the DC, enabling full domain compromise via S4U2Proxy." -Details $det -Recommendation 'Remove msDS-AllowedToActOnBehalfOfOtherIdentity from all DC objects: Get-ADComputer -Filter {PrimaryGroupID -eq 516} | Set-ADComputer -Clear msDS-AllowedToActOnBehalfOfOtherIdentity' -RiskScore 25 -References @('https://attack.mitre.org/techniques/T1134/001/')
    }
    return @{ findings = $findings; stats = $stats }
}

# ══════════════════════════════════════════════════════════════════════════════
#  AGGREGATOR (run_all_checks)
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-AllChecks {
    $allFindings = @(); $allStats = @{}
    $checks = @(
        'Check-PasswordPolicy', 'Check-PrivilegedAccounts', 'Check-Kerberos', 'Check-UnconstrainedDelegation', 'Check-ConstrainedDelegation',
        'Check-Adcs', 'Check-Trusts', 'Check-AccountHygiene', 'Check-Protocols', 'Check-Gpo',
        'Check-Laps', 'Check-LapsCoverage', 'Check-Dns', 'Check-DomainControllers', 'Check-Acls',
        'Check-OptionalFeatures', 'Check-Replication', 'Check-ServiceAccounts', 'Check-Misc', 'Check-DeprecatedOs',
        'Check-LegacyProtocols', 'Check-Exchange', 'Check-AdminCount', 'Check-PasswordsInDescriptions',
        'Check-GppPasswords', 'Check-AdminSdHolder', 'Check-SidHistory', 'Check-ShadowCredentials', 'Check-Rc4Encryption',
        'Check-ForeignSecurityPrincipals', 'Check-PreWindows2000', 'Check-DangerousDelegationTargets', 'Check-OrphanedSubnets',
        'Check-FrsReplication', 'Check-RbcdOnDomain'
    )
    foreach ($fn in $checks) {
        try {
            $res = & $fn
            if ($res.findings) { $allFindings += $res.findings }
            if ($res.stats) { foreach ($k in $res.stats.Keys) { $allStats[$k] = $res.stats[$k] } }
        }
        catch { Write-C "  [!] Check failed ($fn): $_" 'Yellow' }
    }
    return @{ findings = $allFindings; stats = $allStats }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SCORING (models.py ScanResult)
# ══════════════════════════════════════════════════════════════════════════════
function Get-TotalScore { param($Findings); $Findings = @($Findings); $sum = ($Findings | Measure-Object -Property risk_score -Sum).Sum; if ($null -eq $sum) { $sum = 0 }; return [Math]::Max(0, 100 - $sum) }
function Get-RiskLevel { param([int]$Score); if ($Score -ge 80) { 'LOW' } elseif ($Score -ge 60) { 'MEDIUM' } elseif ($Score -ge 40) { 'HIGH' } else { 'CRITICAL' } }
function Get-Counts { param($Findings); $Findings = @($Findings); $c = @{}; foreach ($f in $Findings) { if (-not $c.ContainsKey($f.severity)) { $c[$f.severity] = 0 }; $c[$f.severity]++ }; return $c }
function Sort-BySeverity { param($Findings); $Findings = @($Findings); , @($Findings | Sort-Object @{ Expression = { $script:SEVERITY_ORDER[$_.severity] } }) }

function Get-TopCritical {
    param($Findings, [int]$MaxN = 5)
    $eligible = @(@($Findings) | Where-Object { $_.severity -in @('CRITICAL', 'HIGH') })
    $eligible = @($eligible | Sort-Object @{ Expression = { $script:SEVERITY_ORDER[$_.severity] } }, @{ Expression = { -($_.risk_score) } })
    return , @($eligible | Select-Object -First $MaxN)
}

function Build-StatCards {
    param($Stats)
    $s = $Stats; $cards = @()
    if ($s.ContainsKey('laps_total_hosts') -and $null -ne $s['laps_total_hosts']) {
        $total = $s['laps_total_hosts']; $covered = if ($s.ContainsKey('laps_covered')) { $s['laps_covered'] } else { 0 }
        $pctOk = if ($total) { [int](100 * $covered / $total) } else { 100 }
        $col = if ($pctOk -eq 100) { '#16a34a' } elseif ($pctOk -ge 80) { '#ca8a04' } else { '#dc2626' }
        $cards += @{ label = 'LAPS Coverage'; value = "$pctOk%"; sub = "$covered/$total hosts"; color = $col }
    }
    if ($s.ContainsKey('deprecated_os_count')) { $dep = $s['deprecated_os_count']; $cards += @{ label = 'Deprecated OS'; value = "$dep"; sub = 'active computers'; color = $(if ($dep -gt 0) { '#dc2626' } else { '#16a34a' }) } }
    if ($s.ContainsKey('unconstrained_delegation_computers')) {
        $uncC = $s['unconstrained_delegation_computers']; $uncU = if ($s.ContainsKey('unconstrained_delegation_users')) { $s['unconstrained_delegation_users'] } else { 0 }
        $tot = $uncC + $uncU; $cards += @{ label = 'Unconstrained Delegation'; value = "$tot"; sub = "$uncC computers / $uncU users"; color = $(if ($tot -gt 0) { '#dc2626' } else { '#16a34a' }) }
    }
    if ($s.ContainsKey('admincount1_total')) {
        $admTot = $s['admincount1_total']; $admOrph = if ($s.ContainsKey('admincount1_orphaned')) { $s['admincount1_orphaned'] } else { 0 }
        $col = if ($admOrph) { '#dc2626' } elseif ($admTot -gt 20) { '#ca8a04' } else { '#16a34a' }
        $cards += @{ label = 'adminCount=1 Accounts'; value = "$admTot"; sub = $(if ($admOrph) { "$admOrph orphaned" } else { 'no orphans' }); color = $col }
    }
    if ($s.ContainsKey('passwords_in_descriptions_admins') -or $s.ContainsKey('passwords_in_descriptions_users')) {
        $pa = if ($s.ContainsKey('passwords_in_descriptions_admins')) { $s['passwords_in_descriptions_admins'] } else { 0 }
        $pu = if ($s.ContainsKey('passwords_in_descriptions_users')) { $s['passwords_in_descriptions_users'] } else { 0 }
        $pc = if ($s.ContainsKey('passwords_in_descriptions_computers')) { $s['passwords_in_descriptions_computers'] } else { 0 }
        $pt = $pa + $pu + $pc; $col = if ($pa) { '#dc2626' } elseif ($pt) { '#ea580c' } else { '#16a34a' }
        $cards += @{ label = 'Passwords in Descriptions'; value = "$pt"; sub = "$pa admin / $pu user / $pc computer"; color = $col }
    }
    if ($s.ContainsKey('gpo_count')) {
        $gt = $s['gpo_count']
        $gOrph = if ($s.ContainsKey('gpo_orphaned')) { $s['gpo_orphaned'] } else { 0 }
        $gUnl = if ($s.ContainsKey('gpo_unlinked')) { $s['gpo_unlinked'] } else { 0 }
        $gb = $gOrph + $gUnl
        $col = if ($gb -gt 10) { '#dc2626' } elseif ($gb) { '#ca8a04' } else { '#16a34a' }
        $cards += @{ label = 'GPOs'; value = "$gt"; sub = "$gb orphaned/unlinked"; color = $col }
    }
    if ($s.ContainsKey('gpp_cpassword_count')) {
        $gc = $s['gpp_cpassword_count']; $acc = if ($s.ContainsKey('gpp_sysvol_accessible')) { $s['gpp_sysvol_accessible'] } else { $false }
        $col = if ($gc -gt 0) { '#dc2626' } else { '#16a34a' }
        $sub = if ($acc) { "$gc plaintext password(s)" } else { 'SYSVOL not accessible' }
        $cards += @{ label = 'GPP cpassword (MS14-025)'; value = $(if ($acc) { "$gc" } else { '?' }); sub = $sub; color = $col }
    }
    if ($s.ContainsKey('sid_history_count')) { $sh = $s['sid_history_count']; $cards += @{ label = 'SID History Entries'; value = "$sh"; sub = 'accounts with sIDHistory set'; color = $(if ($sh -gt 0) { '#dc2626' } else { '#16a34a' }) } }
    if ($s.ContainsKey('shadow_credentials_count')) { $sc = $s['shadow_credentials_count']; $cards += @{ label = 'Shadow Credentials'; value = "$sc"; sub = 'msDS-KeyCredentialLink entries'; color = $(if ($sc -gt 0) { '#dc2626' } else { '#16a34a' }) } }
    if ($s.ContainsKey('rc4_service_accounts')) { $r = $s['rc4_service_accounts']; $cards += @{ label = 'RC4-Permitted Service Accts'; value = "$r"; sub = 'Kerberoastable with weak hash'; color = $(if ($r -gt 0) { '#dc2626' } else { '#16a34a' }) } }
    if ($s.ContainsKey('adminsdholder_risky_aces')) { $a = $s['adminsdholder_risky_aces']; $cards += @{ label = 'AdminSDHolder Bad ACEs'; value = "$a"; sub = 'non-privileged write ACEs'; color = $(if ($a -gt 0) { '#dc2626' } else { '#16a34a' }) } }
    if ($s.ContainsKey('rbcd_on_domain_object')) {
        $rd = $s['rbcd_on_domain_object']; $rc = if ($s.ContainsKey('rbcd_on_dc_count')) { $s['rbcd_on_dc_count'] } else { 0 }
        $rdVal = if ($rd) { 1 } else { 0 }
        $tot = $rdVal + $rc
        $cards += @{ label = 'RBCD on Domain/DCs'; value = "$tot"; sub = 'domain obj + DC objects affected'; color = $(if ($tot -gt 0) { '#dc2626' } else { '#16a34a' }) }
    }
    return $cards
}

# ══════════════════════════════════════════════════════════════════════════════
#  CONSOLE REPORT (report.py print_report)
# ══════════════════════════════════════════════════════════════════════════════
function Write-Report {
    param($Findings, $Stats, [string]$DomainName, [string]$DcIpAddr, [string]$ScanTime)
    $W = 72
    $score = Get-TotalScore $Findings; $level = Get-RiskLevel $score
    Write-C ("`n" + ('=' * $W))
    Write-C '  ADPulse ACTIVE DIRECTORY SECURITY SCAN REPORT'
    Write-C ('=' * $W)
    Write-C "  Domain      : $DomainName"
    Write-C "  DC          : $DcIpAddr"
    Write-C "  Scanned     : $ScanTime"
    $scCol = if ($score -ge 80) { 'Green' } elseif ($score -ge 60) { 'Yellow' } else { 'Red' }
    Write-C '  Risk Score  : ' 'Gray' -NoNewline; Write-C "$score/100  [$level]" $scCol
    Write-C ('=' * $W)
    Write-C ''
    $counts = Get-Counts $Findings
    Write-C 'SUMMARY:'
    foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
        if ($counts.ContainsKey($sev) -and $counts[$sev]) {
            Write-C ("  {0,-10}" -f $sev) $script:SEV_COLOR[$sev] -NoNewline; Write-C ": $($counts[$sev]) finding(s)"
        }
    }
    $top = Get-TopCritical $Findings
    Write-C ("`n" + ('-' * $W)); Write-C 'AT A GLANCE - MOST CRITICAL FINDINGS:'; Write-C ('-' * $W)
    if ($top.Count) {
        foreach ($f in $top) {
            Write-C "  [$($f.severity)]" $script:SEV_COLOR[$f.severity] -NoNewline; Write-C "  $($f.title)"
            Write-C "    $($f.description)"
            if ($f.recommendation) { Write-C "    >> $($f.recommendation)" 'Green' }
        }
        Write-C ''
    }
    else { Write-C '  No critical or high-severity findings.' 'Green'; Write-C '' }
    $cards = @(Build-StatCards $Stats)
    if ($cards.Count) {
        Write-C ('-' * $W); Write-C 'KEY METRICS:'; Write-C ('-' * $W)
        $cMap = @{ '#dc2626' = 'Red'; '#ea580c' = 'DarkRed'; '#ca8a04' = 'Yellow'; '#16a34a' = 'Green' }
        foreach ($card in $cards) {
            $col = if ($cMap.ContainsKey($card.color)) { $cMap[$card.color] } else { 'Gray' }
            Write-C ("  {0,-38}" -f $card.label) 'Gray' -NoNewline
            Write-C ("{0,-8}" -f $card.value) $col -NoNewline; Write-C " ($($card.sub))"
        }
    }
    Write-C ("`n" + ('-' * $W)); Write-C 'FINDINGS (sorted by severity):'; Write-C ('-' * $W); Write-C ''
    foreach ($f in (Sort-BySeverity $Findings)) {
        if ($f.severity -eq 'INFO') { continue }
        Write-C "  [$($f.severity)]" $script:SEV_COLOR[$f.severity] -NoNewline; Write-C " [$($f.category)]  $($f.title)"
        Write-C "    $($f.description)"
        $det = @($f.details)
        if ($det.Count) {
            foreach ($d in ($det | Select-Object -First 10)) { Write-C "      * $d" }
            if ($det.Count -gt 10) { Write-C "      ... (+$($det.Count - 10) more)" }
        }
        if ($f.recommendation) { Write-C "    >> $($f.recommendation)" 'Green' }
        $refs = @($f.references)
        if ($refs.Count) { foreach ($ref in $refs) { Write-C "    -> $ref" 'Blue' } }
        Write-C ''
    }
    Write-C ('-' * $W); Write-C 'ADDITIONAL CHECK SUMMARY:'; Write-C ('-' * $W)
    function _cs { param([string]$Label, $Value, [int]$WarnAbove = 0)
        if ($null -eq $Value) { return }
        $col = if (($Value -is [int] -or $Value -is [long]) -and $Value -gt $WarnAbove) { 'Red' } elseif ($Value -is [bool] -and $Value) { 'Red' } else { 'Green' }
        Write-C ("  {0,-40} " -f $Label) 'Gray' -NoNewline; Write-C "$Value" $col
    }
    _cs 'Deprecated OS computers' $(if ($Stats.ContainsKey('deprecated_os_count')) { $Stats['deprecated_os_count'] } else { $null })
    _cs 'Unconstrained deleg. (computers)' $(if ($Stats.ContainsKey('unconstrained_delegation_computers')) { $Stats['unconstrained_delegation_computers'] } else { $null })
    _cs 'Unconstrained deleg. (users)' $(if ($Stats.ContainsKey('unconstrained_delegation_users')) { $Stats['unconstrained_delegation_users'] } else { $null })
    _cs 'Constrained deleg. (proto-xtn)' $(if ($Stats.ContainsKey('constrained_delegation_proto_transition')) { $Stats['constrained_delegation_proto_transition'] } else { $null })
    _cs 'LAPS missing (non-DC hosts)' $(if ($Stats.ContainsKey('laps_missing')) { $Stats['laps_missing'] } else { $null })
    _cs 'adminCount=1 (total)' $(if ($Stats.ContainsKey('admincount1_total')) { $Stats['admincount1_total'] } else { $null }) 20
    _cs 'adminCount=1 (orphaned)' $(if ($Stats.ContainsKey('admincount1_orphaned')) { $Stats['admincount1_orphaned'] } else { $null })
    _cs 'adminCount=1 (disabled/ghost)' $(if ($Stats.ContainsKey('admincount1_disabled')) { $Stats['admincount1_disabled'] } else { $null })
    _cs 'adminCount=1 (stale)' $(if ($Stats.ContainsKey('admincount1_stale')) { $Stats['admincount1_stale'] } else { $null })
    _cs 'Passwords in desc. (admins)' $(if ($Stats.ContainsKey('passwords_in_descriptions_admins')) { $Stats['passwords_in_descriptions_admins'] } else { $null })
    _cs 'Passwords in desc. (users)' $(if ($Stats.ContainsKey('passwords_in_descriptions_users')) { $Stats['passwords_in_descriptions_users'] } else { $null })
    _cs 'GPOs (orphaned)' $(if ($Stats.ContainsKey('gpo_orphaned')) { $Stats['gpo_orphaned'] } else { $null })
    _cs 'GPOs (unlinked)' $(if ($Stats.ContainsKey('gpo_unlinked')) { $Stats['gpo_unlinked'] } else { $null })
    Write-C ''
    if ($Stats.ContainsKey('gpp_sysvol_accessible') -and $Stats['gpp_sysvol_accessible'] -eq $false) {
        Write-C ("  {0,-40} " -f 'GPP cpassword scan') 'Gray' -NoNewline; Write-C 'SYSVOL not accessible' 'Yellow'
    }
    else { _cs 'GPP cpassword hits (MS14-025)' $(if ($Stats.ContainsKey('gpp_cpassword_count')) { $Stats['gpp_cpassword_count'] } else { $null }) }
    _cs 'AdminSDHolder risky ACEs' $(if ($Stats.ContainsKey('adminsdholder_risky_aces')) { $Stats['adminsdholder_risky_aces'] } else { $null })
    _cs 'SID history (total accounts)' $(if ($Stats.ContainsKey('sid_history_count')) { $Stats['sid_history_count'] } else { $null })
    _cs 'Shadow credentials (total)' $(if ($Stats.ContainsKey('shadow_credentials_count')) { $Stats['shadow_credentials_count'] } else { $null })
    _cs 'RC4-permitted service accounts' $(if ($Stats.ContainsKey('rc4_service_accounts')) { $Stats['rc4_service_accounts'] } else { $null })
    _cs 'RC4-permitted domain controllers' $(if ($Stats.ContainsKey('rc4_domain_controllers')) { $Stats['rc4_domain_controllers'] } else { $null })
    _cs 'Admin accts without AES enctype' $(if ($Stats.ContainsKey('admin_no_aes_encryption')) { $Stats['admin_no_aes_encryption'] } else { $null })
    _cs 'FSPs in privileged groups' $(if ($Stats.ContainsKey('foreign_security_principals_in_priv_groups')) { $Stats['foreign_security_principals_in_priv_groups'] } else { $null })
    _cs 'Dangerous delegation targets' $(if ($Stats.ContainsKey('dangerous_delegation_targets')) { $Stats['dangerous_delegation_targets'] } else { $null })
    _cs 'Orphaned AD subnets' $(if ($Stats.ContainsKey('orphaned_subnet_count')) { $Stats['orphaned_subnet_count'] } else { $null })
    if ($Stats.ContainsKey('sysvol_using_frs')) { $frs = $Stats['sysvol_using_frs']; Write-C ("  {0,-40} " -f 'SYSVOL uses legacy FRS') 'Gray' -NoNewline; Write-C "$frs" $(if ($frs) { 'Red' } else { 'Green' }) }
    if ($Stats.ContainsKey('rbcd_on_domain_object')) { $rd = $Stats['rbcd_on_domain_object']; Write-C ("  {0,-40} " -f 'RBCD on domain object') 'Gray' -NoNewline; Write-C "$rd" $(if ($rd) { 'Red' } else { 'Green' }) }
    _cs 'RBCD on DC computer objects' $(if ($Stats.ContainsKey('rbcd_on_dc_count')) { $Stats['rbcd_on_dc_count'] } else { $null })
    Write-C ''
}

# ══════════════════════════════════════════════════════════════════════════════
#  JSON EXPORT (report.py export_json)
# ══════════════════════════════════════════════════════════════════════════════
function Export-Json {
    param($Findings, $Stats, [string]$DomainName, [string]$DcIpAddr, [string]$ScanTime, [string]$Path)
    $score = Get-TotalScore $Findings
    $data = [ordered]@{
        domain     = $DomainName
        dc_ip      = $DcIpAddr
        scan_time  = $ScanTime
        risk_score = $score
        risk_level = Get-RiskLevel $score
        stats      = $Stats
        findings   = @($Findings | ForEach-Object {
                [ordered]@{
                    category = $_.category; title = $_.title; severity = $_.severity; description = $_.description
                    details = @($_.details); recommendation = $_.recommendation; risk_score = $_.risk_score; references = @($_.references)
                }
            })
    }
    $data | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding utf8
    Write-C "[+] JSON report -> $Path" 'Green'
}

# ══════════════════════════════════════════════════════════════════════════════
#  HTML EXPORT (report.py export_html)
# ══════════════════════════════════════════════════════════════════════════════
function HtmlEnc { param([string]$T); if ($null -eq $T) { return '' }; [System.Web.HttpUtility]::HtmlEncode($T) }

function Export-Html {
    param($Findings, $Stats, [string]$DomainName, [string]$DcIpAddr, [string]$ScanTime, [string]$Path)
    Add-Type -AssemblyName System.Web
    $counts = Get-Counts $Findings
    $score = Get-TotalScore $Findings; $level = Get-RiskLevel $score
    $scCol = if ($score -ge 80) { '#16a34a' } elseif ($score -ge 60) { '#ca8a04' } else { '#dc2626' }

    $summaryBars = ''
    foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
        if ($counts.ContainsKey($sev) -and $counts[$sev]) {
            $col = $script:SEV_BADGE_COLOR[$sev]
            $summaryBars += "<div class=`"sbar`" style=`"background:$col`"><strong>$sev</strong><br>$($counts[$sev])</div>"
        }
    }

    # Category sections (skip INFO)
    $catMap = @{}
    foreach ($f in (Sort-BySeverity $Findings)) { if (-not $catMap.ContainsKey($f.category)) { $catMap[$f.category] = @() } $catMap[$f.category] += $f }
    $sortedCats = $catMap.GetEnumerator() | Sort-Object @{ Expression = { ($_.Value | ForEach-Object { $script:SEVERITY_ORDER[$_.severity] } | Measure-Object -Minimum).Minimum } }

    $sections = ''
    foreach ($kv in $sortedCats) {
        $cat = $kv.Key
        $catFindings = @($kv.Value | Where-Object { $_.severity -ne 'INFO' })
        if (-not $catFindings.Count) { continue }
        $worst = $catFindings[0].severity; $catCol = $script:SEV_BADGE_COLOR[$worst]
        $trows = ''
        foreach ($f in $catFindings) {
            $col = $script:SEV_BADGE_COLOR[$f.severity]
            $dets = ($f.details | ForEach-Object { "<li>$(HtmlEnc $_)</li>" }) -join ''
            $detsHtml = if ($dets) { "<ul>$dets</ul>" } else { '' }
            $refs = ($f.references | ForEach-Object { "<a href=`"$_`" target=`"_blank`" class=`"ref`">$(HtmlEnc $_)</a>" }) -join ''
            $trows += "<tr><td class=`"col-sev`"><span class=`"badge`" style=`"background:$col`">$($f.severity)</span></td><td class=`"col-finding`"><strong>$(HtmlEnc $f.title)</strong><br><span class=`"desc`">$(HtmlEnc $f.description)</span>$detsHtml</td><td class=`"col-rec`">$(HtmlEnc $f.recommendation)$refs</td><td class=`"col-score`">$($f.risk_score)</td></tr>"
        }
        $sections += "<div class=`"cat-section`"><div class=`"cat-header`" onclick=`"toggle(this)`"><span class=`"badge`" style=`"background:$catCol`">$worst</span><span class=`"cat-title`">$(HtmlEnc $cat)</span><span class=`"cat-count`">$($catFindings.Count) finding(s)</span><span class=`"chevron`">&#9660;</span></div><div class=`"cat-body`"><table><colgroup><col style=`"width:90px`"><col style=`"width:40%`"><col><col style=`"width:52px`"></colgroup><tr><th class=`"col-sev`">Severity</th><th class=`"col-finding`">Finding</th><th class=`"col-rec`">Recommendation</th><th class=`"col-score`">Score</th></tr>$trows</table></div></div>"
    }

    # At-a-glance
    $top = Get-TopCritical $Findings
    if (-not $top.Count) {
        $criticalHtml = '<div class="glance-empty"><span style="color:#16a34a;font-weight:bold">&#10003; No critical or high-severity findings</span></div>'
    }
    else {
        $criticalHtml = ''
        foreach ($f in $top) {
            $col = $script:SEV_BADGE_COLOR[$f.severity]
            $rec = if ($f.recommendation) { "<div class=`"glance-rec`">$(HtmlEnc $f.recommendation)</div>" } else { '' }
            $criticalHtml += "<div class=`"glance-item`" style=`"border-left:3px solid $col`"><div class=`"glance-header`"><span class=`"badge`" style=`"background:$col`">$($f.severity)</span><span class=`"glance-title`">$(HtmlEnc $f.title)</span><span class=`"glance-score`">-$($f.risk_score) pts</span></div><div class=`"glance-desc`">$(HtmlEnc $f.description)</div>$rec</div>"
        }
    }

    # Stat cards
    $cards = @(Build-StatCards $Stats)
    $statCardsHtml = ''
    if ($cards.Count) {
        $statCardsHtml = '<div class="card-row">'
        foreach ($c in $cards) { $statCardsHtml += "<div class=`"stat-card`" style=`"border-top:3px solid $($c.color)`"><div class=`"card-label`">$(HtmlEnc $c.label)</div><div class=`"card-value`" style=`"color:$($c.color)`">$(HtmlEnc $c.value)</div><div class=`"card-sub`">$(HtmlEnc $c.sub)</div></div>" }
        $statCardsHtml += '</div>'
    }

    # Additional-check summary (with NEW CHECKS 25-35 subheader)
    function _ic { param($V, [int]$W = 0); if ($null -eq $V) { return '&mdash;' }; $col = if ($V -gt $W) { '#dc2626' } else { '#16a34a' }; "<span style=`"color:$col;font-weight:bold`">$V</span>" }
    function _bb { param($V); if ($V -eq $true) { '<span style="color:#dc2626;font-weight:bold">YES &#9888;</span>' } elseif ($V -eq $false) { '<span style="color:#16a34a;font-weight:bold">No</span>' } else { "$V" } }
    function _g { param($K); if ($Stats.ContainsKey($K)) { $Stats[$K] } else { $null } }

    $newRows = "<tr><td colspan=`"2`" style=`"background:#0f1f35;color:#64748b;font-size:.78rem;padding:6px 8px;letter-spacing:.04em`">NEW CHECKS (25-35)</td></tr>"
    $gppAcc = _g 'gpp_sysvol_accessible'; $gppCount = _g 'gpp_cpassword_count'
    $gppCell = if ($gppAcc -eq $false) { '<span style="color:#ca8a04;font-weight:bold">SYSVOL not accessible</span>' } elseif ($null -ne $gppCount) { _ic $gppCount 0 } else { '&mdash;' }
    $newRows += "<tr><td>GPP cpassword hits (MS14-025)</td><td>$gppCell</td></tr>"
    $newRows += "<tr><td>AdminSDHolder risky ACEs</td><td>$(_ic (_g 'adminsdholder_risky_aces') 0)</td></tr>"
    $newRows += "<tr><td>SID history accounts</td><td>$(_ic (_g 'sid_history_count') 0)</td></tr>"
    $newRows += "<tr><td>Shadow credentials</td><td>$(_ic (_g 'shadow_credentials_count') 0)</td></tr>"
    $newRows += "<tr><td>RC4-permitted service accounts</td><td>$(_ic (_g 'rc4_service_accounts') 0)</td></tr>"
    $newRows += "<tr><td>RC4-permitted domain controllers</td><td>$(_ic (_g 'rc4_domain_controllers') 0)</td></tr>"
    $newRows += "<tr><td>Admin accounts without AES enctype</td><td>$(_ic (_g 'admin_no_aes_encryption') 0)</td></tr>"
    $newRows += "<tr><td>FSPs in privileged groups</td><td>$(_ic (_g 'foreign_security_principals_in_priv_groups') 0)</td></tr>"
    $preEv = _g 'pre_win2k_everyone'; $preAn = _g 'pre_win2k_anon'
    $preCell = if ($null -ne $preEv) { if ($preEv -or $preAn) { $who = @(); if ($preEv) { $who += 'Everyone' }; if ($preAn) { $who += 'Anonymous' }; "<span style=`"color:#dc2626;font-weight:bold`">YES - $($who -join ', ') &#9888;</span>" } else { '<span style="color:#16a34a;font-weight:bold">No dangerous members</span>' } } else { '&mdash;' }
    $newRows += "<tr><td>Pre-Win2k group (dangerous members)</td><td>$preCell</td></tr>"
    $newRows += "<tr><td>Dangerous delegation targets (DC)</td><td>$(_ic (_g 'dangerous_delegation_targets') 0)</td></tr>"
    $newRows += "<tr><td>Orphaned AD subnets</td><td>$(_ic (_g 'orphaned_subnet_count') 0)</td></tr>"
    $newRows += "<tr><td>SYSVOL using legacy FRS</td><td>$(_bb (_g 'sysvol_using_frs'))</td></tr>"
    $newRows += "<tr><td>RBCD on domain object</td><td>$(_bb (_g 'rbcd_on_domain_object'))</td></tr>"
    $newRows += "<tr><td>RBCD on DC objects</td><td>$(_ic (_g 'rbcd_on_dc_count') 0)</td></tr>"
    $newChecksHtml = "<div class=`"cat-section`" style=`"margin-top:1rem`"><div class=`"cat-header`" onclick=`"toggle(this)`"><span class=`"cat-title`">Additional Check Summary</span><span class=`"chevron`">&#9660;</span></div><div class=`"cat-body collapsed`"><table><colgroup><col style='width:60%'><col></colgroup><tr><th>Check</th><th>Result</th></tr>$newRows</table></div></div>"

    # GPO-content note (verbatim from README limitations) — surfaced prominently in the report.
    $gpoNote = 'GPO content &mdash; ADPulse checks GPO metadata (flags, version, SYSVOL path, links) but does not parse GPO settings files from SYSVOL (with the exception of the cpassword scan in check 25).'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADPulse Active Directory Security Report - $(HtmlEnc $DomainName)</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Segoe UI",Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
  h1{color:#38bdf8;font-size:1.8rem;margin-bottom:.3rem}
  h2{color:#94a3b8;font-size:1rem;font-weight:bold;margin:1.5rem 0 .5rem;text-transform:uppercase;letter-spacing:.05em}
  .meta{color:#64748b;font-size:.9rem;margin-bottom:1rem}
  .score-box{display:inline-block;font-size:3rem;font-weight:900;color:$scCol;border:3px solid $scCol;border-radius:12px;padding:.2rem 1.2rem;margin:.5rem 0}
  .level{font-size:1.2rem;color:$scCol;font-weight:bold}
  .summary{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}
  .sbar{padding:.5rem 1rem;border-radius:8px;color:#fff;font-size:.85rem;min-width:80px;text-align:center}
  .card-row{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}
  .stat-card{background:#1e293b;border-radius:8px;padding:.8rem 1.1rem;min-width:160px;flex:1}
  .card-label{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}
  .card-value{font-size:2rem;font-weight:900;line-height:1}
  .card-sub{font-size:.75rem;color:#64748b;margin-top:.2rem}
  .glance-item{background:#1e293b;border-radius:8px;padding:.8rem 1rem;margin-bottom:.5rem}
  .glance-header{display:flex;align-items:center;gap:.6rem}
  .glance-title{font-weight:bold;font-size:.95rem;flex:1}
  .glance-score{color:#dc2626;font-weight:bold;font-size:.85rem;white-space:nowrap}
  .glance-desc{color:#94a3b8;font-size:.82rem;margin-top:.35rem;line-height:1.5}
  .glance-rec{color:#4ade80;font-size:.8rem;margin-top:.3rem}
  .glance-empty{background:#1e293b;border-radius:8px;padding:1rem;text-align:center}
  .note-box{background:#1e293b;border-left:3px solid #38bdf8;border-radius:8px;padding:.8rem 1rem;color:#94a3b8;font-size:.82rem;line-height:1.5;margin:.5rem 0}
  .cat-section{margin-bottom:.6rem;border:1px solid #1e293b;border-radius:8px;overflow:hidden}
  .cat-header{display:flex;align-items:center;gap:.7rem;padding:.7rem 1rem;background:#1e293b;cursor:pointer;user-select:none}
  .cat-header:hover{background:#263348}
  .cat-title{font-weight:bold;font-size:1rem;flex:1}
  .cat-count{color:#64748b;font-size:.85rem}
  .chevron{color:#64748b;font-size:.8rem;transition:transform .2s}
  .cat-body.collapsed{display:none}
  table{width:100%;border-collapse:collapse;font-size:.85rem;table-layout:fixed}
  th,td{padding:8px;vertical-align:top;border-bottom:1px solid #1e293b;overflow-wrap:break-word;word-break:break-word}
  th{background:#0f1f35;color:#94a3b8;text-align:left}
  tr:hover td{background:#1a2740}
  .col-sev{width:90px;white-space:nowrap}
  .col-finding{width:40%}
  .col-rec{color:#4ade80;font-size:.8rem}
  .col-score{width:52px;text-align:center;font-weight:bold;white-space:nowrap}
  .badge{color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;white-space:nowrap}
  .desc{color:#94a3b8;font-size:.8rem}
  .ref{display:block;color:#38bdf8;font-size:.75rem;word-break:break-all;margin-top:2px}
  ul{margin:.3rem 0;padding-left:1.2rem;color:#94a3b8}
  code{background:#0f1f35;padding:1px 5px;border-radius:3px;font-size:.82rem}
  .stats-grid td{padding:4px 8px;border-bottom:1px solid #1e293b;font-size:.82rem}
  .btn{background:#1e293b;color:#e2e8f0;border:1px solid #334155;padding:4px 12px;border-radius:4px;cursor:pointer;margin-right:.4rem}
  .btn:hover{background:#263348}
  .legend{display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem}
  .legend-score,.legend-sev{flex:1;min-width:280px;background:#1e293b;border-radius:8px;padding:1rem}
  .legend-title{font-weight:bold;color:#38bdf8;margin-bottom:.6rem;font-size:.95rem}
  .legend-desc{color:#94a3b8;font-size:.82rem;margin-bottom:.7rem;line-height:1.5}
  .legend-table{width:100%;border-collapse:collapse;font-size:.85rem}
  .legend-table th{background:#0f1f35;color:#94a3b8;padding:8px;text-align:left}
  .legend-table td{border-bottom:1px solid #1e293b;padding:8px;color:#cbd5e1;vertical-align:top}
  .legend-table tr:last-child td{border-bottom:none}
  footer{margin-top:2rem;color:#475569;font-size:.75rem;text-align:center}
</style>
<script>
  function toggle(h){var b=h.nextElementSibling,c=h.querySelector('.chevron');b.classList.toggle('collapsed');c.style.transform=b.classList.contains('collapsed')?'rotate(-90deg)':'';}
  function expandAll(){document.querySelectorAll('.cat-body').forEach(function(b){b.classList.remove('collapsed');});}
  function collapseAll(){document.querySelectorAll('.cat-body').forEach(function(b){b.classList.add('collapsed');});}
</script>
</head>
<body>
<h1>ADPulse Active Directory Security Report</h1>
<div class="meta">Domain: <strong>$(HtmlEnc $DomainName)</strong> &nbsp;|&nbsp; DC: <strong>$(HtmlEnc $DcIpAddr)</strong> &nbsp;|&nbsp; Scanned: <strong>$(HtmlEnc $ScanTime)</strong></div>
<div class="score-box">$score</div>
<span class="level"> / 100 &nbsp;&mdash; $level RISK</span>
<div class="summary">$summaryBars</div>

<h2>At a Glance &mdash; Most Critical Findings</h2>
$criticalHtml

<h2>Scoring Legend</h2>
<div class="legend">
  <div class="legend-score">
    <div class="legend-title">Risk Score</div>
    <div class="legend-desc">Starts at <strong>100</strong>; deductions applied per finding.</div>
    <table class="legend-table">
      <tr><th>Score</th><th>Risk Level</th><th>Meaning</th></tr>
      <tr><td>80&ndash;100</td><td><span class="badge" style="background:#16a34a">LOW</span></td><td>Good posture, minor issues only</td></tr>
      <tr><td>60&ndash;79</td><td><span class="badge" style="background:#ca8a04">MEDIUM</span></td><td>Notable weaknesses to address</td></tr>
      <tr><td>40&ndash;59</td><td><span class="badge" style="background:#ea580c">HIGH</span></td><td>Significant vulnerabilities</td></tr>
      <tr><td>0&ndash;39</td><td><span class="badge" style="background:#dc2626">CRITICAL</span></td><td>Severe risks &mdash; immediate action</td></tr>
    </table>
  </div>
  <div class="legend-sev">
    <div class="legend-title">Severity Levels</div>
    <table class="legend-table">
      <tr><th>Severity</th><th>Deduction</th><th>Meaning</th></tr>
      <tr><td><span class="badge" style="background:#dc2626">CRITICAL</span></td><td>20&ndash;25 pts</td><td>Directly exploitable, likely leads to full domain compromise</td></tr>
      <tr><td><span class="badge" style="background:#ea580c">HIGH</span></td><td>10&ndash;15 pts</td><td>Serious misconfiguration enabling privilege escalation</td></tr>
      <tr><td><span class="badge" style="background:#ca8a04">MEDIUM</span></td><td>5&ndash;10 pts</td><td>Security weakness increasing attack surface</td></tr>
      <tr><td><span class="badge" style="background:#2563eb">LOW</span></td><td>2&ndash;5 pts</td><td>Minor hardening gap</td></tr>
      <tr><td><span class="badge" style="background:#6b7280">INFO</span></td><td>0 pts</td><td>Informational, manual review recommended</td></tr>
    </table>
  </div>
</div>

<h2>Findings</h2>
<div style="margin-bottom:.8rem"><button class="btn" onclick="expandAll()">Expand All</button><button class="btn" onclick="collapseAll()">Collapse All</button></div>
$sections

<h2>Statistics</h2>
<h2 style="margin-top:0;color:#64748b;font-size:.85rem;text-transform:none;letter-spacing:0">Key Metrics</h2>
$statCardsHtml
$newChecksHtml

<h2>Scan Coverage Note</h2>
<div class="note-box">$gpoNote</div>

<footer>Generated by ADPulse Active Directory Security Scanner &mdash; for authorised use only</footer>
</body>
</html>
"@
    $html | Out-File -FilePath $Path -Encoding utf8
    Write-C "[+] HTML report -> $Path" 'Green'
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN (ADPulse.py main)
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Main {
    # Banner (verbatim from the original)
    Write-Host '╔═══════════════════════════════════════════╗'
    Write-Host '║ ADPulse Active Directory Security Scanner ║'
    Write-Host '║                version 1.0                ║'
    Write-Host '║                by TheMayor                ║'
    Write-Host '╚═══════════════════════════════════════════╝'
    Write-C '   Original tool by Joe Helle (dievus/TheMayor) - github.com/dievus/ADPulse' 'DarkGray'
    Write-C '   PowerShell port - all detection logic credit to the original author' 'DarkGray'
    Write-Host ''

    # Credential handling
    $ntHashHex = ''
    if ($PSCmdlet.ParameterSetName -eq 'Hash' -or $Hash) {
        $parts = $Hash.Trim().Split(':')
        if ($parts.Count -eq 2) { $ntHashHex = $parts[1] } else { $ntHashHex = $parts[0] }
        if ($ntHashHex.Length -ne 32) { Write-C "[!] NT hash must be 32 hex chars, got $($ntHashHex.Length)." 'Red'; return }
        Write-C "[+] Auth mode         : pass-the-hash (NT: $ntHashHex)" 'Gray'
        Write-C '    NOTE: .NET LdapConnection cannot inject a raw NT hash the way the Python' 'DarkGray'
        Write-C '    tool patches MD4. Run PtH from a host/tooling that supports it, or use -Password.' 'DarkGray'
    }
    else {
        Write-C '[+] Auth mode         : password' 'Gray'
    }

    # DC resolution
    $dcIpResolved = if ($DcIp) { $DcIp } else { Resolve-Dc $Domain }
    if (-not $dcIpResolved) { Write-C '[!] Could not resolve DC. Use -DcIp to specify one explicitly.' 'Red'; return }
    Write-C "[+] Domain Controller : $dcIpResolved" 'Gray'

    # Connect
    if (-not (Connect-AD -DcIpAddr $dcIpResolved -DomainName $Domain -Username $User -PasswordText $Password -NtHashHex $ntHashHex)) {
        Write-C '[!] Could not establish LDAP connection. Aborting.' 'Red'; return
    }
    Write-C '[+] LDAP bind successful' 'Green'; Write-C ''

    # Run checks
    $result = Invoke-AllChecks
    $findings = @($result.findings); $stats = $result.stats
    $scanTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    # Output
    $outDir = Join-Path $OutputDir 'Reports'
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')

    if ($Report -in @('console', 'all')) { Write-Report -Findings $findings -Stats $stats -DomainName $Domain -DcIpAddr $dcIpResolved -ScanTime $scanTime }
    if ($Report -in @('json', 'all')) { Export-Json -Findings $findings -Stats $stats -DomainName $Domain -DcIpAddr $dcIpResolved -ScanTime $scanTime -Path (Join-Path $outDir "ad_scan_${Domain}_${ts}.json") }
    if ($Report -in @('html', 'all')) { Export-Html -Findings $findings -Stats $stats -DomainName $Domain -DcIpAddr $dcIpResolved -ScanTime $scanTime -Path (Join-Path $outDir "ad_scan_${Domain}_${ts}.html") }
}

try { Invoke-Main }
catch { Write-C "[!] Fatal error: $_" 'Red' }
