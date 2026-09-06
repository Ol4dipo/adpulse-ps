# ADPulse  PowerShell Edition

A dependency-free PowerShell port of [**ADPulse**](https://github.com/dievus/ADPulse), the open-source Active Directory security scanner by [**Joe Helle (dievus / TheMayor)**](https://github.com/dievus).

Point it at a domain, and it runs 35 checks over LDAP/LDAPS, scores the domain out of 100, and writes console, JSON, and HTML reports  all from a single `.ps1` file, with no Python, no pip, and no modules to install.

```powershell
.\ADPulse.ps1 -Domain corp.local -User jdoe -Password 'P@ssw0rd!'
```

---

## Credit where it's due

**This is a port, not an original tool.** Every check, the scoring model, the severities, the remediation guidance, and the research behind each detection come from Joe Helle's Python ADPulse. This repository only rewrites that work in PowerShell so it runs natively on Windows without dependencies.

If you get value from this, go **star the original**: **https://github.com/dievus/ADPulse**  and credit [@dievus](https://github.com/dievus). Bugs in detection *logic* almost certainly belong upstream; bugs in the *PowerShell* belong here.

---

## Why this port exists

The original is excellent but needs Python plus `ldap3` and `impacket`. That's a hurdle on a locked-down Windows box or a client jump host where you can't freely install packages.

This version leans on `System.DirectoryServices.Protocols`, which ships with .NET, so it runs on a stock Windows install:

- **No dependencies**  one file, nothing to `pip install`
- **Runs on Windows PowerShell 5.1 and PowerShell 7+**
- **Same checks, same scoring, same report layout** as the original
- **Drop-and-run**  copy `ADPulse.ps1` to the host and go

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Line of sight to a Domain Controller (LDAP 389 / LDAPS 636)
- Domain credentials : a standard user covers most checks; some ACL/security-descriptor checks see more with elevated rights
- For the GPP cpassword check (check 25): read access to `\\<dc>\SYSVOL`

---

## Getting started

Scripts pulled from the internet are blocked until you unblock them. In the session where you'll run it:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Unblock-File .\ADPulse.ps1
```

Then run a scan:

```powershell
# Password auth
.\ADPulse.ps1 -Domain corp.local -User jdoe -Password 'P@ssw0rd!'

# Name the DC explicitly (best when running on the DC itself)
.\ADPulse.ps1 -Domain corp.local -User jdoe -Password 'P@ssw0rd!' -DcIp 10.0.0.10

# HTML report only, into a chosen folder
.\ADPulse.ps1 -Domain corp.local -User jdoe -Password 'P@ssw0rd!' -Report html -OutputDir C:\Audits

# Pass-the-hash (see caveat under Limitations)
.\ADPulse.ps1 -Domain corp.local -User jdoe -Hash 31d6cfe0d16ae931b73c59d7e0c089c0
```

> **Tip:** wrap passwords containing `$`, `@`, or other special characters in **single quotes** so PowerShell doesn't interpret them.

---

## Parameters

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `-Domain` | yes | Target domain FQDN, e.g. `corp.local` |
| `-User` | yes | Username to bind as |
| `-Password` | password mode | Plaintext password (single-quote it if it has special characters) |
| `-Hash` / `-H` | hash mode | NT hash, or an `LM:NT` pair, for pass-the-hash |
| `-DcIp` | no | DC IP or hostname; resolved via DNS if omitted |
| `-Report` | no | `console`, `json`, `html`, or `all`  default `all` |
| `-OutputDir` | no | Base folder for reports; default is the current directory |
| `-NoColor` | no | Plain console output, no ANSI colours |

---

## What you get back

Reports land in `<OutputDir>\Reports\`:

- **`ad_scan_<domain>_<timestamp>.json`** full findings, machine-readable, easy to feed into a SIEM or diff between scans
- **`ad_scan_<domain>_<timestamp>.html`** dark-themed report: at-a-glance criticals, key metrics, collapsible per-category findings, and a scoring legend

The console output gives you a summary, the top findings, key metrics, every finding by severity, and an additional-check summary table.

### How the score works

You start at 100. Every finding subtracts its risk value. The score can't go below 0:

```
score = max(0, 100 - sum(risk_scores))
```

| Score | Risk level |
|:-----:|:----------:|
| 80-100 | LOW |
| 60-79 | MEDIUM |
| 40-59 | HIGH |
| 0-39 | CRITICAL |

A deliberately vulnerable lab can legitimately land on **0/100** that just means the findings added up to more than 100 points of deductions, which is the point. On a hardened domain you'll see a much higher number.

---

## The 35 checks

Run in the same order as the original.

**Core (1-24)**

Password policy · privileged accounts · Kerberos (Kerberoasting / AS-REP / DES) · unconstrained delegation · constrained delegation · ADCS (ESC1/2/3/6/8/9/10/11/13/15) · domain trusts · account hygiene · protocol security · GPOs · LAPS · LAPS coverage · DNS · domain controllers · ACLs (ESC4/5/7 + DCSync) · optional features · replication · service accounts · misc hardening · deprecated OS · legacy protocols (SMBv1 / signing / null sessions) · Exchange · adminCount inventory · passwords in descriptions

**Additional (25-35)**

GPP cpassword in SYSVOL (MS14-025) · AdminSDHolder ACL · SID history · shadow credentials (`msDS-KeyCredentialLink`) · RC4 Kerberos encryption · foreign security principals in privileged groups · Pre-Windows 2000 group · dangerous constrained-delegation targets · orphaned subnets · legacy FRS SYSVOL replication · RBCD on the domain / DC objects

---

## Limitations

- **Registry-only settings** NTLMv1 (`LmCompatibilityLevel`), WDigest (`UseLogonCredential`), and LDAP signing / channel binding can't be read over LDAP, so they're reported as manual-verification items.
- **GPO content** ADPulse checks GPO *metadata* (flags, version, SYSVOL path, links) but does **not** parse GPO settings files from SYSVOL, with the single exception of the cpassword scan in check 25.
- **Pass-the-hash** : .NET's `LdapConnection` can't inject a raw NT hash the way the original's `ldap3` MD4 patch does. Password auth behaves identically; `-Hash` mode is best-effort and depends on platform support. For reliable PtH, drive it from tooling built for that.
- **SMB probes** : a firewall blocking port 445 can produce false negatives on the SMBv1 / signing / null-session checks.
- **Query cap** : LDAP searches are capped at 10,000 results each.

---

## A note on testing

This port has been validated at the code level (it parses cleanly and the logic mirrors the original) and against a lab domain, but it has **not** been exhaustively tested across every AD topology. Treat it as you would any security tool: verify surprising results against the raw directory before acting on them. If a check reports `0` where you expect findings, confirm the underlying attribute or membership actually exists in AD  in a lab, missing data (e.g. an unpopulated `operatingSystem` attribute, or `adminCount` that SDProp hasn't propagated yet) is a common and legitimate cause.

Found a real discrepancy between this port and the original's behaviour? Open an issue.

---

## Legal

For **authorised security assessments only.** Run it solely against domains you own or have explicit written permission to test. The authors and contributors accept no liability for misuse or for any damage arising from use of this tool.

---

## License & acknowledgements

Released under the **MIT License** (see [`LICENSE`](LICENSE)). The original work is Copyright (c) 2026 Joe Helle; that attribution is preserved in the license, and this port is distributed under the same terms.

- **Original ADPulse & all detection logic** — [Joe Helle (dievus / TheMayor)](https://github.com/dievus) · https://github.com/dievus/ADPulse
- **Technique references** — [MITRE ATT&CK](https://attack.mitre.org/)
