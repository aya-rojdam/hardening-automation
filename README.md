# hardening-automation

A config-driven hardening engine for auditing, remediating, and rolling back compliance controls. Built out of real CIS Benchmark remediation work in a vulnerability management workflow (scan → remediate → re-scan → verify).

Controls are declared in JSON, not hardcoded. Adding a control means adding an object, not writing code.

## Getting Started

1. **Open PowerShell as Administrator.**
2. **Set Execution Policy:** Windows restricts local script execution by default. To allow the script to run in your current session, use:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   
3. **Navigate to the repository folder:**
   ```powershell
   cd path\to\hardening-automation

4. **Audit your system:**
   ```powershell
   .\Invoke-Hardening.ps1 -Mode Audit


## How it works

```powershell
# Check compliance state, change nothing (exit code = failure count)
.\Invoke-Hardening.ps1 -Mode Audit

# Snapshot current state, then fix only the failing controls
.\Invoke-Hardening.ps1 -Mode Remediate

# Undo: restore state from the latest backup
.\Invoke-Hardening.ps1 -Mode Rollback

# Target specific controls
.\Invoke-Hardening.ps1 -Mode Remediate -ControlId SVC-001,REG-004
```

Every remediation run writes a timestamped state snapshot to `backups/` before touching anything, so changes are always reversible.

## Supported control types

| Type | Checks / enforces | Mechanism |
|------|-------------------|-----------|
| `service` | Service disabled | `Set-Service` |
| `registry` | Registry value present and correct | `New-ItemProperty` |
| `firewall-logging` | Logging enabled per profile, min log size | `Set-NetFirewallProfile` |
| `eventlog` | Minimum event log size | `wevtutil` |

## Included baseline (`controls.json`)

22 controls aligned with CIS Benchmark recommendations for Windows 10 22H2:

- **Services (CIS §5):** UPnP, SSDP, Xbox services, ICS, RPC Locator, media sharing
- **Registry (CIS §18):** AutoPlay/AutoRun disabled, Authenticode cert padding check (MSA 2915720)
- **Firewall (CIS §9):** logging enabled on Domain/Private/Public profiles, 16 MB minimum
- **Event logs (CIS §18):** minimum sizes for Application, Security, Setup, System

Controls carrying operational risk (ICS, cert padding check) have a `warning` field that surfaces at remediation time.

## Tools

`tools/detect-dotnet-version.ps1` identifies the real .NET Framework patch level by cross-referencing registry keys with installed hotfixes. Solves a real remediation problem: the registry can report 4.8 while 4.8.1 is actually installed, which leads to selecting non-applicable update packages when addressing scanner findings.

## Extending

Add a control to `controls.json`:

```json
{
  "id": "REG-006",
  "name": "My new control",
  "cisSection": "18",
  "type": "registry",
  "path": "HKLM:\\SOFTWARE\\...",
  "valueName": "SomeValue",
  "valueType": "DWord",
  "expectedValue": 1
}
```

New control *types* (audit policies, SMB settings, local security policy) require implementing them in the four engine functions: `Get-ControlState`, `Test-Control`, `Set-Control`, `Restore-Control`.

## Roadmap

- Audit policy and LSA control types
- Linux baseline (bash + the same JSON control model)
- HTML compliance report output

## Disclaimer

Built and tested against Windows 10 22H2 in a lab environment. Audit mode is always safe; review `controls.json` before remediating, and test in your own environment before production use.
