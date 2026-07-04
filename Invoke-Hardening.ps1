#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Config-driven hardening engine: audit, remediate, and roll back
    compliance controls defined in controls.json.

.DESCRIPTION
    Controls are defined declaratively in a JSON file (service state,
    registry values, firewall logging, event log sizes). The engine:

      Audit     - checks every control, reports PASS/FAIL, changes nothing
      Remediate - backs up current state to a timestamped JSON file,
                  then applies only the failing controls
      Rollback  - restores the state captured in a backup file

.EXAMPLE
    .\Invoke-Hardening.ps1 -Mode Audit

.EXAMPLE
    .\Invoke-Hardening.ps1 -Mode Remediate

.EXAMPLE
    .\Invoke-Hardening.ps1 -Mode Remediate -ControlId SVC-001,REG-004

.EXAMPLE
    .\Invoke-Hardening.ps1 -Mode Rollback   # uses most recent backup

.NOTES
    Tested on Windows 10 22H2. Exit code = number of failed controls
    (Audit mode), so it can gate a CI pipeline or scheduled task.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Audit", "Remediate", "Rollback")]
    [string]$Mode,

    [string]$ControlsFile = (Join-Path $PSScriptRoot "controls.json"),
    [string]$BackupDir    = (Join-Path $PSScriptRoot "backups"),
    [string]$BackupFile,          # Rollback only; defaults to most recent
    [string[]]$ControlId          # Optional: limit to specific control IDs
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- state readers

function Get-ControlState {
    param($Control)
    switch ($Control.type) {
        "service" {
            $svc = Get-Service -Name $Control.service -ErrorAction SilentlyContinue
            if (-not $svc) { return @{ present = $false } }
            return @{ present = $true; startType = "$($svc.StartType)"; status = "$($svc.Status)" }
        }
        "registry" {
            if (Test-Path $Control.path) {
                $prop = Get-ItemProperty -Path $Control.path -Name $Control.valueName -ErrorAction SilentlyContinue
                if ($null -ne $prop) {
                    return @{ present = $true; value = $prop.($Control.valueName) }
                }
            }
            return @{ present = $false }
        }
        "firewall-logging" {
            $p = Get-NetFirewallProfile -Name $Control.profile
            return @{
                present   = $true
                logFile   = $p.LogFileName
                maxSizeKB = [int]$p.LogMaxSizeKilobytes
                blocked   = "$($p.LogBlocked)"
                allowed   = "$($p.LogAllowed)"
            }
        }
        "eventlog" {
            $log = Get-WinEvent -ListLog $Control.logName -ErrorAction SilentlyContinue
            if (-not $log) { return @{ present = $false } }
            return @{ present = $true; maxSizeBytes = [int64]$log.MaximumSizeInBytes }
        }
        default { throw "Unknown control type: $($Control.type)" }
    }
}

# ---------------------------------------------------------------- compliance test

function Test-Control {
    param($Control, $State)
    switch ($Control.type) {
        "service" {
            if (-not $State.present) { return @{ pass = $true; detail = "service not installed" } }
            $ok = ($State.startType -eq "Disabled")
            return @{ pass = $ok; detail = "StartType=$($State.startType), Status=$($State.status)" }
        }
        "registry" {
            if (-not $State.present) { return @{ pass = $false; detail = "value not set" } }
            $ok = ($State.value -eq $Control.expectedValue)
            return @{ pass = $ok; detail = "current=$($State.value), expected=$($Control.expectedValue)" }
        }
        "firewall-logging" {
            $ok = ($State.blocked -eq "True") -and
                  ($State.allowed -eq "True") -and
                  ($State.maxSizeKB -ge $Control.minSizeKB)
            return @{ pass = $ok; detail = "blocked=$($State.blocked), allowed=$($State.allowed), maxKB=$($State.maxSizeKB)" }
        }
        "eventlog" {
            if (-not $State.present) { return @{ pass = $false; detail = "log not found" } }
            $ok = ($State.maxSizeBytes -ge [int64]$Control.minSizeBytes)
            return @{ pass = $ok; detail = "current=$($State.maxSizeBytes), min=$($Control.minSizeBytes)" }
        }
    }
}

# ---------------------------------------------------------------- remediation

function Set-Control {
    param($Control)
    switch ($Control.type) {
        "service" {
            Stop-Service -Name $Control.service -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $Control.service -StartupType Disabled
        }
        "registry" {
            if (-not (Test-Path $Control.path)) {
                New-Item -Path $Control.path -Force | Out-Null
            }
            New-ItemProperty -Path $Control.path -Name $Control.valueName `
                -Value $Control.expectedValue -PropertyType $Control.valueType -Force | Out-Null
        }
        "firewall-logging" {
            Set-NetFirewallProfile -Name $Control.profile `
                -LogFileName $Control.logFile `
                -LogMaxSizeKilobytes $Control.minSizeKB `
                -LogBlocked True -LogAllowed True
        }
        "eventlog" {
            wevtutil sl $Control.logName /ms:$($Control.minSizeBytes)
        }
    }
}

# ---------------------------------------------------------------- rollback

function Restore-Control {
    param($Control, $SavedState)
    switch ($Control.type) {
        "service" {
            if (-not $SavedState.present) { return }
            Set-Service -Name $Control.service -StartupType $SavedState.startType
            if ($SavedState.status -eq "Running") {
                Start-Service -Name $Control.service -ErrorAction SilentlyContinue
            }
        }
        "registry" {
            if ($SavedState.present) {
                New-ItemProperty -Path $Control.path -Name $Control.valueName `
                    -Value $SavedState.value -PropertyType $Control.valueType -Force | Out-Null
            } else {
                Remove-ItemProperty -Path $Control.path -Name $Control.valueName -ErrorAction SilentlyContinue
            }
        }
        "firewall-logging" {
            Set-NetFirewallProfile -Name $Control.profile `
                -LogFileName $SavedState.logFile `
                -LogMaxSizeKilobytes $SavedState.maxSizeKB `
                -LogBlocked $SavedState.blocked -LogAllowed $SavedState.allowed
        }
        "eventlog" {
            if ($SavedState.present) {
                wevtutil sl $Control.logName /ms:$($SavedState.maxSizeBytes)
            }
        }
    }
}

# ---------------------------------------------------------------- main

$config   = Get-Content $ControlsFile -Raw | ConvertFrom-Json
$controls = $config.controls
if ($ControlId) {
    $controls = $controls | Where-Object { $ControlId -contains $_.id }
    if (-not $controls) { throw "No controls match the given ControlId filter." }
}

switch ($Mode) {

    "Audit" {
        $results = foreach ($c in $controls) {
            $state = Get-ControlState -Control $c
            $test  = Test-Control -Control $c -State $state
            [PSCustomObject]@{
                Id      = $c.id
                Control = $c.name
                Status  = if ($test.pass) { "PASS" } else { "FAIL" }
                Detail  = $test.detail
            }
        }
        $results | Format-Table -AutoSize
        $failed = @($results | Where-Object Status -eq "FAIL")
        Write-Host ("`n{0} controls checked: {1} PASS, {2} FAIL" -f `
            $results.Count, ($results.Count - $failed.Count), $failed.Count) `
            -ForegroundColor $(if ($failed.Count) { "Yellow" } else { "Green" })
        exit $failed.Count
    }

    "Remediate" {
        # 1. Snapshot current state of every targeted control
        if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }
        $stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
        $backup = @{}
        foreach ($c in $controls) {
            $backup[$c.id] = Get-ControlState -Control $c
        }
        $backupPath = Join-Path $BackupDir "backup-$stamp.json"
        $backup | ConvertTo-Json -Depth 5 | Set-Content $backupPath
        Write-Host "State backed up to $backupPath`n" -ForegroundColor Cyan

        # 2. Apply only the failing controls
        foreach ($c in $controls) {
            $state = Get-ControlState -Control $c
            $test  = Test-Control -Control $c -State $state
            if ($test.pass) {
                Write-Host ("  SKIP  {0}  {1} (already compliant)" -f $c.id, $c.name) -ForegroundColor DarkGray
                continue
            }
            if ($c.warning) {
                Write-Host ("  WARN  {0}  {1}" -f $c.id, $c.warning) -ForegroundColor Yellow
            }
            try {
                Set-Control -Control $c
                Write-Host ("  FIXED {0}  {1}" -f $c.id, $c.name) -ForegroundColor Green
            } catch {
                Write-Host ("  ERROR {0}  {1}: {2}" -f $c.id, $c.name, $_.Exception.Message) -ForegroundColor Red
            }
        }
        Write-Host "`nDone. Run '-Mode Audit' to verify, or '-Mode Rollback' to undo." -ForegroundColor Cyan
    }

    "Rollback" {
        if (-not $BackupFile) {
            $latest = Get-ChildItem $BackupDir -Filter "backup-*.json" -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $latest) { throw "No backup files found in $BackupDir" }
            $BackupFile = $latest.FullName
        }
        Write-Host "Restoring from $BackupFile`n" -ForegroundColor Cyan
        $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json

        foreach ($c in $controls) {
            $saved = $backup.($c.id)
            if ($null -eq $saved) { continue }
            try {
                Restore-Control -Control $c -SavedState $saved
                Write-Host ("  RESTORED {0}  {1}" -f $c.id, $c.name) -ForegroundColor Green
            } catch {
                Write-Host ("  ERROR    {0}  {1}: {2}" -f $c.id, $c.name, $_.Exception.Message) -ForegroundColor Red
            }
        }
        Write-Host "`nRollback complete. Run '-Mode Audit' to inspect current state." -ForegroundColor Cyan
    }
}
