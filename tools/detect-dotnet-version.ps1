<#
.SYNOPSIS
    Accurately identify the installed .NET Framework version and patch level.

.DESCRIPTION
    Vulnerability scanners flag missing .NET updates, but identifying the
    correct patch requires knowing the REAL installed version. The registry
    Release value can be misleading: a machine can report 4.8 registry keys
    while actually running 4.8.1 (installed via hotfix). This script
    cross-references the registry with installed hotfixes to avoid applying
    non-applicable update packages.

.NOTES
    No elevation required for detection.
#>

# --- Registry-reported version ---
$release = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release
$version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Version

$releaseMap = @{
    528040 = "4.8 (Win10 May 2019+)"
    528372 = "4.8 (Win10 20H1-22H2)"
    528449 = "4.8 (Win11/Server 2022)"
    533320 = "4.8.1 (Win11 22H2+)"
    533325 = "4.8.1 (all other OS)"
}

Write-Host "`n--- Registry ---" -ForegroundColor Cyan
Write-Host "Release value : $release"
Write-Host "Version string: $version"
if ($releaseMap.ContainsKey([int]$release)) {
    Write-Host "Mapped version: $($releaseMap[[int]$release])" -ForegroundColor Green
} else {
    Write-Host "Unknown Release value - check Microsoft docs for newer mappings." -ForegroundColor Yellow
}

# --- Cross-reference with installed hotfixes ---
# KB5011048 = .NET 4.8.1 installer package: its presence means 4.8.1 is
# installed even if the registry still shows 4.8-era keys.
Write-Host "`n--- Installed .NET-related hotfixes ---" -ForegroundColor Cyan
$dotnetKBs = Get-HotFix | Where-Object { $_.Description -match "Update" } |
    Sort-Object InstalledOn -Descending |
    Select-Object HotFixID, Description, InstalledOn

$dotnetKBs | Format-Table -AutoSize

if ($dotnetKBs.HotFixID -contains "KB5011048") {
    Write-Host ".NET Framework 4.8.1 is installed (KB5011048 present)." -ForegroundColor Green
    Write-Host "Use 4.8.1-applicable update packages, NOT 4.8-only packages." -ForegroundColor Yellow
}

# --- Sanity check: flag hotfixes with future install dates (clock issues) ---
$future = $dotnetKBs | Where-Object { $_.InstalledOn -gt (Get-Date) }
if ($future) {
    Write-Host "`nWARNING: hotfixes with future install dates detected - verify system clock:" -ForegroundColor Red
    $future | Format-Table -AutoSize
}
