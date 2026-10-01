#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the local Point and Print configuration for PrintNightmare-class issues. Read-only.

.DESCRIPTION
    Reports whether a standard user could install a printer driver (and reach SYSTEM) on this
    machine, and classifies the result:
        SECURE   - driver installation is restricted to administrators (default since KB5005652).
        CASE 1   - CVE-2021-34527 "PrintNightmare": non-admins can install AND a security prompt
                   is disabled.
        CASE 2   - "Bring Your Own Vulnerable Driver": non-admins can install from any server
                   (no approved-server list).
        CASE 3   - residual risk: approved-server list set, but still bypassable by spoofing an
                   approved server name (DNS spoofing / MITM).

    Only the computer policy (HKLM) is read: current Windows ignores Point and Print Restrictions
    set in the user context, so HKCU values would be misleading.

    Nothing is modified and no administrator privileges are required.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PointAndPrintCheck.ps1

.LINK
    https://itm4n.github.io/printnightmare-exploitation/
    https://itm4n.github.io/printnightmare-not-over/
    https://support.microsoft.com/en-gb/topic/kb5005652-873642bf-2634-49c5-a23b-6d8e9a302872
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PointAndPrintKey        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$PackagePointAndPrintKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint'
$ListOfServersKey        = "$PackagePointAndPrintKey\ListofServers"

# ------------------------------------------------------------------------------------

# Reads a single registry value, returning $null when the key or value is absent.
# Reads the whole key then tests for the property, so a missing value is $null even
# under Set-StrictMode (dynamic .$Name access would otherwise throw).
function Get-PolicyValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties.Name -contains $Name) { $item.$Name } else { $null }
}

# Prints one check line: marker, value name, raw value, and a short plain-language note.
function Write-Check {
    param(
        [ValidateSet('OK', '!', '-')][string]$Marker,
        [string]$Name,
        [string]$Value,
        [string]$Note
    )
    $color = switch ($Marker) { 'OK' { 'Green' } '!' { 'Red' } '-' { 'DarkGray' } }
    # Pad the bracketed marker to a fixed width so [OK] and [!] keep the columns aligned.
    Write-Host ('  {0,-5}' -f "[$Marker]") -ForegroundColor $color -NoNewline
    Write-Host ('{0,-44} {1,-10} {2}' -f $Name, $Value, $Note)
}

function Write-Separator {
    Write-Host ('  ' + ('-' * 61)) -ForegroundColor DarkGray
}

# Formats a registry value for display: 'not set' when absent, otherwise its value.
function Show-Value {
    param($Value)
    if ($null -eq $Value) { 'not set' } else { "$Value" }
}

# ------------------------------------------------------------------------------------

$spooler         = Get-Service -Name Spooler -ErrorAction SilentlyContinue
$spoolerRunning  = $spooler -and $spooler.Status -eq 'Running'
$spoolerDisabled = -not $spooler -or $spooler.StartType -eq 'Disabled'

# Absent or 1 = installation restricted to administrators (overrides every other P&P setting).
$restrictToAdmins = Get-PolicyValue $PointAndPrintKey 'RestrictDriverInstallationToAdministrators'

# "Point and Print Restrictions" policy. Restricted = 0 means it is explicitly Disabled, which
# itself suppresses the warning and elevation prompts.
$restricted       = Get-PolicyValue $PointAndPrintKey 'Restricted'
$noWarnOnInstall  = Get-PolicyValue $PointAndPrintKey 'NoWarningNoElevationOnInstall'
$updatePrompt     = Get-PolicyValue $PointAndPrintKey 'UpdatePromptSettings'

$packageOnly      = Get-PolicyValue $PackagePointAndPrintKey 'PackagePointAndPrintOnly'
$serverListOn     = Get-PolicyValue $PackagePointAndPrintKey 'PackagePointAndPrintServerList'

$approvedServers = @()
if (Test-Path $ListOfServersKey) {
    $key = Get-Item $ListOfServersKey
    $approvedServers = @(
        $key.GetValueNames() |
            ForEach-Object { "$($key.GetValue($_))".Trim() } |
            Where-Object { $_ }
    )
}

# -----------------------------------------------------------------------------------

$nonAdminsCanInstall = $restrictToAdmins -eq 0

# A value weakens security only when it is set to its insecure value, never when absent.
# ($null -ne 0 is $true in PowerShell, so the null guard is required.)
$restrictedDisabled = $restricted -eq 0                                        # policy explicitly Disabled
$noWarnDisabled     = $null -ne $noWarnOnInstall -and $noWarnOnInstall -ne 0    # 1 = no prompt
$updateDisabled     = $null -ne $updatePrompt    -and $updatePrompt    -ne 0    # 1/2 = weakened prompt
$promptsDisabled    = $restrictedDisabled -or $noWarnDisabled -or $updateDisabled

$serverListEnforced = $serverListOn -eq 1 -and $approvedServers.Count -gt 0

# Classify. Only reachable once non-admins are allowed to install drivers.
if (-not $nonAdminsCanInstall) { $case = 'SECURE' }
elseif ($promptsDisabled)      { $case = 'CASE1' }
elseif (-not $serverListEnforced) { $case = 'CASE2' }
else                           { $case = 'CASE3' }

# -------------------------------------------------------------------------------------

Write-Host ''
Write-Host "=== Point and Print check - $env:COMPUTERNAME ($env:USERNAME) ===" -ForegroundColor Cyan
Write-Host ''

$spoolerMarker = if ($spoolerDisabled) { '-' } else { 'OK' }
Write-Check $spoolerMarker 'Print Spooler service' '' "$(if ($spooler) { "$($spooler.Status) / $($spooler.StartType)" } else { 'not installed' })"
Write-Host ''

Write-Separator
Write-Host "  $($PointAndPrintKey -replace '^HKLM:', 'HKLM')"
Write-Host ''
Write-Check $(if ($nonAdminsCanInstall) { '!' } else { 'OK' }) `
    'RestrictDriverInstallationToAdministrators' (Show-Value $restrictToAdmins) `
    $(if ($nonAdminsCanInstall) { '(= non-admins can install)' } else { '(= admins only, secure)' })
Write-Check $(if ($restrictedDisabled) { '!' } else { 'OK' }) `
    'Restricted' (Show-Value $restricted) `
    $(if ($restrictedDisabled) { '(= policy disabled, no prompt)' } else { '(secure)' })
Write-Check $(if ($noWarnDisabled) { '!' } else { 'OK' }) `
    'NoWarningNoElevationOnInstall' (Show-Value $noWarnOnInstall) `
    $(if ($noWarnDisabled) { '(= no prompt)' } else { '(secure)' })
Write-Check $(if ($updateDisabled) { '!' } else { 'OK' }) `
    'UpdatePromptSettings' (Show-Value $updatePrompt) `
    $(if ($updateDisabled) { '(= no prompt)' } else { '(secure)' })
Write-Host ''

# Package Point and Print settings only matter once non-admins are allowed to install.
Write-Separator
Write-Host "  $($PackagePointAndPrintKey -replace '^HKLM:', 'HKLM')"
Write-Host ''
Write-Check '-' 'PackagePointAndPrintOnly' (Show-Value $packageOnly) ''
$listMarker = if ($nonAdminsCanInstall -and -not $serverListEnforced) { '!' } else { '-' }
Write-Check $listMarker 'PackagePointAndPrintServerList' (Show-Value $serverListOn) `
    $(if ($listMarker -eq '!') { '(no approved-server limit)' } else { '' })
Write-Check '-' 'ListofServers (subkey)' "$($approvedServers.Count) server(s)" ''
foreach ($srv in $approvedServers) { Write-Host "        - $srv" }
Write-Host ''

# ------------------------------------------------------------------------------------

Write-Separator
switch ($case) {
    'SECURE' {
        Write-Host '  VERDICT: SECURE - driver installation restricted to administrators.' -ForegroundColor Green
    }
    'CASE1' {
        Write-Host '  VERDICT: VULNERABLE - case 1 (CVE-2021-34527 "PrintNightmare").' -ForegroundColor Red
        Write-Host '           Non-admins can install drivers and security prompts are disabled.' -ForegroundColor Red
    }
    'CASE2' {
        Write-Host '  VERDICT: VULNERABLE - case 2 (Bring Your Own Vulnerable Driver).' -ForegroundColor Red
        Write-Host '           Non-admins can install drivers from any print server.' -ForegroundColor Red
    }
    'CASE3' {
        Write-Host '  VERDICT: RESIDUAL RISK - case 3 (approved-server spoofing).' -ForegroundColor Yellow
        Write-Host '           Bypassable by spoofing an approved server name (DNS spoofing / MITM).' -ForegroundColor Yellow
    }
}

# A vulnerable config is only exploitable while the spooler can run.
if ($case -ne 'SECURE' -and $spoolerDisabled) {
    Write-Host '           Spooler is disabled: unsafe, but not exploitable as is.' -ForegroundColor Yellow
}
elseif ($case -ne 'SECURE' -and -not $spoolerRunning) {
    Write-Host '           Spooler is stopped but not disabled: it may start again.' -ForegroundColor Yellow
}

if ($case -ne 'SECURE') {
    Write-Host ''
    Write-Host '  FIX: set "Limits print driver installation to Administrators" = Enabled,' -ForegroundColor Cyan
    Write-Host '       keep the security prompts on, and pre-deploy required drivers.' -ForegroundColor Cyan
}
Write-Host ''