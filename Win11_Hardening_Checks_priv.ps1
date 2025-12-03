<#
    Windows 11 Hardening Check Script
    This script is read only and does not change any settings.
    Run from an elevated PowerShell session.
#>

$ErrorActionPreference = "SilentlyContinue"

# Helper to collect results
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,   # PASS, FAIL, INFO, MANUAL, UNKNOWN
        [string]$Details
    )
    $results.Add([pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Details = $Details
    })
}

Write-Host "Running hardening checks on this system..."
Write-Host ""

# 1. VBS and HVCI
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"

    $vbsStatus = $dg.VirtualizationBasedSecurityStatus       # 0 off, 1 on, 2 on and locked
    $vbsOn = $vbsStatus -in 1,2

    # 1 means Credential Guard, 2 means HVCI
    $hvciRunning = $dg.SecurityServicesRunning -contains 2

    if ($vbsOn -and $hvciRunning) {
        Add-Result "VBS and HVCI" "PASS" "Virtualization Based Security status $vbsStatus and HVCI service running."
    }
    else {
        Add-Result "VBS and HVCI" "FAIL" ("VBS status {0}, HVCI running: {1}" -f $vbsStatus, ($hvciRunning))
    }
}
catch {
    Add-Result "VBS and HVCI" "UNKNOWN" "Could not query Win32_DeviceGuard. Possibly not supported on this system."
}

# 2. Credential Guard
try {
    if (-not $dg) {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"
    }

    $cgRunning = $dg.SecurityServicesRunning -contains 1
    if ($cgRunning) {
        Add-Result "Credential Guard" "PASS" "Credential Guard is reported as running by Device Guard."
    }
    else {
        Add-Result "Credential Guard" "FAIL" "Credential Guard is not reported as running."
    }
}
catch {
    Add-Result "Credential Guard" "UNKNOWN" "Could not query Credential Guard status."
}

# 3. BitLocker on system drive
try {
    $blv = Get-BitLockerVolume
    $osVol = $blv | Where-Object { $_.VolumeType -eq "OperatingSystem" }

    if ($osVol -and $osVol.ProtectionStatus -eq "On") {
        Add-Result "BitLocker OS volume" "PASS" "BitLocker protection is On for operating system volume $($osVol.MountPoint)."
    }
    else {
        Add-Result "BitLocker OS volume" "FAIL" "BitLocker is not protecting the operating system volume or could not be detected."
    }
}
catch {
    Add-Result "BitLocker OS volume" "UNKNOWN" "Get-BitLockerVolume failed. BitLocker may not be installed or PowerShell BitLocker module not available."
}

# 4. LSA protection
try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lsa = Get-ItemProperty -Path $lsaKey -Name "RunAsPPL" -ErrorAction Stop
    $runAsPPL = $lsa.RunAsPPL

    if ($runAsPPL -in 1,2) {
        Add-Result "LSA protection" "PASS" "RunAsPPL value $runAsPPL indicates LSA protection is enabled."
    }
    else {
        Add-Result "LSA protection" "FAIL" "RunAsPPL value is $runAsPPL which does not indicate LSA protection."
    }
}
catch {
    Add-Result "LSA protection" "FAIL" "RunAsPPL registry value not found or not accessible."
}

# 5. No saved credentials (cmdkey)
try {
    $cmdkeyOutput = cmdkey /list 2>$null

    if (-not $cmdkeyOutput) {
        Add-Result "Saved credentials (cmdkey)" "UNKNOWN" "cmdkey did not return any output."
    }
    else {
        # Simple heuristic: if we see lines with 'Target' then there are saved credentials
        $hasTargets = $cmdkeyOutput -match "Target"
        $nonePattern = $cmdkeyOutput -match "None" -or $cmdkeyOutput -match "no stored credentials"

        if (-not $hasTargets -or $nonePattern) {
            Add-Result "Saved credentials (cmdkey)" "PASS" "No stored credentials were found by cmdkey."
        }
        else {
            $targets = ($cmdkeyOutput | Select-String "Target").Line -join "; "
            Add-Result "Saved credentials (cmdkey)" "FAIL" ("Stored credentials detected. Targets: {0}" -f $targets)
        }
    }
}
catch {
    Add-Result "Saved credentials (cmdkey)" "UNKNOWN" "Could not run cmdkey or parse the output."
}

# 6. AppLocker or WDAC
$applockerActive = $false
$wdacActive = $false

# AppLocker check
try {
    $applockerPolicy = Get-AppLockerPolicy -Effective
    if ($applockerPolicy -and $applockerPolicy.RuleCollections) {
        $hasRules = $false
        foreach ($rc in $applockerPolicy.RuleCollections) {
            if ($rc.Rules.Count -gt 0) {
                $hasRules = $true
                break
            }
        }
        if ($hasRules) {
            $applockerActive = $true
        }
    }
}
catch {
    # AppLocker may not be configured or available
}

# WDAC check through CodeIntegrity policy registry
try {
    $ciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
    if (Test-Path $ciKey) {
        $ciProps = Get-ItemProperty -Path $ciKey
        # If any policy id exists, treat as active
        $policyProps = $ciProps.PSObject.Properties | Where-Object { $_.Name -like "*PolicyId*" -and $_.Value }
        if ($policyProps) {
            $wdacActive = $true
        }
    }
}
catch {
}

if ($applockerActive -or $wdacActive) {
    $details = @()
    if ($applockerActive) { $details += "AppLocker rules present" }
    if ($wdacActive) { $details += "Code Integrity policy present" }
    Add-Result "Application control (AppLocker or WDAC)" "PASS" ($details -join "; ")
}
else {
    Add-Result "Application control (AppLocker or WDAC)" "FAIL" "No effective AppLocker rules or WDAC Code Integrity policy detected."
}

# 7. ASR rules
try {
    $mpPref = Get-MpPreference
    if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Actions) {
        # Actions: 0 disabled, 1 block, 2 audit, 6 warn but allow, etc
        $activeRules = @()
        for ($i = 0; $i -lt $mpPref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $id = $mpPref.AttackSurfaceReductionRules_Ids[$i]
            $action = $mpPref.AttackSurfaceReductionRules_Actions[$i]
            if ($action -in 1,6) {
                $activeRules += "$id (action $action)"
            }
        }

        if ($activeRules.Count -gt 0) {
            Add-Result "ASR rules" "PASS" ("ASR rules with block or warn actions: {0}" -f ($activeRules -join "; "))
        }
        else {
            Add-Result "ASR rules" "FAIL" "No ASR rules in block or warn actions detected."
        }
    }
    else {
        Add-Result "ASR rules" "FAIL" "Get-MpPreference did not return ASR configuration or Defender is not active."
    }
}
catch {
    Add-Result "ASR rules" "UNKNOWN" "Could not query ASR rules. Defender may not be present or access is restricted."
}

# 8. Unquoted service paths
try {
    $services = Get-CimInstance Win32_Service |
        Where-Object {
            $_.PathName -and
            $_.PathName.Contains(" ") -and
            -not $_.PathName.Trim().StartsWith('"')
        }

    if (-not $services -or $services.Count -eq 0) {
        Add-Result "Service paths (unquoted)" "PASS" "No unquoted service paths with spaces detected."
    }
    else {
        $list = $services | Select-Object Name, DisplayName, PathName
        $summary = ($list | ForEach-Object { "$($_.Name) -> $($_.PathName)" }) -join "; "
        Add-Result "Service paths (unquoted)" "FAIL" ("Unquoted service paths detected: {0}" -f $summary)
    }
}
catch {
    Add-Result "Service paths (unquoted)" "UNKNOWN" "Could not enumerate services or their paths."
}

# 9. CrowdStrike and Guardicore enforcing
try {
    $csServices = Get-Service | Where-Object {
        $_.DisplayName -match "CrowdStrike|Falcon" -or
        $_.Name -match "CSAgent|CrowdStrike"
    }

    if ($csServices -and ($csServices.Status -contains "Running")) {
        $csNames = ($csServices | Where-Object Status -eq "Running").DisplayName -join ", "
        Add-Result "CrowdStrike enforcement" "PASS" ("Running services: {0}" -f $csNames)
    }
    else {
        Add-Result "CrowdStrike enforcement" "FAIL" "CrowdStrike service not found or not running."
    }

    $gcServices = Get-Service | Where-Object {
        $_.DisplayName -match "Guardicore" -or
        $_.Name -match "Guardicore"
    }

    if ($gcServices -and ($gcServices.Status -contains "Running")) {
        $gcNames = ($gcServices | Where-Object Status -eq "Running").DisplayName -join ", "
        Add-Result "Guardicore enforcement" "PASS" ("Running services: {0}" -f $gcNames)
    }
    else {
        Add-Result "Guardicore enforcement" "FAIL" "Guardicore service not found or not running."
    }
}
catch {
    Add-Result "CrowdStrike and Guardicore enforcement" "UNKNOWN" "Could not enumerate services to confirm EDR status."
}

# 10. Local users minimal
try {
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled }
    $systemUsers = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")
    $nonSystemEnabled = $localUsers | Where-Object { $systemUsers -notcontains $_.Name }

    if ($nonSystemEnabled.Count -le 2) {
        Add-Result "Local users minimal" "PASS" ("Enabled non system local accounts: {0}" -f ($nonSystemEnabled.Name -join ", "))
    }
    else {
        Add-Result "Local users minimal" "FAIL" ("Too many enabled non system local accounts: {0}" -f ($nonSystemEnabled.Name -join ", "))
    }
}
catch {
    Add-Result "Local users minimal" "UNKNOWN" "Could not query local users."
}

# 11. Installed software (manual review)
try {
    $apps = @()

    # Modern uninstallation registry locations
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            $apps += Get-ItemProperty $p | Where-Object { $_.DisplayName } |
                     Select-Object DisplayName, DisplayVersion, Publisher
        }
    }

    $appSummary = ($apps | Sort-Object DisplayName | Select-Object -First 50 | ForEach-Object { "$($_.DisplayName) ($($_.DisplayVersion))" }) -join "; "

    Add-Result "Installed software inventory" "MANUAL" ("First fifty entries: {0}. Full review required for unnecessary software." -f $appSummary)
}
catch {
    Add-Result "Installed software inventory" "UNKNOWN" "Could not enumerate installed software."
}

# 12. Listening ports
try {
    $listeners = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess -Unique

    $listenerCount = $listeners.Count
    $listenerSummary = ($listeners | Select-Object -First 30 | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) (PID $($_.OwningProcess))" }) -join "; "

    Add-Result "Listening ports" "MANUAL" ("Total listening entries: {0}. First thirty: {1}. Manual review required to decide if only essential services are listening." -f $listenerCount, $listenerSummary)
}
catch {
    Add-Result "Listening ports" "UNKNOWN" "Could not query listening ports."
}

# Write results to text file
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path -Path (Get-Location) -ChildPath ("Win11_Hardening_Report_{0}.txt" -f $timestamp)

$header = @()
$header += "Windows 11 Hardening Check Report"
$header += "Generated on: $(Get-Date)"
$header += "Computer name: $env:COMPUTERNAME"
$header += "User: $env:USERNAME"
$header += ""

$body = $results | Sort-Object Check | Format-Table -AutoSize | Out-String

$footer = @()
$footer += ""
$footer += "Status legend:"
$footer += "PASS   requirement appears to be satisfied."
$footer += "FAIL   requirement appears not satisfied."
$footer += "MANUAL requires manual interpretation."
$footer += "INFO   informational only."
$footer += "UNKNOWN could not be determined by this script."

$reportText = ($header -join [Environment]::NewLine) + $body + ($footer -join [Environment]::NewLine)

$reportText | Out-File -FilePath $outFile -Encoding UTF8

Write-Host ""
Write-Host "Report written to: $outFile"
