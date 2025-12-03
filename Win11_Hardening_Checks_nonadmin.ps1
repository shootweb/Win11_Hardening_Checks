<#
 Non admin security posture checklist

 It will:
   • Run everything that works for a standard user
   • Automatically skip checks that are better done with admin rights
   • Write a txt report in the current directory
#>

# Helper: are we running as admin?
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$results = @()

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details
    )

    $results += [pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Details = $Details
    }
}

############################################################
# VBS, HVCI, Credential Guard
############################################################

try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    $vbsRunning = $dg.VirtualizationBasedSecurityStatus -eq 2
    $hvciOn     = $dg.SecurityServicesRunning -contains 2
    $cgOn       = $dg.SecurityServicesRunning -contains 1

    Add-Result "VBS enabled" `
        ($(if ($vbsRunning) { "PASS" } else { "FAIL" })) `
        ("VirtualizationBasedSecurityStatus = {0}" -f $dg.VirtualizationBasedSecurityStatus)

    Add-Result "HVCI enabled" `
        ($(if ($hvciOn) { "PASS" } else { "FAIL" })) `
        ("SecurityServicesRunning = {0}" -f ($dg.SecurityServicesRunning -join ","))

    Add-Result "Credential Guard enabled" `
        ($(if ($cgOn) { "PASS" } else { "FAIL" })) `
        ("SecurityServicesRunning = {0}" -f ($dg.SecurityServicesRunning -join ","))

}
catch {
    Add-Result "VBS, HVCI, Credential Guard" "UNKNOWN" `
        ("Could not query Win32_DeviceGuard: {0}" -f $_.Exception.Message)
}

############################################################
# BitLocker (admin friendly, skipped for non admin)
############################################################

if (-not $IsAdmin) {
    Add-Result "BitLocker OS volume" "SKIPPED" `
        "Admin rights recommended to query BitLocker status reliably"
}
else {
    try {
        $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $protected = ($blv.ProtectionStatus -eq "On" -or $blv.ProtectionStatus -eq 1)

        Add-Result "BitLocker OS volume" `
            ($(if ($protected) { "PASS" } else { "FAIL" })) `
            ("ProtectionStatus = {0}" -f $blv.ProtectionStatus)
    }
    catch {
        Add-Result "BitLocker OS volume" "UNKNOWN" `
            ("Error querying BitLocker: {0}" -f $_.Exception.Message)
    }
}

############################################################
# LSA protection
############################################################

try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $props  = Get-ItemProperty -Path $lsaKey -ErrorAction Stop

    $runAsPpl     = $props.RunAsPPL
    $runAsPplBoot = $props.RunAsPPLBoot
    $lsaProtected = ($runAsPpl -ge 1) -or ($runAsPplBoot -ge 1)

    $details = "RunAsPPL={0} RunAsPPLBoot={1}" -f $runAsPpl, $runAsPplBoot

    Add-Result "LSA protection" `
        ($(if ($lsaProtected) { "PASS" } else { "FAIL" })) `
        $details
}
catch {
    Add-Result "LSA protection" "UNKNOWN" `
        ("Error reading LSA registry: {0}" -f $_.Exception.Message)
}

############################################################
# No saved credentials (cmdkey)
############################################################

try {
    $cmdkeyOutput = cmdkey /list 2>&1
    $targetLines  = $cmdkeyOutput | Where-Object { $_ -match "^\s*Target:" }

    if (-not $targetLines) {
        Add-Result "No saved credentials (cmdkey)" "PASS" `
            "No cmdkey stored targets found"
    }
    else {
        Add-Result "No saved credentials (cmdkey)" "FAIL" `
            ("Found stored credentials:`n{0}" -f ($targetLines -join "`n"))
    }
}
catch {
    Add-Result "No saved credentials (cmdkey)" "UNKNOWN" `
        ("Error running cmdkey: {0}" -f $_.Exception.Message)
}

############################################################
# AppLocker or WDAC (skipped for non admin)
############################################################

if (-not $IsAdmin) {
    Add-Result "AppLocker or WDAC" "SKIPPED" `
        "Admin rights recommended to query effective AppLocker or WDAC policy"
}
else {
    try {
        $wdacFiles = Get-ChildItem -Path "C:\Windows\System32\CodeIntegrity" `
            -Include "*.cip","CiPoliciesActive*" -File -ErrorAction SilentlyContinue

        $appLocker = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

        $hasPolicy = $wdacFiles -or $appLocker

        $detail = @()
        if ($wdacFiles) { $detail += "WDAC policy files present" }
        if ($appLocker) { $detail += "AppLocker effective policy returned" }
        if (-not $detail) { $detail = "No WDAC or AppLocker policy detected" }

        Add-Result "AppLocker or WDAC" `
            ($(if ($hasPolicy) { "PASS" } else { "FAIL" })) `
            ($detail -join "; ")
    }
    catch {
        Add-Result "AppLocker or WDAC" "UNKNOWN" `
            ("Error checking AppLocker or WDAC: {0}" -f $_.Exception.Message)
    }
}

############################################################
# ASR rules (Defender) skipped for non admin
############################################################

if (-not $IsAdmin) {
    Add-Result "ASR rules" "SKIPPED" `
        "Admin rights recommended to query Defender ASR configuration"
}
else {
    try {
        $mp = Get-MpPreference

        $asrIds     = $mp.AttackSurfaceReductionRules_Ids
        $asrActions = $mp.AttackSurfaceReductionRules_Actions

        if ($asrIds) {
            $enabled = @()
            for ($i = 0; $i -lt $asrIds.Count; $i++) {
                # 1 is usually block
                if ($asrActions[$i] -eq 1) {
                    $enabled += $asrIds[$i]
                }
            }

            if ($enabled.Count -gt 0) {
                Add-Result "ASR rules" "PASS" `
                    ("Enabled rule ids: {0}" -f ($enabled -join ","))
            }
            else {
                Add-Result "ASR rules" "FAIL" `
                    "No ASR rules in block mode"
            }
        }
        else {
            Add-Result "ASR rules" "FAIL" `
                "No ASR rules configured"
        }
    }
    catch {
        Add-Result "ASR rules" "UNKNOWN" `
            ("Error reading Defender preferences: {0}" -f $_.Exception.Message)
    }
}

############################################################
# Writable service paths (marked as admin style check)
############################################################

if (-not $IsAdmin) {
    Add-Result "No writable service paths" "SKIPPED" `
        "Service path writeability check is best done with admin rights"
}
else {
    try {
        # Very quick heuristic, not a full audit
        $writable = @()

        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($svc in $services) {
            if (-not $svc.PathName) { continue }

            $exePath = $svc.PathName.Trim('"')
            $exePath = $exePath.Split(" ")[0]

            if (-not (Test-Path $exePath)) { continue }

            $dir = Split-Path $exePath -Parent
            try {
                $acl = Get-Acl $dir
            }
            catch {
                continue
            }

            $badAce = $acl.Access | Where-Object {
                ($_.FileSystemRights.ToString() -match "Write" -or $_.FileSystemRights.ToString() -match "Modify") -and
                ($_.IdentityReference -match "Everyone" -or
                 $_.IdentityReference -match "Users" -or
                 $_.IdentityReference -match "Authenticated Users")
            }

            if ($badAce) {
                $writable += $svc.Name
            }
        }

        if ($writable.Count -eq 0) {
            Add-Result "No writable service paths" "PASS" `
                "No obviously writable service directories for low privileged users (heuristic)"
        }
        else {
            Add-Result "No writable service paths" "FAIL" `
                ("Potentially writable service dirs for low privilege: {0}" -f ($writable -join ","))
        }
    }
    catch {
        Add-Result "No writable service paths" "UNKNOWN" `
            ("Error while checking service paths: {0}" -f $_.Exception.Message)
    }
}

############################################################
# CrowdStrike and Guardicore enforcing
############################################################

try {
    $csSvc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "CSFalcon" -or $_.DisplayName -match "CrowdStrike"
    }

    $gcSvc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "Guardicore" -or $_.Name -match "Guardicore"
    }

    $csOn = $csSvc -and ($csSvc.Status -eq "Running")
    $gcOn = $gcSvc -and ($gcSvc.Status -eq "Running")

    $detail = @()
    if ($csSvc) { $detail += "CrowdStrike: {0} ({1})" -f $csSvc.Status, $csSvc.Name }
    else       { $detail += "CrowdStrike service not found" }

    if ($gcSvc) { $detail += "Guardicore: {0} ({1})" -f $gcSvc.Status, $gcSvc.Name }
    else        { $detail += "Guardicore service not found" }

    $bothOn = $csOn -and $gcOn

    Add-Result "CrowdStrike and Guardicore enforcing" `
        ($(if ($bothOn) { "PASS" } else { "FAIL" })) `
        ($detail -join " ; ")
}
catch {
    Add-Result "CrowdStrike and Guardicore enforcing" "UNKNOWN" `
        ("Error checking EDR services: {0}" -f $_.Exception.Message)
}

############################################################
# Local users minimal
############################################################

try {
    $enabledUsers = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -eq $true }
    $names        = $enabledUsers.Name -join ", "

    Add-Result "Local users minimal" "INFO" `
        ("Enabled local users count = {0} ({1}) - manual review" -f $enabledUsers.Count, $names)
}
catch {
    Add-Result "Local users minimal" "UNKNOWN" `
        ("Error listing local users: {0}" -f $_.Exception.Message)
}

############################################################
# No unnecessary software
############################################################

try {
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $apps = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName -Unique

    Add-Result "No unnecessary software" "INFO" `
        ("Installed products count = {0} - manual review required" -f $apps.Count)
}
catch {
    Add-Result "No unnecessary software" "UNKNOWN" `
        ("Error enumerating installed software: {0}" -f $_.Exception.Message)
}

############################################################
# No listening ports besides essential services
############################################################

try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop

    $loopbackOnly = $listeners | Where-Object {
        $_.LocalAddress -in @("127.0.0.1", "::1")
    }

    $nonLoopback = $listeners | Where-Object {
        $_.LocalAddress -notin @("127.0.0.1", "::1")
    }

    if (-not $nonLoopback) {
        Add-Result "Listening ports limited" "PASS" `
            ("Only loopback listeners present: count = {0}" -f $loopbackOnly.Count)
    }
    else {
        $detail = $nonLoopback | Select-Object LocalAddress,LocalPort,OwningProcess |
            Format-Table -AutoSize | Out-String

        Add-Result "Listening ports limited" "FAIL" `
            ("Non loopback listeners present:`n{0}" -f $detail.Trim())
    }
}
catch {
    Add-Result "Listening ports limited" "UNKNOWN" `
        ("Error querying listening ports: {0}" -f $_.Exception.Message)
}

############################################################
# Write report
############################################################

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outPath   = Join-Path -Path (Get-Location) -ChildPath ("Win11_SecurityChecklist_nonAdmin_{0}.txt" -f $timestamp)

$lines = $results | ForEach-Object {
    "{0}: {1} - {2}" -f $_.Check, $_.Status, $_.Details
}

$lines | Out-File -FilePath $outPath -Encoding UTF8

Write-Host ""
Write-Host "Checklist finished."
Write-Host "Admin mode: $IsAdmin"
Write-Host "Report written to: $outPath"
