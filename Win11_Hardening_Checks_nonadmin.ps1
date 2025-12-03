<# 
  check_win11_hardening_nonadmin.ps1

  Non admin hardening checks for Windows 11.
  It will automatically skip checks that require elevation.
#>

param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\win11_hardening_nonadmin_results.txt"
)

# Helper to track results
$results = @()

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,   # PASS, FAIL, SKIPPED, UNKNOWN, INFO
        [string]$Details
    )

    $obj = [pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Details = $Details
    }
    $script:results += $obj
    $line = "[{0}] {1}: {2}" -f $Status, $Name, $Details
    Write-Output $line
}

# Detect privilege level
try {
    $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal        = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin          = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

Add-Result -Name "Privilege level" -Status "INFO" -Details ($(if ($isAdmin) { "Running with admin rights" } else { "Running as standard user" }))

########## Checks ##########

function Test-VbsHvci {
    $name = "VBS and HVCI"
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction Stop

        $vbsOn          = ($dg.VirtualizationBasedSecurityStatus -eq 2)
        $hvciConfigured = ($dg.SecurityServicesConfigured -contains 1)
        $hvciRunning    = ($dg.SecurityServicesRunning   -contains 1)

        if ($vbsOn -and $hvciConfigured -and $hvciRunning) {
            Add-Result $name "PASS" "VBS and HVCI appear to be enabled"
        } else {
            Add-Result $name "FAIL" ("VBSOn={0} HVCIConfigured={1} HVCIRunning={2}" -f $vbsOn, $hvciConfigured, $hvciRunning)
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not query DeviceGuard: $($_.Exception.Message)"
    }
}

function Test-CredentialGuard {
    $name = "Credential Guard"
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction Stop

        $cgConfigured = ($dg.SecurityServicesConfigured -contains 2)
        $cgRunning    = ($dg.SecurityServicesRunning   -contains 2)

        if ($cgConfigured -and $cgRunning) {
            Add-Result $name "PASS" "Credential Guard appears to be enabled and running"
        } else {
            Add-Result $name "FAIL" ("Configured={0} Running={1}" -f $cgConfigured, $cgRunning)
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not query DeviceGuard: $($_.Exception.Message)"
    }
}

function Test-BitLocker {
    $name = "BitLocker OS drive"
    try {
        # This often needs admin, so be graceful
        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($null -ne $vol -and $vol.VolumeStatus -eq "FullyEncrypted") {
            Add-Result $name "PASS" "C drive fully encrypted"
        } else {
            Add-Result $name "FAIL" ("BitLocker status for C drive is {0}" -f $vol.VolumeStatus)
        }
    } catch {
        Add-Result $name "SKIPPED" "BitLocker check requires admin rights or BitLocker module not available: $($_.Exception.Message)"
    }
}

function Test-LsaProtection {
    $name = "LSA protection (RunAsPPL)"
    try {
        $lsaKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $val = Get-ItemProperty -Path $lsaKeyPath -Name "RunAsPPL" -ErrorAction Stop | Select-Object -ExpandProperty RunAsPPL
        if ($val -eq 1 -or $val -eq 2) {
            Add-Result $name "PASS" "LSA protection enabled (RunAsPPL=$val)"
        } else {
            Add-Result $name "FAIL" "RunAsPPL value is $val"
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not read LSA registry value: $($_.Exception.Message)"
    }
}

function Test-NoSavedCreds {
    $name = "Saved credentials (cmdkey)"
    try {
        $output = cmdkey /list 2>&1
        # On a fresh system, cmdkey still prints some built in targets
        $saved = $output | Where-Object { $_ -match "Target:" }

        if ($saved.Count -gt 0) {
            Add-Result $name "FAIL" ("Found saved credentials: {0}" -f ($saved -join " | "))
        } else {
            Add-Result $name "PASS" "No saved credentials listed for this user"
        }
    } catch {
        Add-Result $name "UNKNOWN" "Error running cmdkey: $($_.Exception.Message)"
    }
}

function Test-AppLockerWdac {
    $name = "AppLocker or WDAC"
    try {
        # Best effort for AppLocker policies
        $applockerKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
        if (Test-Path $applockerKey) {
            Add-Result $name "PASS" "AppLocker policy key present"
            return
        }

        # Best effort for WDAC (CodeIntegrity)
        $ciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
        if (Test-Path $ciKey) {
            Add-Result $name "PASS" "WDAC Code Integrity policy key present"
            return
        }

        Add-Result $name "FAIL" "No obvious AppLocker or WDAC policy keys found"
    } catch {
        Add-Result $name "UNKNOWN" "Could not query AppLocker or WDAC registry: $($_.Exception.Message)"
    }
}

function Test-ASRRules {
    $name = "Defender ASR rules"
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids     = $pref.AttackSurfaceReductionRules_Ids
        $actions = $pref.AttackSurfaceReductionRules_Actions

        if ($ids -and $actions) {
            # 1 or 6 means enabled
            $enabledCount = 0
            for ($i = 0; $i -lt $ids.Count; $i++) {
                if ($actions[$i] -eq 1 -or $actions[$i] -eq 6) {
                    $enabledCount++
                }
            }
            if ($enabledCount -gt 0) {
                Add-Result $name "PASS" "$enabledCount ASR rules enabled"
            } else {
                Add-Result $name "FAIL" "No ASR rules appear to be enabled"
            }
        } else {
            Add-Result $name "FAIL" "No ASR rules configured"
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not read Defender preferences: $($_.Exception.Message)"
    }
}

function Test-WritableServicePaths {
    $name = "Writable service paths"
    if (-not $isAdmin) {
        Add-Result $name "SKIPPED" "Service binary ACL checks generally require admin rights"
        return
    }

    try {
        $suspect = @()
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        foreach ($s in $services) {
            if ($s.PathName -and -not $s.PathName.StartsWith('"')) {
                $suspect += $s.Name
            }
        }

        if ($suspect.Count -gt 0) {
            Add-Result $name "FAIL" ("Services with non quoted paths: {0}" -f ($suspect -join ", "))
        } else {
            Add-Result $name "PASS" "No obvious non quoted service paths found"
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not enumerate service paths: $($_.Exception.Message)"
    }
}

function Test-EDR {
    $name = "CrowdStrike and Guardicore"
    try {
        $services = Get-Service -ErrorAction Stop

        $cs = $services | Where-Object { $_.Name -like "CSAgent*" -or $_.DisplayName -like "*CrowdStrike*" }
        $gc = $services | Where-Object { $_.DisplayName -like "*Guardicore*" -or $_.Name -like "*Guardicore*" -or $_.Name -like "*Illumio*" }

        $details = @()
        if ($cs) {
            $details += ("CrowdStrike services: {0}" -f (($cs | ForEach-Object { "$($_.Name)($($_.Status))" }) -join ", "))
        } else {
            $details += "CrowdStrike service not found"
        }

        if ($gc) {
            $details += ("Guardicore services: {0}" -f (($gc | ForEach-Object { "$($_.Name)($($_.Status))" }) -join ", "))
        } else {
            $details += "Guardicore service not found"
        }

        if ($cs -and $gc -and ($cs | Where-Object Status -eq "Running") -and ($gc | Where-Object Status -eq "Running")) {
            Add-Result $name "PASS" ($details -join " | ")
        } else {
            Add-Result $name "FAIL" ($details -join " | ")
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not query EDR services: $($_.Exception.Message)"
    }
}

function Test-LocalUsersMinimal {
    $name = "Local users minimal"
    if (-not $isAdmin) {
        Add-Result $name "SKIPPED" "Local user enumeration usually needs admin or special rights"
        return
    }

    try {
        $users = Get-LocalUser -ErrorAction Stop
        $enabled = $users | Where-Object { $_.Enabled }
        Add-Result $name "INFO" ("Enabled local users count: {0}. Review manually." -f $enabled.Count)
    } catch {
        Add-Result $name "UNKNOWN" "Could not enumerate local users: $($_.Exception.Message)"
    }
}

function Test-UnnecessarySoftware {
    $name = "Unnecessary software"
    try {
        # Simple count from uninstall keys in both hives
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        $apps = @()
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $apps += Get-ItemProperty -Path "$p\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
            }
        }

        $count = $apps.Count
        Add-Result $name "INFO" ("Installed entries counted: {0}. Manual review required for bloat or risky tools." -f $count)
    } catch {
        Add-Result $name "UNKNOWN" "Could not enumerate installed software: $($_.Exception.Message)"
    }
}

function Test-ListeningPorts {
    $name = "Listening ports"
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop
        # Simple summary only, manual analysis needed
        $summary = $connections |
            Group-Object -Property LocalPort |
            Sort-Object -Property Count -Descending |
            Select-Object -First 20 |
            ForEach-Object { "Port {0} Count {1}" -f $_.Name, $_.Count }

        if ($summary.Count -eq 0) {
            Add-Result $name "PASS" "No listening TCP ports reported"
        } else {
            Add-Result $name "INFO" ("Listening ports summary: {0}" -f ($summary -join " | "))
        }
    } catch {
        Add-Result $name "UNKNOWN" "Could not query TCP listeners: $($_.Exception.Message)"
    }
}

########## Run all checks ##########

Test-VbsHvci
Test-CredentialGuard
Test-BitLocker
Test-LsaProtection
Test-NoSavedCreds
Test-AppLockerWdac
Test-ASRRules
Test-WritableServicePaths
Test-EDR
Test-LocalUsersMinimal
Test-UnnecessarySoftware
Test-ListeningPorts

########## Write output file ##########

try {
    $header = "Windows 11 hardening check run on {0}" -f (Get-Date)
    $header | Out-File -FilePath $OutputPath -Encoding UTF8

    foreach ($r in $results) {
        $line = "[{0}] {1}: {2}" -f $r.Status, $r.Check, $r.Details
        Add-Content -Path $OutputPath -Value $line
    }

    Write-Output "`nResults written to: $OutputPath"
} catch {
    Write-Output "Failed to write results to file: $($_.Exception.Message)"
}
