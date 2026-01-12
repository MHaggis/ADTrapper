<#
.SYNOPSIS
    ADTrapper Windows Authentication Log Collector
    Collects Windows Security events for threat detection and analysis.

.DESCRIPTION
    This script extracts comprehensive authentication events from Windows Security logs
    for use with the ADTrapper analytics platform. It supports:
    
    - Authentication events (logon success/failure, Kerberos, NTLM)
    - AD CS certificate events for ADCS attack detection (ESC1-ESC11)
    - SMB share access events for enumeration detection
    - Active Directory enrichment for user context
    - Raw CA database analysis for enhanced ESC1 detection (opt-in, CA servers only)

    The output is formatted for direct upload to ADTrapper's analytics engine.

.PARAMETER Hours
    Number of hours of events to collect. Default: 24

.PARAMETER OutputPath
    Path for the output file. Default: .\adtrapper_events.json

.PARAMETER Format
    Output format: 'json' or 'csv'. Default: json

.PARAMETER EnrichWithAD
    Enrich events with Active Directory user information (department, groups, etc.)

.PARAMETER ADCS
    Collect AD CS certificate events for certificate-based attack detection.

.PARAMETER RawDatabase
    CAUTION: Performs raw CA database analysis for enhanced ESC1 detection.
    This STOPS the Certificate Authority service temporarily and should only
    be used during maintenance windows on CA servers.

.PARAMETER Verbose
    Show detailed progress information.

.EXAMPLE
    .\capture.ps1
    Collect last 24 hours of authentication events.

.EXAMPLE
    .\capture.ps1 -Hours 48 -OutputPath C:\Logs\auth.json
    Collect 48 hours of events and save to a specific path.

.EXAMPLE
    .\capture.ps1 -EnrichWithAD -ADCS
    Collect auth + AD CS events with Active Directory enrichment.

.EXAMPLE
    .\capture.ps1 -ADCS -RawDatabase
    Collect AD CS events including raw database analysis (CA servers only).
    WARNING: This will temporarily stop the Certificate Authority service!

.EXAMPLE
    .\capture.ps1 -Hours 168 -Format csv
    Collect a week of events in CSV format.

.NOTES
    Author: ADTrapper Team
    Version: 2.0
    Requires: PowerShell 5.1+, Administrator privileges for Security log access
    
    For AD enrichment: Active Directory PowerShell module
    For AD CS events: Run on CA server or domain-joined machine
    For raw database analysis: Run on CA server with admin privileges

.LINK
    https://github.com/MHaggis/ADTrapper

#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Number of hours of events to collect")]
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [Parameter(HelpMessage="Output file path")]
    [string]$OutputPath = ".\adtrapper_events.json",

    [Parameter(HelpMessage="Output format: json or csv")]
    [ValidateSet("json", "csv")]
    [string]$Format = "json",

    [Parameter(HelpMessage="Enrich events with Active Directory data")]
    [switch]$EnrichWithAD,

    [Parameter(HelpMessage="Collect AD CS certificate events")]
    [switch]$ADCS,

    [Parameter(HelpMessage="CAUTION: Perform raw CA database analysis (stops CA service!)")]
    [switch]$RawDatabase,

    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Script configuration
$Script:Version = "2.0"
$Script:RawDatabaseAnalysis = $false

# Known VPN/Proxy providers for risk scoring (expandable)
$Script:VPNProviders = @(
    'mullvad', 'protonvpn', 'expressvpn', 'nordvpn', 'pia', 'surfshark', 
    'ipvanish', 'cyberghost', 'privatevpn', 'purevpn', 'windscribe',
    'hotspotshield', 'tunnelbear', 'zenmate', 'hide.me', 'strongvpn',
    'torguard', 'airvpn', 'ivpn', 'perfect-privacy', 'ovpn'
)

# Event IDs to monitor
$AuthEventIDs = @(4624, 4625, 4634, 4647, 4648, 4740, 4742, 4768, 4769, 4771, 4776, 4778, 4779, 5140, 5145)

# AD CS Event IDs
$ADCSEventIDs = @{
    # Certificate Services events (logged in specialized logs)
}

# Logon type mappings
$LogonTypes = @{
    2 = "Interactive"
    3 = "Network" 
    4 = "Batch"
    5 = "Service"
    7 = "Unlock"
    8 = "NetworkCleartext"
    9 = "NewCredentials"
    10 = "RemoteInteractive"
    11 = "CachedInteractive"
}

function Show-Banner {
    $Banner = @"

    _    ____ _____                                
   / \  |  _ \_   _| __ __ _ _ __  _ __   ___ _ __ 
  / _ \ | | | || || '__/ _` | '_ \| '_ \ / _ \ '__|
 / ___ \| |_| || || | | (_| | |_) | |_) |  __/ |   
/_/   \_\____/ |_||_|  \__,_| .__/| .__/ \___|_|   
                            |_|   |_|              
    Windows Authentication Log Collector v$($Script:Version)
"@
    Write-Host $Banner -ForegroundColor Red
    Write-Host "=" * 60 -ForegroundColor Yellow
    Write-Host ""
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-EventLogs {
    Write-Host "Checking available event logs..." -ForegroundColor Cyan
    try {
        $Logs = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | Select-Object LogName, RecordCount | Sort-Object RecordCount -Descending
        Write-Host "Available logs with events:" -ForegroundColor Green
        $Logs | Select-Object -First 15 | ForEach-Object {
            Write-Host "  $($_.LogName): $($_.RecordCount) events" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Could not enumerate event logs: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-RawDatabaseAccess {
    Write-Host "`nChecking ADCS raw database access for enhanced ESC1 detection..." -ForegroundColor Cyan

    try {
        $IsCAServer = $false

        # Check Windows Feature
        Write-Host "  Checking Windows Features..." -ForegroundColor Gray
        $CARole = Get-WindowsFeature -Name AD-Certificate -ErrorAction SilentlyContinue
        if ($CARole.InstallState -eq "Installed") {
            Write-Host "  [OK] AD Certificate Services role is installed" -ForegroundColor Green
            $IsCAServer = $true
        } else {
            Write-Host "  [INFO] AD Certificate Services role not detected via Windows Features" -ForegroundColor Yellow
        }

        # Check CA configuration registry
        Write-Host "  Checking CA registry configuration..." -ForegroundColor Gray
        $CAConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "Active" -ErrorAction SilentlyContinue
        if ($CAConfig) {
            Write-Host "  [OK] CA configuration found in registry: $($CAConfig.Active)" -ForegroundColor Green
            $IsCAServer = $true
        } else {
            Write-Host "  [INFO] CA configuration not found in registry" -ForegroundColor Yellow
        }

        # Check for CA database files
        Write-Host "  Checking for CA database files..." -ForegroundColor Gray
        $CADatabasePath = "$env:windir\System32\CertLog"
        if (Test-Path $CADatabasePath) {
            $DatabaseFiles = Get-ChildItem -Path $CADatabasePath -Filter "*.edb" -ErrorAction SilentlyContinue
            if ($DatabaseFiles) {
                Write-Host "  [OK] CA database files found: $($DatabaseFiles.Count) database file(s)" -ForegroundColor Green
                $IsCAServer = $true
            } else {
                Write-Host "  [INFO] CA database directory exists but no .edb files found" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [INFO] CA database directory not found: $CADatabasePath" -ForegroundColor Yellow
        }

        if (-not $IsCAServer) {
            Write-Host "  [INFO] This server does not appear to be a Certificate Authority" -ForegroundColor Yellow
            Write-Host "  [INFO] AD CS events may still be available from client-side logs" -ForegroundColor Cyan
            return $false
        }

        # Check ADCS service
        Write-Host "  Checking ADCS service..." -ForegroundColor Gray
        $ADCSService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
        if ($ADCSService) {
            Write-Host "  [OK] ADCS service found: $($ADCSService.Status)" -ForegroundColor Green
        } else {
            Write-Host "  [WARNING] ADCS service not found" -ForegroundColor Red
            return $false
        }

        # Test certutil availability
        Write-Host "  Testing certutil command availability..." -ForegroundColor Gray
        $CertutilPath = Get-Command certutil -ErrorAction SilentlyContinue
        if ($CertutilPath) {
            Write-Host "  [OK] certutil found: $($CertutilPath.Source)" -ForegroundColor Green
        } else {
            $System32Path = "$env:windir\System32\certutil.exe"
            if (Test-Path $System32Path) {
                Write-Host "  [OK] certutil found in System32: $System32Path" -ForegroundColor Green
                $env:PATH = "$env:windir\System32;" + $env:PATH
            } else {
                Write-Host "  [ERROR] certutil not found" -ForegroundColor Red
                return $false
            }
        }

        Write-Host "  [SUCCESS] Raw ADCS database access available for ESC1 analysis" -ForegroundColor Green
        return $true

    } catch {
        Write-Host "  [ERROR] Could not test raw database access: $_" -ForegroundColor Red
        return $false
    }
}

function Confirm-RawDatabaseAnalysis {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Red
    Write-Host "  WARNING: Raw Database Analysis Requested" -ForegroundColor Red
    Write-Host "=" * 60 -ForegroundColor Red
    Write-Host ""
    Write-Host "  This operation will:" -ForegroundColor Yellow
    Write-Host "    1. STOP the Certificate Authority service (certsvc)" -ForegroundColor Yellow
    Write-Host "    2. Read the CA database directly for ESC1 indicators" -ForegroundColor Yellow
    Write-Host "    3. RESTART the Certificate Authority service" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  During this time, certificate requests will FAIL." -ForegroundColor Red
    Write-Host "  Only run this during a maintenance window!" -ForegroundColor Red
    Write-Host ""
    
    $Response = Read-Host "  Type 'YES' to proceed with raw database analysis"
    
    if ($Response -eq "YES") {
        Write-Host "  Proceeding with raw database analysis..." -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "  Raw database analysis cancelled. Continuing with event log collection only." -ForegroundColor Cyan
        return $false
    }
}

function Get-RawADCSData {
    param([int]$Hours)

    Write-Host "Collecting raw ADCS database data for ESC1 analysis..." -ForegroundColor Cyan

    $RawData = @{
        successfulRequests = @()
        deniedRequests = @()
        esc1Indicators = @()
        totalRequests = 0
    }

    try {
        $ADCSService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
        $ServiceWasRunning = $false

        if ($ADCSService.Status -eq 'Running') {
            Write-Host "  Stopping ADCS service for database access..." -ForegroundColor Yellow
            Stop-Service -Name certsvc -Force
            $ServiceWasRunning = $true
            Start-Sleep -Seconds 2
        }

        # Export successful certificate requests
        Write-Host "  Exporting successful certificate requests..." -ForegroundColor Gray
        $TempFile = "$env:TEMP\adcs_successful_requests.txt"
        certutil -db -v -restrict "Request.Disposition=20" -out all > $TempFile 2>&1

        if (Test-Path $TempFile) {
            $RawData.successfulRequests = Get-Content $TempFile -Raw
            $RawData.totalRequests += ($RawData.successfulRequests | Select-String -Pattern "Row \d+:" -AllMatches).Matches.Count
            Write-Host "    Found $($RawData.successfulRequests.Count) successful requests" -ForegroundColor Green
        }

        # Export denied certificate requests
        Write-Host "  Exporting denied certificate requests..." -ForegroundColor Gray
        $TempFileDenied = "$env:TEMP\adcs_denied_requests.txt"
        certutil -db -v -restrict "Request.Disposition=30" -out all > $TempFileDenied 2>&1

        if (Test-Path $TempFileDenied) {
            $RawData.deniedRequests = Get-Content $TempFileDenied -Raw
            Write-Host "    Found $(($RawData.deniedRequests | Select-String -Pattern "Row \d+:" -AllMatches).Matches.Count) denied requests" -ForegroundColor Yellow
        }

        # Analyze for ESC1 indicators
        Write-Host "  Analyzing for ESC1 vulnerability patterns..." -ForegroundColor Gray
        $RawData.esc1Indicators = Analyze-ESC1Patterns -RawData $RawData.successfulRequests

        # Cleanup temp files
        if (Test-Path $TempFile) { Remove-Item $TempFile -Force }
        if (Test-Path $TempFileDenied) { Remove-Item $TempFileDenied -Force }

    } catch {
        Write-Host "  [ERROR] Failed to collect raw ADCS data: $_" -ForegroundColor Red
    } finally {
        if ($ServiceWasRunning) {
            Write-Host "  Restarting ADCS service..." -ForegroundColor Yellow
            Start-Service -Name certsvc
            Write-Host "  ADCS service restarted." -ForegroundColor Green
        }
    }

    Write-Host "  Raw ADCS analysis complete: $($RawData.esc1Indicators.Count) ESC1 indicators found" -ForegroundColor Cyan
    return $RawData
}

function Analyze-ESC1Patterns {
    param([string]$RawData)

    $Indicators = @()

    if (-not $RawData) { return $Indicators }

    $Lines = $RawData -split "`n"

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $Line = $Lines[$i]

        # Look for SAN=upn= patterns (ESC1 indicator)
        if ($Line -match 'SAN=upn=([^\s]+)') {
            $UPN = $matches[1]

            $ContextStart = [Math]::Max(0, $i - 5)
            $ContextEnd = [Math]::Min($Lines.Count - 1, $i + 10)
            $Context = $Lines[$ContextStart..$ContextEnd] -join "`n"

            $Requester = "Unknown"
            if ($Context -match 'Requester:\s*([^\r\n]+)') {
                $Requester = $matches[1].Trim()
            }

            $Template = "Unknown"
            if ($Context -match 'CertificateTemplate:\s*([^\r\n]+)') {
                $Template = $matches[1].Trim()
            }

            $IsSuspicious = $false
            $RequesterUPN = $null
            if ($Requester -match '([^\\]+)@(.+)') {
                $RequesterUPN = $Requester
            }

            if ($RequesterUPN -and ($UPN -ne $RequesterUPN)) {
                $IsSuspicious = $true
            }

            $PrivilegedPatterns = @('admin', 'administrator', 'domain.admin', 'enterprise.admin', 'root', 'sa')
            $IsPrivilegedTarget = $PrivilegedPatterns | Where-Object { $UPN -match $_ }

            $Indicators += @{
                type = "SAN_UPN_Manipulation"
                upn = $UPN
                requester = $Requester
                template = $Template
                isSuspicious = $IsSuspicious
                isPrivilegedTarget = ($IsPrivilegedTarget.Count -gt 0)
                context = $Context
                lineNumber = $i
            }
        }
    }

    return $Indicators
}

function Test-ADCSLogging {
    Write-Host "`nChecking AD CS auditing configuration..." -ForegroundColor Cyan
    
    $Issues = @()
    
    try {
        $CARole = Get-WindowsFeature -Name AD-Certificate -ErrorAction SilentlyContinue
        if ($CARole.InstallState -ne "Installed") {
            Write-Host "  [INFO] This server is not a Certificate Authority" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "  [INFO] Unable to determine if this is a CA server" -ForegroundColor Yellow
    }
    
    # Check CA audit settings
    try {
        $CAName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "Active" -ErrorAction SilentlyContinue)."Active"
        if ($CAName) {
            $AuditFilterOutput = certutil -getreg "CA\AuditFilter" 2>$null
            $AuditFilterValue = $null
            
            foreach ($line in $AuditFilterOutput) {
                if ($line -match 'AuditFilter REG_DWORD = (\S+)') {
                    $AuditFilterValue = $matches[1]
                    if ($AuditFilterValue -match '0x7f|7f') {
                        $AuditFilterValue = 127
                    } elseif ($AuditFilterValue -match '\((\d+)\)') {
                        $AuditFilterValue = [int]$matches[1]
                    } else {
                        $AuditFilterValue = [int]$AuditFilterValue
                    }
                    break
                }
            }
            
            if ($AuditFilterValue -ne 127) {
                $Issues += "CA Auditing is not fully enabled (current value: $AuditFilterValue)"
                Write-Host "  [WARNING] CA Auditing is not fully enabled on $CAName (current value: $AuditFilterValue)" -ForegroundColor Red
                Write-Host "  [FIX] Run as admin: certutil -setreg CA\AuditFilter 127" -ForegroundColor Yellow
                Write-Host "  [FIX] Then restart: Restart-Service certsvc" -ForegroundColor Yellow
            } else {
                Write-Host "  [OK] CA Auditing is properly configured (value: 127)" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  [ERROR] Could not check CA audit settings: $_" -ForegroundColor Red
    }
    
    $AuditPolicyOutput = auditpol /get /subcategory:"Certification Services" 2>$null
    $CertServicesAuditEnabled = $false
    
    foreach ($line in $AuditPolicyOutput) {
        if ($line -match 'Certification Services\s+Success and Failure') {
            $CertServicesAuditEnabled = $true
            break
        }
    }
    
    if (-not $CertServicesAuditEnabled) {
        $Issues += "Certification Services auditing not enabled in Windows audit policy"
        Write-Host "  [WARNING] Certification Services auditing is not enabled" -ForegroundColor Red
        Write-Host "  [FIX] Run as admin: auditpol /set /subcategory:`"Certification Services`" /success:enable /failure:enable" -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] Certification Services auditing is enabled in audit policy" -ForegroundColor Green
    }
    
    # Check for CertificationAuthority log
    try {
        $CALog = Get-WinEvent -ListLog "Microsoft-Windows-CertificationAuthority/Operational" -ErrorAction SilentlyContinue
        if ($CALog) {
            if ($CALog.IsEnabled) {
                Write-Host "  [OK] CertificationAuthority operational log is enabled" -ForegroundColor Green
            } else {
                $Issues += "CertificationAuthority operational log is disabled"
                Write-Host "  [WARNING] CertificationAuthority operational log is disabled" -ForegroundColor Red
                Write-Host "  [FIX] Run: wevtutil sl Microsoft-Windows-CertificationAuthority/Operational /e:true" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [INFO] CertificationAuthority operational log not found (normal for non-CA servers)" -ForegroundColor Yellow
    }
    
    if ($Issues.Count -gt 0) {
        Write-Host "`n  Summary: Found $($Issues.Count) configuration issue(s) that may prevent proper AD CS event collection" -ForegroundColor Yellow
        return $true 
    } else {
        Write-Host "`n  Summary: AD CS auditing is properly configured" -ForegroundColor Green
        return $true
    }
}

function Get-ADCSEvents {
    param([int]$Hours)
    
    $StartTime = (Get-Date).AddHours(-$Hours)
    $AllEvents = @()
    
    Write-Host "Collecting AD CS events from the last $Hours hours..." -ForegroundColor Cyan

    # Check for raw database analysis capability (only if -RawDatabase flag was used)
    if ($Script:RawDatabaseAnalysis) {
        $CanDoRawAnalysis = Test-RawDatabaseAccess
        if ($CanDoRawAnalysis) {
            $RawADCSData = Get-RawADCSData -Hours $Hours
        }
    }
    
    $CanCollect = Test-ADCSLogging
    
    if (-not $CanCollect) {
        Write-Host "  Skipping AD CS event collection on non-CA server" -ForegroundColor Yellow
        return @()
    }
    
    # Collect AD CS events from specialized logs
    Write-Host "  Collecting from specialized AD CS logs..." -ForegroundColor Gray

    # Discover available AD CS event logs
    Write-Host "  Discovering available AD CS event logs..." -ForegroundColor Gray
    $ADCSLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {
        $_.LogName -like "*cert*" -or
        $_.LogName -like "*Certificate*" -or
        $_.LogName -like "*CA*" -or
        $_.LogName -like "*ADCS*"
    }

    if ($ADCSLogs) {
        Write-Host "  Found $($ADCSLogs.Count) AD CS related event logs:" -ForegroundColor Cyan
        foreach ($log in $ADCSLogs) {
            Write-Host "    - $($log.LogName): $($log.RecordCount) events" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No AD CS related event logs found" -ForegroundColor Yellow
    }

    # Try Certificate Services Client Lifecycle log
    $LifecycleEvents = @()
    try {
        Write-Host "  Checking Certificate Services Client Lifecycle log..." -ForegroundColor Gray
        $LifecycleEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($LifecycleEvents) {
            Write-Host "    Found $($LifecycleEvents.Count) events in Certificate Services Client Lifecycle log" -ForegroundColor Green
        } else {
            Write-Host "    No recent events in Certificate Services Client Lifecycle log" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Certificate Services Client Lifecycle log not available: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Collect Security log AD CS events
    Write-Host "  Collecting from Security log..." -ForegroundColor Gray
    $SecurityEvents = @()
    foreach ($EventID in $ADCSEventIDs.Keys) {
        try {
            $Events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = $EventID
                StartTime = $StartTime
            } -ErrorAction SilentlyContinue
            
            if ($Events) {
                $SecurityEvents += $Events
                Write-Host "    Found $($Events.Count) events for ID $EventID - $($ADCSEventIDs[$EventID])" -ForegroundColor Green
            }
        } catch {
            # Event ID not found is normal
        }
    }
    
    # Combine all AD CS events
    $AllADCS = @()
    if ($LifecycleEvents.Count -gt 0) {
        $AllADCS += $LifecycleEvents
    }
    if ($SecurityEvents.Count -gt 0) {
        $AllADCS += $SecurityEvents
    }

    if ($AllADCS.Count -eq 0) {
        Write-Host "    No AD CS events found in any logs" -ForegroundColor Yellow
    } else {
        Write-Host "    Total: $($AllADCS.Count) AD CS events collected" -ForegroundColor Green
        $AllEvents += $AllADCS
    }
    
    # Collect from CertificationAuthority log
    Write-Host "  Collecting from CertificationAuthority operational log..." -ForegroundColor Gray

    $CAPossibleLogs = @(
        'Microsoft-Windows-CertificationAuthority/Operational',
        'Microsoft-Windows-CertificationAuthority/Admin',
        'Microsoft-Windows-CertificationAuthority/Debug'
    )

    $CAFound = $false
    foreach ($CALogName in $CAPossibleLogs) {
        try {
            Write-Host "    Checking for CA log: $CALogName" -ForegroundColor Gray
            $LogInfo = Get-WinEvent -ListLog $CALogName -ErrorAction SilentlyContinue
            if ($LogInfo -and $LogInfo.RecordCount -gt 0) {
                Write-Host "    Found CA log: $CALogName ($($LogInfo.RecordCount) events)" -ForegroundColor Cyan
                $CAFound = $true

                try {
                    $CAEvents = Get-WinEvent -FilterHashtable @{
                        LogName = $CALogName
                        StartTime = $StartTime
                    } -ErrorAction SilentlyContinue

                    if ($CAEvents) {
                        Write-Host "      Found $($CAEvents.Count) recent events in $CALogName" -ForegroundColor Green
                        $AllEvents += $CAEvents
                    } else {
                        Write-Host "      No recent events in $CALogName" -ForegroundColor Yellow
                        try {
                            $AllCAEvents = Get-WinEvent -LogName $CALogName -ErrorAction SilentlyContinue
                            if ($AllCAEvents -and $AllCAEvents.Count -gt 0) {
                                Write-Host "      Found $($AllCAEvents.Count) total events in $CALogName (ignoring time filter)" -ForegroundColor Cyan
                                $AllEvents += $AllCAEvents
                            }
                        } catch {
                            Write-Host "      Could not read any events from $CALogName" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Host "      Could not query $CALogName : $($_.Exception.Message)" -ForegroundColor Yellow
                }
                break
            }
        } catch {
            # Log doesn't exist
        }
    }

    if (-not $CAFound) {
        Write-Host "    No CertificationAuthority logs found on this system" -ForegroundColor Yellow
    }

    # Check Certificate Services Deployment log
    try {
        Write-Host "  Checking Certificate Services Deployment log..." -ForegroundColor Gray
        $DeploymentEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-CertificateServices-Deployment/Operational'
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($DeploymentEvents) {
            Write-Host "    Found $($DeploymentEvents.Count) events in Certificate Services Deployment log" -ForegroundColor Green
            $AllEvents += $DeploymentEvents
        } else {
            Write-Host "    No recent events in Certificate Services Deployment log" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Could not access Certificate Services Deployment log" -ForegroundColor Yellow
    }

    # Check other AD CS related logs
    $OtherADCLogs = @(
        'Microsoft-Windows-CAPI2/Operational',
        'System'
    )

    foreach ($OtherLog in $OtherADCLogs) {
        try {
            $OtherLogInfo = Get-WinEvent -ListLog $OtherLog -ErrorAction SilentlyContinue
            if ($OtherLogInfo -and $OtherLogInfo.RecordCount -gt 0) {
                Write-Host "    Checking $OtherLog for AD CS events..." -ForegroundColor Gray

                try {
                    $OtherEvents = Get-WinEvent -FilterHashtable @{
                        LogName = $OtherLog
                        StartTime = $StartTime
                    } -ErrorAction SilentlyContinue

                    if ($OtherEvents -and $OtherEvents.Count -gt 0) {
                        $ADCSEvents = $OtherEvents | Where-Object {
                            $_.Message -match '(?i)(certificate|cert|template|ca|authority|adcs)' -or
                            $_.Id -in @(1001, 1003, 1007, 4886, 4887, 4888, 4898, 4899, 4900)
                        }

                        if ($ADCSEvents -and $ADCSEvents.Count -gt 0) {
                            Write-Host "      Found $($ADCSEvents.Count) AD CS related events in $OtherLog" -ForegroundColor Green
                            $AllEvents += $ADCSEvents
                        }
                    }
                } catch {
                    Write-Host "      Could not query $OtherLog" -ForegroundColor Yellow
                }
            }
        } catch {
            # Log doesn't exist
        }
    }

    # Collect certificate export events
    Write-Host "  Collecting certificate export events..." -ForegroundColor Gray
    try {
        $ExportEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-CertificateServicesClient/Certificateservicesclient-lifecycle-user'
            ID = 1007
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($ExportEvents) {
            Write-Host "    Found $($ExportEvents.Count) certificate export events" -ForegroundColor Green
            $AllEvents += $ExportEvents
        } else {
            Write-Host "    No certificate export events found" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Certificate export events not accessible" -ForegroundColor Yellow
    }
    
    # Try certutil for recent certificate activity
    Write-Host "  Checking recent certificate activity via certutil..." -ForegroundColor Gray
    try {
        $CAName = & certutil -dump 2>$null | Select-String "Name:" | Select-Object -First 1
        if ($CAName) {
            $CAName = $CAName.ToString().Split(":")[1].Trim().Trim('"')
            Write-Host "    Found CA: $CAName" -ForegroundColor Cyan

            Write-Host "    Querying recent certificate requests..." -ForegroundColor Gray
            $DateFilter = (Get-Date).AddHours(-$Hours).ToString('MM/dd/yyyy')

            try {
                $RecentRequests = & certutil -view -restrict "NotBefore>=$DateFilter" -out "RequestID,RequesterName,CertificateTemplate,NotBefore,NotAfter,Disposition" 2>$null
            } catch {
                $RecentRequests = $null
            }

            if ($RecentRequests) {
                $Lines = $RecentRequests -split "`n" | Where-Object { $_ -match '\S' }
                $SyntheticCertEvents = @()

                foreach ($line in $Lines) {
                    if ($line -match 'RequestID:\s+(\d+)') {
                        $RequestID = $matches[1]

                        $Requester = "Unknown"
                        $Template = "Unknown"

                        if ($line -match 'RequesterName:\s*"([^"]*)"') {
                            $Requester = $matches[1]
                        }
                        if ($line -match 'CertificateTemplate:\s*"([^"]*)"') {
                            $Template = $matches[1]
                        }

                        $SyntheticEvent = @{
                            id = "cert_request_$RequestID_$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
                            timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            eventId = "4886"
                            eventType = "ADCS"
                            computerName = $env:COMPUTERNAME
                            certificateTemplate = $Template
                            requester = $Requester
                            requestId = $RequestID
                            hasSubjectAltName = $false
                            riskIndicators = @("Certificate request from database")
                            description = "Certificate request found in CA database"
                            rawData = @{
                                RequestID = $RequestID
                                RequesterName = $Requester
                                CertificateTemplate = $Template
                            }
                        }
                        $SyntheticCertEvents += $SyntheticEvent
                    }
                }

                if ($SyntheticCertEvents.Count -gt 0) {
                    Write-Host "    Created $($SyntheticCertEvents.Count) synthetic certificate events" -ForegroundColor Green
                    $AllEvents += $SyntheticCertEvents
                }
            }
        }
    } catch {
        Write-Host "    Could not query certificate database" -ForegroundColor Yellow
    }

    # Check Directory Service log for AD CS events
    Write-Host "  Checking Directory Service log for AD CS events..." -ForegroundColor Gray
    try {
        $DirectoryEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Directory Service'
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($DirectoryEvents) {
            $ADCSRelatedEvents = $DirectoryEvents | Where-Object {
                $_.Id -in @(2887, 2888, 2889, 1000, 1001, 1002, 1003) -or
                $_.Message -match '(?i)(certificate|cert|template|ca|authority)'
            }

            if ($ADCSRelatedEvents -and $ADCSRelatedEvents.Count -gt 0) {
                Write-Host "    Found $($ADCSRelatedEvents.Count) AD CS related events in Directory Service log" -ForegroundColor Green
                $AllEvents += $ADCSRelatedEvents
            }
        }
    } catch {
        Write-Host "    Could not access Directory Service log" -ForegroundColor Yellow
    }

    # Add raw database ESC1 indicators as synthetic events
    if ($Script:RawDatabaseAnalysis -and $RawADCSData -and $RawADCSData.esc1Indicators -and $RawADCSData.esc1Indicators.Count -gt 0) {
        Write-Host "  Converting $($RawADCSData.esc1Indicators.Count) raw database ESC1 indicators to events..." -ForegroundColor Gray
        foreach ($Indicator in $RawADCSData.esc1Indicators) {
            $SyntheticEvent = @{
                id = "raw_adcs_esc1_$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())_$($Indicator.lineNumber)"
                timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                eventId = "4887"
                eventType = "RawADCS"
                computerName = $env:COMPUTERNAME
                requester = $Indicator.requester
                certificateTemplate = $Indicator.template
                subjectAltName = $Indicator.upn
                hasSubjectAltName = $true
                isSuspiciousUPN = $Indicator.isSuspicious
                isPrivilegedTarget = $Indicator.isPrivilegedTarget
                riskIndicators = @()
                description = "Raw ADCS database ESC1 indicator: $($Indicator.type)"
                rawData = $Indicator
            }

            if ($Indicator.isSuspicious) {
                $SyntheticEvent.riskIndicators += "UPN mismatch between requester and SAN (ESC1 pattern)"
            }
            if ($Indicator.isPrivilegedTarget) {
                $SyntheticEvent.riskIndicators += "Certificate issued for privileged account via SAN manipulation"
            }
            $SyntheticEvent.riskIndicators += "Raw database analysis detected potential ESC1"

            $AllEvents += $SyntheticEvent
        }
    }

    # Final summary
    $ADCSEventCount = ($AllEvents | Where-Object { $_.eventType -eq "ADCS" }).Count
    $RawADCSEventCount = ($AllEvents | Where-Object { $_.eventType -eq "RawADCS" }).Count
    $SyntheticEventCount = ($AllEvents | Where-Object { $_.id -like "cert_request_*" }).Count

    Write-Host "`nAD CS Collection Summary:" -ForegroundColor Magenta
    Write-Host "  Total AD CS events collected: $($ADCSEventCount + $RawADCSEventCount + $SyntheticEventCount)" -ForegroundColor Cyan
    if ($ADCSEventCount -gt 0) {
        Write-Host "  - Event log events: $ADCSEventCount" -ForegroundColor Green
    }
    if ($RawADCSEventCount -gt 0) {
        Write-Host "  - Raw database ESC1 events: $RawADCSEventCount" -ForegroundColor Green
    }
    if ($SyntheticEventCount -gt 0) {
        Write-Host "  - Synthetic certificate events: $SyntheticEventCount" -ForegroundColor Green
    }

    if ($ADCSEventCount -eq 0 -and $RawADCSEventCount -eq 0 -and $SyntheticEventCount -eq 0) {
        Write-Host "`nAD CS Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Verify CA auditing is enabled: certutil -getreg CA\\AuditFilter" -ForegroundColor Gray
        Write-Host "  2. Check event log sizes: Get-WinEvent -ListLog *cert* | Select LogName, RecordCount" -ForegroundColor Gray
        Write-Host "  3. Enable more AD CS logging in Group Policy" -ForegroundColor Gray
        Write-Host "  4. Generate some certificate activity and try again" -ForegroundColor Gray
    }

    return $AllEvents
}

function Parse-ADCSEvent {
    param($Event)
    
    # Handle synthetic RawADCS events
    if ($Event.eventType -eq "RawADCS") {
        return $Event
    }
    
    if (-not $Event) { return $null }
    if (-not $Event.RecordId) { return $null }
    
    try {
        $EventXML = [xml]$Event.ToXml()
        $EventData = @{}
        
        if ($EventXML -and $EventXML.Event -and $EventXML.Event.EventData -and $EventXML.Event.EventData.Data) {
            foreach ($Data in $EventXML.Event.EventData.Data) {
                if ($Data -and $Data.Name) {
                    $EventData[$Data.Name] = $Data.'#text'
                }
            }
        }
    } catch {
        return $null
    }
    
    $ParsedEvent = @{
        id = "adcs_event_$($Event.RecordId)_$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
        timestamp = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        eventId = $Event.Id.ToString()
        eventType = "ADCS"
        logName = $Event.LogName
        computerName = $Event.MachineName
        requester = if($EventData.SubjectName) { $EventData.SubjectName } else { $EventData.RequesterName }
        certificateTemplate = $EventData.CertificateTemplate
        certificateSerialNumber = $EventData.SerialNumber
        certificateThumbprint = $EventData.Thumbprint
        subjectAltName = $EventData.SubjectAlternativeName
        hasSubjectAltName = [bool]($EventData.SubjectAlternativeName -and $EventData.SubjectAlternativeName -ne "-")
        templateName = $EventData.TemplateName
        modifiedBy = if($EventData.SubjectUserName) { "$($EventData.SubjectDomainName)\$($EventData.SubjectUserName)" } else { $null }
        caName = $EventData.CAName
        configurationEntry = $EventData.ConfigEntry
        previousValue = $EventData.PreviousValue
        newValue = $EventData.NewValue
        disposition = $EventData.Disposition
        dispositionMessage = $EventData.DispositionMessage
        requestId = $EventData.RequestId
        riskIndicators = @()
        description = if($ADCSEventIDs.ContainsKey($Event.Id)) { $ADCSEventIDs[$Event.Id] } else { $Event.Message }
        rawData = $EventData
    }
    
    # Add risk indicators
    switch ($Event.Id) {
        4887 {
            if ($ParsedEvent.hasSubjectAltName) {
                $ParsedEvent.riskIndicators += "Certificate issued with SAN (potential ESC1/ESC6)"
            }
            if ($ParsedEvent.certificateTemplate -match "User|Machine|Computer|DomainController") {
                $ParsedEvent.riskIndicators += "High-value certificate template"
            }
        }
        4898 { $ParsedEvent.riskIndicators += "Template permissions changed (potential ESC4)" }
        4899 { $ParsedEvent.riskIndicators += "Template configuration modified" }
        4882 { $ParsedEvent.riskIndicators += "CA security modified (potential ESC5/ESC7)" }
        4890 { $ParsedEvent.riskIndicators += "CA manager settings modified (potential ESC7)" }
    }
    
    return $ParsedEvent
}

function Get-AuthenticationEvents {
    param([int]$Hours)

    $StartTime = (Get-Date).AddHours(-$Hours)

    Write-Host "Collecting authentication events from the last $Hours hours..."

    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = $AuthEventIDs
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    return $Events
}

function Get-ShareEvents {
    param([int]$Hours)

    $StartTime = (Get-Date).AddHours(-$Hours)

    Write-Host "Collecting SMB share access events from the last $Hours hours..."

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(5140, 5145)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue

        if ($Events) {
            Write-Host "Found $($Events.Count) share access events" -ForegroundColor Green
        } else {
            Write-Host "No share access events found (requires object access auditing)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Share access events not accessible" -ForegroundColor Yellow
        $Events = @()
    }

    return $Events
}

function Parse-AuthEvent {
    param($Event)

    if (-not $Event) { return $null }
    if (-not $Event.RecordId) { return $null }
    
    try {
        $EventXML = [xml]$Event.ToXml()
        $EventData = @{}

        if ($EventXML -and $EventXML.Event -and $EventXML.Event.EventData -and $EventXML.Event.EventData.Data) {
            foreach ($Data in $EventXML.Event.EventData.Data) {
                if ($Data -and $Data.Name) {
                    $EventData[$Data.Name] = $Data.'#text'
                }
            }
        }
    } catch {
        return $null
    }

    $ParsedEvent = @{
        id = "event_$($Event.RecordId)_$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
        timestamp = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        eventId = $Event.Id.ToString()
        eventType = "Authentication"
        computerName = if($EventData.WorkstationName -and $EventData.WorkstationName -ne "-") { $EventData.WorkstationName } else { $Event.MachineName }
        userName = if($EventData.TargetUserName -and $EventData.TargetUserName -ne "-") { $EventData.TargetUserName } else { $null }
        domainName = if($EventData.TargetDomainName -and $EventData.TargetDomainName -ne "-") { $EventData.TargetDomainName } else { $null }
        callerUserName = if($EventData.SubjectUserName -and $EventData.SubjectUserName -ne "-") { $EventData.SubjectUserName } else { $null }
        callerDomainName = if($EventData.SubjectDomainName -and $EventData.SubjectDomainName -ne "-") { $EventData.SubjectDomainName } else { $null }
        sourceIp = if($EventData.IpAddress -and $EventData.IpAddress -ne "-" -and $EventData.IpAddress -ne "127.0.0.1") { $EventData.IpAddress } else { $null }
        sourcePort = if($EventData.IpPort -and $EventData.IpPort -ne "-") { [int]$EventData.IpPort } else { $null }
        logonType = if($EventData.LogonType) { $LogonTypes[[int]$EventData.LogonType] } else { $null }
        status = switch ($Event.Id) {
            4624 { "Success" }
            4625 { "Failed" }
            4634 { "Logoff" }
            4647 { "Success" }
            4648 { "Success" }
            4740 { "Success" }
            4742 { "Success" }
            4768 { "Success" }
            4769 { "Failed" }
            4771 { "Failed" }
            4776 { if($EventData.Status -eq "0x0") { "Success" } else { "Failed" } }
            4778 { "Success" }
            4779 { "Success" }
            default { "Success" }
        }
        failureReason = if($EventData.FailureReason -and $EventData.FailureReason -ne "-") { $EventData.FailureReason } else { $null }
        failureCode = if($EventData.Status -and $EventData.Status -ne "-") { $EventData.Status } else { $null }
        authenticationPackage = if($EventData.AuthenticationPackageName -and $EventData.AuthenticationPackageName -ne "-") { $EventData.AuthenticationPackageName } else { $null }
        logonProcess = if($EventData.LogonProcessName -and $EventData.LogonProcessName -ne "-") { $EventData.LogonProcessName } else { $null }
        workstationName = if($EventData.WorkstationName -and $EventData.WorkstationName -ne "-") { $EventData.WorkstationName } else { $null }
        rawData = @{
            recordId = $Event.RecordId
            processId = $EventData.ProcessId
            processName = $EventData.ProcessName
            subjectUserName = $EventData.SubjectUserName
            subjectDomainName = $EventData.SubjectDomainName
            subjectLogonId = $EventData.SubjectLogonId
            targetLogonId = $EventData.TargetLogonId
            status = $EventData.Status
            subStatus = $EventData.SubStatus
            failureCode = $EventData.Status
        }
    }

    return $ParsedEvent
}

function Parse-ShareEvent {
    param($Event)

    if (-not $Event) { return $null }
    if (-not $Event.RecordId) { return $null }
    
    try {
        $EventXML = [xml]$Event.ToXml()
        $EventData = @{}

        if ($EventXML -and $EventXML.Event -and $EventXML.Event.EventData -and $EventXML.Event.EventData.Data) {
            foreach ($Data in $EventXML.Event.EventData.Data) {
                if ($Data -and $Data.Name) {
                    $EventData[$Data.Name] = $Data.'#text'
                }
            }
        }
    } catch {
        return $null
    }

    $ParsedEvent = @{
        id = "share_event_$($Event.RecordId)_$([DateTimeOffset]::Now.ToUnixTimeMilliseconds())"
        timestamp = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        eventId = $Event.Id.ToString()
        eventType = "ShareAccess"
        computerName = $Event.MachineName
        userName = if($EventData.SubjectUserName -and $EventData.SubjectUserName -ne "-") { $EventData.SubjectUserName } else { $null }
        domainName = if($EventData.SubjectDomainName -and $EventData.SubjectDomainName -ne "-") { $EventData.SubjectDomainName } else { $null }
        sourceIp = if($EventData.IpAddress -and $EventData.IpAddress -ne "-" -and $EventData.IpAddress -ne "127.0.0.1" -and $EventData.IpAddress -ne "::1") { $EventData.IpAddress } else { $null }
        sourcePort = if($EventData.IpPort -and $EventData.IpPort -ne "-") { [int]$EventData.IpPort } else { $null }
        shareName = if($EventData.ShareName) { $EventData.ShareName } else { $null }
        shareLocalPath = if($EventData.ShareLocalPath) { $EventData.ShareLocalPath } else { $null }
        objectType = if($EventData.ObjectType) { $EventData.ObjectType } else { $null }
        accessMask = if($EventData.AccessMask) { $EventData.AccessMask } else { $null }
        accessList = if($EventData.AccessList) { $EventData.AccessList } else { $null }
        accessReason = if($EventData.AccessReason) { $EventData.AccessReason } else { $null }
        status = if($EventData.AccessMask -and $EventData.AccessMask -ne "0x0") { "Success" } else { "Failed" }
        rawData = @{
            recordId = $Event.RecordId
            subjectUserSid = $EventData.SubjectUserSid
            subjectDomainName = $EventData.SubjectDomainName
            subjectLogonId = $EventData.SubjectLogonId
            objectServer = $EventData.ObjectServer
            objectType = $EventData.ObjectType
            objectName = $EventData.ObjectName
            handleId = $EventData.HandleId
            accessList = $EventData.AccessList
            accessMask = $EventData.AccessMask
            accessReason = $EventData.AccessReason
            shareName = $EventData.ShareName
            shareLocalPath = $EventData.ShareLocalPath
        }
    }

    return $ParsedEvent
}

function Enrich-WithAD {
    param($Events)
    
    if (-not (Get-Module ActiveDirectory -ListAvailable)) {
        Write-Warning "Active Directory module not available. Skipping AD enrichment."
        return $Events
    }
    
    Write-Host "Enriching with Active Directory data..."
    
    $UserCache = @{}
    
    foreach ($Event in $Events) {
        if ($Event.userName -and $Event.userName -ne "ANONYMOUS LOGON" -and $Event.userName -notmatch '\$$') {
            $UserKey = "$($Event.domainName)\$($Event.userName)"
            
            if (-not $UserCache.ContainsKey($UserKey)) {
                try {
                    $ADUser = Get-ADUser -Identity $Event.userName -Properties Department, Title, LastLogonDate, PasswordLastSet, Enabled, LockedOut, MemberOf, Description, SamAccountName, UserPrincipalName, whenCreated, PasswordNeverExpires, CannotChangePassword, AccountExpirationDate, LastBadPasswordAttempt, BadPwdCount -ErrorAction SilentlyContinue

                    if ($ADUser) {
                        $PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Backup Operators", "Server Operators", "Account Operators", "Print Operators")
                        $UserGroups = $ADUser.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } | Where-Object { $_ }
                        $IsPrivileged = ($UserGroups | Where-Object { $PrivilegedGroups -contains $_ }) -ne $null

                        # Service Account Detection
                        $IsServiceAccount = $false
                        $ServiceAccountType = "regular_user"
                        $ServiceAccountIndicators = @()

                        if ($ADUser.SamAccountName -match '^(svc|service|sql|app|web|iis|tomcat|oracle|mysql|mssql|postgres|mongodb|redis|nginx|apache|jenkins|gitlab|docker|k8s|kube)_') {
                            $IsServiceAccount = $true
                            $ServiceAccountType = "application_service"
                            $ServiceAccountIndicators += "Username pattern matches service account convention"
                        }

                        if ($ADUser.SamAccountName -match '\$$') {
                            $IsServiceAccount = $true
                            $ServiceAccountType = "computer_account"
                            $ServiceAccountIndicators += "Computer account (ends with $)"
                        }

                        if ($ADUser.Description -and ($ADUser.Description -match '(?i)(service|svc|app|application|sql|database|web|server|daemon|system|batch|job|scheduled|automation|integration)')) {
                            $IsServiceAccount = $true
                            if ($ServiceAccountType -eq "regular_user") {
                                $ServiceAccountType = "application_service"
                            }
                            $ServiceAccountIndicators += "Description indicates service usage"
                        }

                        if ($ADUser.PasswordNeverExpires) {
                            $IsServiceAccount = $true
                            $ServiceAccountIndicators += "Password never expires (service account pattern)"
                        }

                        if ($ADUser.CannotChangePassword) {
                            $IsServiceAccount = $true
                            $ServiceAccountType = "managed_service"
                            $ServiceAccountIndicators += "Cannot change password (managed service account)"
                        }

                        $ServiceAccountGroups = @("Service Accounts", "Managed Service Accounts", "Domain Service Accounts")
                        $InServiceGroup = ($UserGroups | Where-Object { $ServiceAccountGroups -contains $_ }) -ne $null
                        if ($InServiceGroup) {
                            $IsServiceAccount = $true
                            $ServiceAccountType = "group_managed"
                            $ServiceAccountIndicators += "Member of service account groups"
                        }

                        $AccountAge = (Get-Date) - $ADUser.whenCreated
                        if ($AccountAge.TotalDays -gt 365) {
                            $ServiceAccountIndicators += "Account older than 1 year"
                        }

                        $NormalHours = @{ start = 8; end = 17 }
                        if ($IsServiceAccount) {
                            $NormalHours = @{ start = 0; end = 23 }
                        }

                        $UserCache[$UserKey] = @{
                            Department = $ADUser.Department
                            Title = $ADUser.Title
                            LastLogonDate = $ADUser.LastLogonDate
                            PasswordLastSet = $ADUser.PasswordLastSet
                            Enabled = $ADUser.Enabled
                            LockedOut = $ADUser.LockedOut
                            Groups = $UserGroups
                            IsPrivileged = $IsPrivileged
                            Description = $ADUser.Description
                            NormalLoginHours = $NormalHours
                            IsServiceAccount = $IsServiceAccount
                            ServiceAccountType = $ServiceAccountType
                            ServiceAccountIndicators = $ServiceAccountIndicators
                            PasswordNeverExpires = $ADUser.PasswordNeverExpires
                            CannotChangePassword = $ADUser.CannotChangePassword
                            AccountExpirationDate = $ADUser.AccountExpirationDate
                            LastBadPasswordAttempt = $ADUser.LastBadPasswordAttempt
                            BadPasswordCount = $ADUser.BadPwdCount
                            AccountAgeDays = [math]::Round($AccountAge.TotalDays)
                        }
                    }
                } catch {
                    $UserCache[$UserKey] = $null
                }
            }
            
            if ($UserCache[$UserKey]) {
                $Event.adUserInfo = $UserCache[$UserKey]
            }
        }
    }
    
    return $Events
}

function Export-AuthEvents {
    param($Events, $OutputPath, $Format)
    
    if ($Format.ToLower() -eq "csv") {
        Export-AuthEventsCSV $Events $OutputPath
    } else {
        Export-AuthEventsJSON $Events $OutputPath
    }
}

function Export-AuthEventsJSON {
    param($Events, $OutputPath)
    
    $AuthEvents = $Events | Where-Object { $_.eventType -eq "Authentication" }
    $ADCSEvents = $Events | Where-Object { $_.eventType -eq "ADCS" -or $_.eventType -eq "RawADCS" }
    $ShareEvents = $Events | Where-Object { $_.eventType -eq "ShareAccess" }
    
    # Create analytics context
    $UserProfiles = @()
    
    $UniqueUsers = $AuthEvents | Where-Object { $_.userName -and $_.adUserInfo } | Group-Object { "$($_.domainName)\$($_.userName)" }
    foreach ($UserGroup in $UniqueUsers) {
        $SampleEvent = $UserGroup.Group[0]
        $UserInfo = $SampleEvent.adUserInfo
        
        $UserProfiles += @{
            userName = $SampleEvent.userName
            domain = $SampleEvent.domainName
            department = $UserInfo.Department
            title = $UserInfo.Title
            privileged = $UserInfo.IsPrivileged
            enabled = $UserInfo.Enabled
            groups = $UserInfo.Groups
            normalLoginHours = $UserInfo.NormalLoginHours
            isServiceAccount = $UserInfo.IsServiceAccount
            serviceAccountType = $UserInfo.ServiceAccountType
        }
    }
    
    $RawADCSEvents = $ADCSEvents | Where-Object { $_.eventType -eq "RawADCS" }
    $ADCSContext = @{
        certificatesIssued = ($ADCSEvents | Where-Object { $_.eventId -eq "4887" }).Count
        certificatesDenied = ($ADCSEvents | Where-Object { $_.eventId -eq "4888" }).Count
        templateModifications = ($ADCSEvents | Where-Object { $_.eventId -in @("4898", "4899") }).Count
        caConfigChanges = ($ADCSEvents | Where-Object { $_.eventId -in @("4882", "4890", "4891") }).Count
        uniqueTemplates = ($ADCSEvents | Where-Object { $_.certificateTemplate } | Select-Object -ExpandProperty certificateTemplate -Unique).Count
        riskyEvents = ($ADCSEvents | Where-Object { $_.riskIndicators.Count -gt 0 }).Count
        rawDatabaseAnalysis = @{
            enabled = $Script:RawDatabaseAnalysis
            esc1Indicators = $RawADCSEvents.Count
            upnMismatches = ($RawADCSEvents | Where-Object { $_.isSuspiciousUPN }).Count
            privilegedTargets = ($RawADCSEvents | Where-Object { $_.isPrivilegedTarget }).Count
        }
    }
    
    $ExportData = @{
        events = $Events | ForEach-Object {
            $CleanEvent = $_.PSObject.Copy()
            $CleanEvent.PSObject.Properties.Remove('adUserInfo')
            return $CleanEvent
        }
        context = @{
            sessionId = [guid]::NewGuid().ToString()
            organizationId = "collected_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            timeRange = @{
                start = ($Events | Sort-Object timestamp | Select-Object -First 1).timestamp
                end = ($Events | Sort-Object timestamp | Select-Object -Last 1).timestamp
            }
            userProfiles = $UserProfiles
            adcsContext = $ADCSContext
        }
        metadata = @{
            generatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            generatedBy = "ADTrapper PowerShell Collector v$($Script:Version)"
            eventCount = $Events.Count
            authEventCount = $AuthEvents.Count
            adcsEventCount = $ADCSEvents.Count
            shareEventCount = $ShareEvents.Count
            timeRangeHours = $Hours
            enrichmentFlags = @{
                adEnrichment = $EnrichWithAD.IsPresent
                adcsCollection = $ADCS.IsPresent
                smbCollection = $true
                rawDatabaseAnalysis = $Script:RawDatabaseAnalysis
            }
            uniqueUsers = $UserProfiles.Count
            eventTypes = $Events | Group-Object eventId | ForEach-Object { @{ eventId = $_.Name; count = $_.Count } }
            eventCategories = @{
                authentication = $AuthEvents.Count
                adcs = $ADCSEvents.Count
                rawAdcs = $RawADCSEvents.Count
                shareAccess = $ShareEvents.Count
            }
        }
    }
    
    $ExportData | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host "  Export Complete!" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host ""
    Write-Host "  Output File: $OutputPath" -ForegroundColor White
    Write-Host "  Total Events: $($Events.Count)" -ForegroundColor Cyan
    Write-Host "    - Authentication: $($AuthEvents.Count)" -ForegroundColor Gray
    Write-Host "    - AD CS: $($ADCSEvents.Count)" -ForegroundColor Gray
    Write-Host "    - Share Access: $($ShareEvents.Count)" -ForegroundColor Gray
    Write-Host "  Unique Users: $($UserProfiles.Count)" -ForegroundColor Cyan
    Write-Host ""
}

function Export-AuthEventsCSV {
    param($Events, $OutputPath)
    
    $FlattenedEvents = $Events | ForEach-Object {
        $Event = $_
        $UserInfo = $Event.adUserInfo
        
        [PSCustomObject]@{
            ID = $Event.id
            Timestamp = $Event.timestamp
            EventID = $Event.eventId
            EventType = $Event.eventType
            ComputerName = $Event.computerName
            UserName = $Event.userName
            DomainName = $Event.domainName
            CallerUserName = $Event.callerUserName
            CallerDomainName = $Event.callerDomainName
            SourceIP = $Event.sourceIp
            SourcePort = $Event.sourcePort
            LogonType = $Event.logonType
            Status = $Event.status
            FailureReason = $Event.failureReason
            AuthPackage = $Event.authenticationPackage
            LogonProcess = $Event.logonProcess
            WorkstationName = $Event.workstationName
            CertificateTemplate = $Event.certificateTemplate
            HasSAN = $Event.hasSubjectAltName
            RiskIndicators = if($Event.riskIndicators) { $Event.riskIndicators -join ";" } else { $null }
            UserDepartment = if($UserInfo) { $UserInfo.Department } else { $null }
            UserTitle = if($UserInfo) { $UserInfo.Title } else { $null }
            UserEnabled = if($UserInfo) { $UserInfo.Enabled } else { $null }
            IsPrivileged = if($UserInfo) { $UserInfo.IsPrivileged } else { $null }
            IsServiceAccount = if($UserInfo) { $UserInfo.IsServiceAccount } else { $null }
            UserGroups = if($UserInfo) { $UserInfo.Groups -join ";" } else { $null }
        }
    }
    
    $FlattenedEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host "  CSV Export Complete!" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host ""
    Write-Host "  Output File: $OutputPath" -ForegroundColor White
    Write-Host "  Total Events: $($Events.Count)" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# Main Execution
# ============================================================================

Show-Banner

# Check admin privileges
if (-not (Test-AdminPrivileges)) {
    Write-Host "[WARNING] Not running as Administrator!" -ForegroundColor Red
    Write-Host "Some events may not be accessible. Run PowerShell as Administrator for full access." -ForegroundColor Yellow
    Write-Host ""
}

# Show configuration
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Time Range: $Hours hours" -ForegroundColor Gray
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host "  Format: $Format" -ForegroundColor Gray
Write-Host "  AD Enrichment: $($EnrichWithAD.IsPresent)" -ForegroundColor Gray
Write-Host "  AD CS Collection: $($ADCS.IsPresent)" -ForegroundColor Gray
Write-Host "  Raw Database Analysis: $($RawDatabase.IsPresent)" -ForegroundColor Gray
Write-Host ""

# Handle raw database analysis confirmation
if ($RawDatabase -and $ADCS) {
    $Script:RawDatabaseAnalysis = Confirm-RawDatabaseAnalysis
} elseif ($RawDatabase -and -not $ADCS) {
    Write-Host "[WARNING] -RawDatabase requires -ADCS flag. Ignoring -RawDatabase." -ForegroundColor Yellow
    $Script:RawDatabaseAnalysis = $false
}

try {
    $AllEvents = @()
    
    # Collect AD CS events if requested
    if ($ADCS) {
        Write-Host "`n[AD CS Events]" -ForegroundColor Magenta
        Write-Host "-" * 40 -ForegroundColor Gray
        $ADCSEvents = Get-ADCSEvents -Hours $Hours
        
        if ($ADCSEvents.Count -gt 0) {
            Write-Host "Found $($ADCSEvents.Count) AD CS events" -ForegroundColor Green
            
            Write-Host "Parsing AD CS events..." -ForegroundColor Cyan
            $ParsedADCSEvents = @()
            foreach ($Event in $ADCSEvents) {
                $ParsedEvent = Parse-ADCSEvent $Event
                if ($ParsedEvent) {
                    $ParsedADCSEvents += $ParsedEvent
                }
            }
            Write-Host "Successfully parsed $($ParsedADCSEvents.Count) AD CS events" -ForegroundColor Green
            $AllEvents += $ParsedADCSEvents
        } else {
            Write-Host "No AD CS events found" -ForegroundColor Yellow
        }
    }
    
    # Collect authentication events
    Write-Host "`n[Authentication Events]" -ForegroundColor Magenta
    Write-Host "-" * 40 -ForegroundColor Gray
    $AuthEvents = Get-AuthenticationEvents -Hours $Hours

    # Collect SMB share events
    Write-Host "`n[SMB Share Events]" -ForegroundColor Magenta
    Write-Host "-" * 40 -ForegroundColor Gray
    $ShareEvents = Get-ShareEvents -Hours $Hours

    if ($AuthEvents.Count -eq 0 -and $ShareEvents.Count -eq 0 -and $AllEvents.Count -eq 0) {
        Write-Warning "No events found in the specified time range."
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Run PowerShell as Administrator" -ForegroundColor Gray
        Write-Host "  2. Try increasing -Hours parameter" -ForegroundColor Gray
        Write-Host "  3. Check if Security logging is enabled" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Running diagnostic check..." -ForegroundColor Cyan
        Test-EventLogs
        exit 1
    }

    if ($AuthEvents.Count -gt 0) {
        Write-Host "Found $($AuthEvents.Count) authentication events" -ForegroundColor Green

        Write-Host "Parsing authentication events..." -ForegroundColor Cyan
        $ParsedAuthEvents = @()
        foreach ($Event in $AuthEvents) {
            $ParsedEvent = Parse-AuthEvent $Event
            if ($ParsedEvent) {
                $ParsedAuthEvents += $ParsedEvent
            }
        }
        Write-Host "Successfully parsed $($ParsedAuthEvents.Count) authentication events" -ForegroundColor Green

        if ($EnrichWithAD) {
            $ParsedAuthEvents = Enrich-WithAD $ParsedAuthEvents
        }

        $AllEvents += $ParsedAuthEvents
    }

    if ($ShareEvents.Count -gt 0) {
        Write-Host "Found $($ShareEvents.Count) share access events" -ForegroundColor Green

        Write-Host "Parsing share access events..." -ForegroundColor Cyan
        $ParsedShareEvents = @()
        foreach ($Event in $ShareEvents) {
            $ParsedEvent = Parse-ShareEvent $Event
            if ($ParsedEvent) {
                $ParsedShareEvents += $ParsedEvent
            }
        }
        Write-Host "Successfully parsed $($ParsedShareEvents.Count) share events" -ForegroundColor Green

        $AllEvents += $ParsedShareEvents
    }
    
    # Export
    Write-Host "`n[Exporting]" -ForegroundColor Magenta
    Write-Host "-" * 40 -ForegroundColor Gray
    Export-AuthEvents $AllEvents $OutputPath $Format
    
    Write-Host "Upload this file to ADTrapper for analysis:" -ForegroundColor Cyan
    Write-Host "  https://github.com/MHaggis/ADTrapper" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Error "Error processing logs: $($_.Exception.Message)"
    Write-Host "Try running with -Verbose for more details" -ForegroundColor Yellow
    exit 1
}

