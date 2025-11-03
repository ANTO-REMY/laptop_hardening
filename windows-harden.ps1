<#!
  Windows Laptop Hardening Script
  References:
    - CIS Benchmarks for Windows 10/11
    - NIST Cybersecurity Framework
    - Microsoft Security Baselines
    - OWASP Top 10 (Config Guidance)

  Safe, idempotent, modular hardening checks, logging all evidence to ./reports.
  NOT destructive: no file deletion, no forced reboots, no auto BitLocker.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
  [switch]$DryRun,
  [string]$LogPath = ".\reports",
  [switch]$SkipChocolatey,
  [switch]$Confirm = $true
)

# Setup timestamp and log file paths
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportsDir = $LogPath
$LogFile = Join-Path $ReportsDir "hardening-log-$Timestamp.txt"

# Ensure reports directory exists
if (!(Test-Path $ReportsDir)) {
  if (-not $DryRun) { New-Item -Path $ReportsDir -ItemType Directory | Out-Null }
  Write-Host "Created reports directory: $ReportsDir"
}

function Log-Write ($Message) {
  Write-Host $Message
  Add-Content $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format "u"), $Message)
}

Log-Write "Windows Laptop Hardening Script Started"

function Confirm-Action ($Prompt) {
  if (-not $Confirm) { return $true }
  $response = Read-Host "$Prompt [y/N]"
  return $response -match '^(y|Y)$'
}

function Install-ChocolateyIfMissing {
  if ($SkipChocolatey) { Log-Write "Skipping Chocolatey install per parameter"; return }
  $choco = Get-Command choco -ErrorAction SilentlyContinue
  if ($null -eq $choco) {
    Log-Write "Chocolatey not found. Will install."
    if ($DryRun) { Log-Write "DryRun active; would install Chocolatey."; return }
    if (-not (Confirm-Action "Install Chocolatey?")) { Log-Write "User declined Chocolatey install."; return }
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Log-Write "Chocolatey installed (check for errors above)."
  } else {
    Log-Write "Chocolatey is already installed."
  }
}

function Install-Tools {
  $tools = @('sysinternals','7zip','notepadplusplus','nmap','git')
  foreach ($tool in $tools) {
    $pkg = choco list --local-only | Select-String "^$tool"
    if ($pkg) {
      Log-Write "$tool already installed."
    } else {
      if ($DryRun) {
        Log-Write "DryRun: Would install $tool"
      } else {
        if (-not (Confirm-Action "Install $tool via Chocolatey?")) { Log-Write "User declined $tool install."; continue }
        choco install $tool -y
        Log-Write "$tool installed."
      }
    }
  }
}

function Check-WindowsUpdateStatus {
  $updateSession = New-Object -ComObject Microsoft.Update.Session
  $searcher = $updateSession.CreateUpdateSearcher()
  $historyCount = $searcher.GetTotalHistoryCount()
  $lastUpdate = $null
  if ($historyCount -gt 0) {
    $lastUpdate = $searcher.QueryHistory(0,1)[0].Date
    Log-Write "Last update is $lastUpdate"
  } else {
    Log-Write "No update history found."
  }
  $pending = $searcher.Search("IsInstalled=0").Updates.Count
  if ($pending -gt 0) {
    Log-Write "$pending Windows updates are pending."
  } else {
    Log-Write "No Windows updates pending."
  }
}

function Ensure-WindowsFirewall {
  $profiles = Get-NetFirewallProfile
  $enabledCount = 0
  foreach ($profile in $profiles) {
    if (-not $profile.Enabled) {
      if (-not $DryRun) {
        if (Confirm-Action "Enable Windows Firewall for $($profile.Name) profile?") {
          Set-NetFirewallProfile -Name $profile.Name -Enabled True
          Log-Write "Enabled firewall for $($profile.Name)"
        } else {
          Log-Write "User skipped enabling firewall for $($profile.Name)"
        }
      } else {
        Log-Write "DryRun: Would enable Windows Firewall for $($profile.Name)"
      }
    } else {
      $enabledCount += 1
    }
  }
  $fwReport = Join-Path $ReportsDir "firewall-$Timestamp.txt"
  $profiles | Format-Table | Out-String | Set-Content $fwReport
  Log-Write "$enabledCount firewall profile(s) enabled; see firewall report: $fwReport"
}

function Ensure-WindowsDefender {
  try {
    $defender = Get-MpComputerStatus
    Log-Write ("Defender status: RealTimeProtectionEnabled={0}, AntivirusEnabled={1}, AMServiceEnabled={2}" -f $defender.RealTimeProtectionEnabled, $defender.AntivirusEnabled, $defender.AMServiceEnabled)
  } catch {
    Log-Write "Defender status unavailable—likely due to another EDR/AV solution."
  }
}

function Export-RunningServices {
  $svcReport = Join-Path $ReportsDir "running-services-$Timestamp.txt"
  Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object DisplayName | Format-Table | Out-String | Set-Content $svcReport
  Log-Write "Exported running services report to $svcReport"
}

function Export-OpenPorts {
  $portsReport = Join-Path $ReportsDir "network-ports-$Timestamp.txt"
  $ports = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
  $udpports = Get-NetUDPEndpoint
  "$ports" | Out-File -Append $portsReport
  "$udpports" | Out-File -Append $portsReport
  $listenCount = ($ports | Measure-Object).Count
  Log-Write "$listenCount listening TCP ports detected. See $portsReport"
}

function Check-BitLockerStatus {
  $bitlockerReport = Join-Path $ReportsDir "bitlocker-status-$Timestamp.txt"
  manage-bde -status | Out-File $bitlockerReport
  Log-Write "Exported BitLocker status report to $bitlockerReport"
}

function Enable-BitLockerInteractive {
  Log-Write "BitLocker IS NOT ENABLED. Guidance:"
  Write-Host @"  
To enable BitLocker:

1. Ensure you have a backup of your Recovery Key—never store solely on your disk.
2. Run: 'manage-bde -on C:' (administrator prompt).
3. When prompted, save or print your recovery key.
4. Store recovery key in a safe, offline place. Never post/email it.
5. Do NOT enable BitLocker on system drives if unsure.
"@
  Log-Write "Displayed BitLocker user instructions, did not enable automatically."
}

function Run-BasicAuditTools {
  if (Get-Command nmap -ErrorAction SilentlyContinue) {
    $nmapReport = Join-Path $ReportsDir "nmap-local-$Timestamp.txt"
    if ($DryRun) {
      Log-Write "DryRun: Would run 'nmap -sT -O localhost'"
    } else {
      nmap -sT -O localhost | Out-File $nmapReport
      Log-Write "Nmap local scan completed to $nmapReport"
    }
  } else {
    Log-Write "nmap not installed; skipping scan."
  }
  # Lynis not typically available on Windows; skip unless explicitly present
  if (Get-Command lynis -ErrorAction SilentlyContinue) {
    $lynisReport = Join-Path $ReportsDir "lynis-$Timestamp.txt"
    lynis audit system | Out-File $lynisReport
    Log-Write "Lynis audit run complete to $lynisReport"
  }
}

# Main execution flow:
Install-ChocolateyIfMissing
Install-Tools
Check-WindowsUpdateStatus
Ensure-WindowsFirewall
Ensure-WindowsDefender
Export-RunningServices
Export-OpenPorts
Check-BitLockerStatus
Run-BasicAuditTools

# BitLocker enable prompt
if ((manage-bde -status | Select-String "Conversion Status: Fully Encrypted") -eq $null) {
  Enable-BitLockerInteractive
}

# List all report files created
Log-Write "Script completed. Generated report files:"
Get-ChildItem $ReportsDir | Where-Object {$_.LastWriteTime -gt (Get-Date).AddMinutes(-30)} | ForEach-Object {
  Log-Write "  $_"
}
Log-Write "All outputs safely saved to $ReportsDir. Review before sharing with mentor.
"