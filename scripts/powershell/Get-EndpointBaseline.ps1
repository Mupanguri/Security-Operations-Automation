<#
.SYNOPSIS
    Local security baseline check. Deploy as an Intune Remediation DETECTION script
    (exit 1 = issues found, remediation runs) or run ad hoc as administrator.
#>
$approvedAdmins   = @('Administrator', 'Domain Admins', 'ENTITY-LocalAdmin')           # EDIT
$requiredServices = @('Sophos MCS Agent', 'Sophos Endpoint Defense Service',
                      'Sophos Anti-Virus')    # VERIFY with: Get-Service -DisplayName 'Sophos*'
$issues = New-Object System.Collections.Generic.List[string]

# Disk encryption
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.ProtectionStatus -ne 'On') { $issues.Add('BitLocker off on system drive') }
} catch { $issues.Add('BitLocker status unavailable') }

# Windows Firewall
Get-NetFirewallProfile | Where-Object { -not $_.Enabled } |
    ForEach-Object { $issues.Add("Firewall disabled: $($_.Name)") }

# Sophos agent services
foreach ($name in $requiredServices) {
    $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue
    if (-not $svc) { $issues.Add("Service missing: $name") }
    elseif ($svc.Status -ne 'Running') { $issues.Add("Service not running: $name") }
}

# Legacy protocol and remote access exposure
if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { $issues.Add('SMBv1 server enabled') }
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name fDenyTSConnections).fDenyTSConnections
if ($rdp -eq 0) { $issues.Add('RDP enabled') }                 # remove if RDP is expected

# Local administrators
try {
    $members = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop).Name
} catch {
    # Get-LocalGroupMember can fail on Entra-joined devices with orphaned SIDs
    $members = net localgroup Administrators 2>$null |
               Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }
}
foreach ($m in $members) {
    if ($approvedAdmins -notcontains (($m -split '\\')[-1])) { $issues.Add("Unapproved local admin: $m") }
}

# Housekeeping
$free = [math]::Round((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB, 1)
if ($free -lt 10) { $issues.Add("Low disk space: $free GB free") }
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if ($uptime.TotalDays -gt 30) { $issues.Add("Not rebooted for $([int]$uptime.TotalDays) days") }

if ($issues.Count -gt 0) {
    Write-Output ('NONCOMPLIANT: ' + ($issues -join ' | '))
    exit 1
}
Write-Output 'COMPLIANT'
exit 0
