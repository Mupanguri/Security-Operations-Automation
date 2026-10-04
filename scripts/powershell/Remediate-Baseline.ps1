<#
.SYNOPSIS
    Remediation script paired with Get-EndpointBaseline.ps1. CHANGES DEVICE STATE.
    Runs as SYSTEM via Intune Remediations. Local admins are deliberately NOT removed.
#>
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]

Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object {
    Set-NetFirewallProfile -Name $_.Name -Enabled True
    $log.Add("Enabled firewall profile $($_.Name)")
}

if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    $log.Add('Disabled SMBv1 server')
}

foreach ($name in 'Sophos MCS Agent', 'Sophos Endpoint Defense Service', 'Sophos Anti-Virus') {
    $svc = Get-Service -DisplayName $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -ne 'Disabled' -and $svc.Status -ne 'Running') {
        Start-Service -InputObject $svc
        $log.Add("Started service $name")
    }
}

try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($bl.VolumeStatus -eq 'FullyEncrypted' -and $bl.ProtectionStatus -ne 'On') {
        Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null
        $log.Add('Resumed BitLocker protection')
    }
} catch { $log.Add("BitLocker step failed: $($_.Exception.Message)") }

Write-Output ($log -join ' | ')
exit 0
