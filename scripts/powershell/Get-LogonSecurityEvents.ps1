<#
.SYNOPSIS
    Summarises failed logons, lockouts and privileged-group changes from domain controllers.
.DESCRIPTION
    Needs read access to the Security log on each DC (Event Log Readers) and the
    "Remote Event Log Management" firewall rules. Event IDs used:
    4625 failed logon, 4740 lockout, 4728/4732/4756 member added to a security group.
#>
[CmdletBinding()]
param(
    [string[]]$DomainControllers = @('DC01.yourdomain.local', 'DC02.yourdomain.local'),   # EDIT
    [int]$LookbackHours   = 24,
    [int]$FailedThreshold = 10,
    [string[]]$PrivilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
                                    'Administrators'),
    [string]$OutDir = 'C:\SecOps\out'
)

$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$LookbackHours)
$stamp = Get-Date -Format 'yyyyMMdd'
Start-Transcript -Path "C:\SecOps\logs\logon_events_$stamp.log" -Append | Out-Null

function ConvertTo-EventObject($evt) {
    $h = [ordered]@{ TimeCreated = $evt.TimeCreated; Id = $evt.Id; DC = $evt.MachineName }
    foreach ($d in ([xml]$evt.ToXml()).Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    [pscustomobject]$h
}

try {
    $events = foreach ($dc in $DomainControllers) {
        try {
            Get-WinEvent -ComputerName $dc -ErrorAction Stop -FilterHashtable @{
                LogName = 'Security'; Id = 4625, 4740, 4728, 4732, 4756; StartTime = $start
            } | ForEach-Object { ConvertTo-EventObject $_ }
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Warning "Could not query ${dc}: $($_.Exception.Message)"
            }
        }
    }

    $failed = @($events | Where-Object { $_.Id -eq 4625 })

    $bruteForce = @($failed | Group-Object TargetUserName |
        Where-Object { $_.Count -ge $FailedThreshold } |
        Select-Object @{n='User'; e={$_.Name}}, Count,
            @{n='SourceIPs'; e={ (@($_.Group.IpAddress) | Where-Object { $_ -and $_ -ne '-' } |
                                  Sort-Object -Unique) -join ',' }})

    $sprayByIp = @($failed | Where-Object { $_.IpAddress -and $_.IpAddress -ne '-' } |
        Group-Object IpAddress |
        Where-Object { @($_.Group.TargetUserName | Sort-Object -Unique).Count -ge 5 } |
        Select-Object @{n='SourceIP'; e={$_.Name}}, Count,
            @{n='DistinctUsers'; e={ @($_.Group.TargetUserName | Sort-Object -Unique).Count }})

    $lockouts = @($events | Where-Object { $_.Id -eq 4740 } |
        Select-Object TimeCreated, DC, @{n='User'; e={$_.TargetUserName}},
                      @{n='CallerComputer'; e={$_.TargetDomainName}})

    $groupChanges = @($events |
        Where-Object { $_.Id -in 4728, 4732, 4756 -and $PrivilegedGroups -contains $_.TargetUserName } |
        Select-Object TimeCreated, DC, Id, @{n='Group'; e={$_.TargetUserName}},
                      @{n='Member'; e={$_.MemberName}}, @{n='ChangedBy'; e={$_.SubjectUserName}})

    $exports = @{ bruteforce = $bruteForce; spray = $sprayByIp;
                  lockouts = $lockouts; groupchanges = $groupChanges }
    foreach ($k in $exports.Keys) {
        if ($exports[$k].Count) {
            $exports[$k] | Export-Csv "$OutDir\logon_${k}_$stamp.csv" -NoTypeInformation
        }
    }

    [ordered]@{
        window_hours             = $LookbackHours
        failed_logons            = $failed.Count
        brute_force_users        = $bruteForce.Count
        spray_ips                = $sprayByIp.Count
        lockouts                 = $lockouts.Count
        privileged_group_changes = $groupChanges.Count
        generated_utc            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } | ConvertTo-Json | Set-Content (Join-Path $OutDir 'logon_events.summary.json') -Encoding utf8

    Write-Output ("Failed: $($failed.Count) | Lockouts: $($lockouts.Count) | " +
                  "Privileged group changes: $($groupChanges.Count)")
}
catch { Write-Error $_; exit 1 }
finally { Stop-Transcript | Out-Null }
