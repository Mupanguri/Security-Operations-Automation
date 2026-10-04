<#
.SYNOPSIS
    Daily Intune compliance, stale-device and OS-version report (app-only Microsoft Graph).
.DESCRIPTION
    Writes CSV reports and intune_compliance.summary.json to C:\SecOps\out.
    Requires: Microsoft.Graph.Authentication module, an Entra app registration with the
    application permissions DeviceManagementManagedDevices.Read.All and
    DeviceManagementConfiguration.Read.All (admin consented), and its certificate in
    Cert:\LocalMachine\My.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\SecOps\config\config.json',
    [string]$OutDir     = 'C:\SecOps\out',
    [int]$StaleDays     = 14
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd'
Start-Transcript -Path "C:\SecOps\logs\intune_compliance_$stamp.log" -Append | Out-Null

function Get-GraphPaged {
    param([string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri
        foreach ($i in $r.value) { $items.Add($i) }
        $Uri = $r.'@odata.nextLink'
    }
    $items
}

try {
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $g   = $cfg.graph
    $cert = Get-Item "Cert:\LocalMachine\My\$($g.certThumbprint)" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item "Cert:\CurrentUser\My\$($g.certThumbprint)" }
    Connect-MgGraph -ClientId $g.clientId -TenantId $g.tenantId -Certificate $cert -NoWelcome

    $fields = 'id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,' +
              'lastSyncDateTime,isEncrypted,serialNumber,enrolledDateTime'
    $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=' +
           $fields + '&$top=200'
    $devices = @(Get-GraphPaged -Uri $uri)
    Write-Output "Retrieved $($devices.Count) managed devices"

    $now = Get-Date
    $report = foreach ($d in $devices) {
        $last = if ($d.lastSyncDateTime) { [datetime]$d.lastSyncDateTime } else { [datetime]'2000-01-01' }
        [pscustomobject]@{
            Id              = $d.id
            DeviceName      = $d.deviceName
            User            = $d.userPrincipalName
            OS              = $d.operatingSystem
            OSVersion       = $d.osVersion
            Compliance      = $d.complianceState
            Encrypted       = $d.isEncrypted
            Serial          = $d.serialNumber
            LastSync        = $last
            DaysSinceSync   = [int]($now - $last).TotalDays
            FailingPolicies = ''
        }
    }

    # Which policy is each non-compliant device failing?
    $nonCompliant = @($report | Where-Object { $_.Compliance -eq 'noncompliant' })
    foreach ($nc in $nonCompliant) {
        try {
            $states = @(Get-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/deviceManagement/" +
                        "managedDevices/$($nc.Id)/deviceCompliancePolicyStates"))
            $nc.FailingPolicies = (($states | Where-Object { $_.state -eq 'nonCompliant' } |
                                    ForEach-Object { $_.displayName }) -join '; ')
        } catch { $nc.FailingPolicies = 'lookup failed' }
        Start-Sleep -Milliseconds 200
    }

    $stale = @($report | Where-Object { $_.DaysSinceSync -ge $StaleDays })

    $summaryPath = Join-Path $OutDir 'intune_compliance.summary.json'
    $prev = $null
    if (Test-Path $summaryPath) {
        $prev = (Get-Content $summaryPath -Raw | ConvertFrom-Json).noncompliant
    }

    $report       | Select-Object * -ExcludeProperty Id |
        Export-Csv (Join-Path $OutDir "intune_all_devices_$stamp.csv") -NoTypeInformation -Encoding UTF8
    $nonCompliant | Select-Object * -ExcludeProperty Id |
        Export-Csv (Join-Path $OutDir "intune_noncompliant_$stamp.csv") -NoTypeInformation -Encoding UTF8
    $stale        | Select-Object * -ExcludeProperty Id |
        Export-Csv (Join-Path $OutDir "intune_stale_$stamp.csv") -NoTypeInformation -Encoding UTF8

    $osVersions = @($report | Where-Object { $_.OS -eq 'Windows' } |
                    Group-Object OSVersion | Sort-Object Count -Descending |
                    Select-Object -First 8 |
                    ForEach-Object { [pscustomobject]@{ version = $_.Name; count = $_.Count } })

    [ordered]@{
        total                 = $report.Count
        compliant             = @($report | Where-Object { $_.Compliance -eq 'compliant' }).Count
        noncompliant          = $nonCompliant.Count
        stale                 = $stale.Count
        stale_days            = $StaleDays
        previous_noncompliant = $prev
        os_versions           = $osVersions
        generated_utc         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath -Encoding utf8

    Write-Output "Non-compliant: $($nonCompliant.Count). Stale ($StaleDays+ days): $($stale.Count)."
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Stop-Transcript | Out-Null
}
