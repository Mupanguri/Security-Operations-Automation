<#
.SYNOPSIS
    Loads secrets from SecretManagement into this process only, then runs a Python job.
.EXAMPLE
    .\Run-Job.ps1 -Script sophos_alert_collector.py
#>
param([string]$Script)

$ErrorActionPreference = 'Stop'
if (-not $Script) { throw 'Usage: Run-Job.ps1 -Script <file.py> [script arguments]' }
Import-Module Microsoft.PowerShell.SecretManagement

$env:SOPHOS_CLIENT_ID     = Get-Secret -Name SophosClientId     -AsPlainText
$env:SOPHOS_CLIENT_SECRET = Get-Secret -Name SophosClientSecret -AsPlainText
$env:TEAMS_WEBHOOK_URL    = Get-Secret -Name TeamsWebhookUrl    -AsPlainText
# Only if email.enabled is true and your SMTP relay needs authentication:
# $env:SMTP_USER     = Get-Secret -Name SmtpUser     -AsPlainText
# $env:SMTP_PASSWORD = Get-Secret -Name SmtpPassword -AsPlainText

$python = 'C:\SecOps\venv\Scripts\python.exe'
Set-Location 'C:\SecOps\scripts'
& $python (Join-Path 'C:\SecOps\scripts' $Script) @args
exit $LASTEXITCODE
