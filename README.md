# Security Operations Automation

A collection of PowerShell and Python jobs that continuously monitor an enterprise
endpoint, identity and network estate and report **only the exceptions**. Each job
writes a CSV report and a small `*.summary.json` file; a single daily digest reads
those summaries and posts one consolidated message to Microsoft Teams.

The estate in scope:

| Domain | System | Source |
| --- | --- | --- |
| Device management | Microsoft Intune | Microsoft Graph |
| Endpoint security | Sophos Central | Sophos Central API |
| Firewall logons | Sophos Firewall | Syslog (key=`"value"` format) |
| Identity | Active Directory | Domain controller Security logs |
| Availability | Core network devices | ICMP and TCP |
| Notification | Microsoft Teams | Workflows webhook |

---

## Table of contents

- [Design principles](#design-principles)
- [Repository layout](#repository-layout)
- [Runtime folder layout](#runtime-folder-layout)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Connecting to the environment](#connecting-to-the-environment)
- [Configuration file](#configuration-file)
- [Script reference](#script-reference)
  - [Shared libraries](#shared-libraries)
  - [PowerShell jobs](#powershell-jobs)
  - [Python jobs](#python-jobs)
- [Scheduling](#scheduling)
- [Security and operations](#security-and-operations)
- [Testing and rollout](#testing-and-rollout)
- [Troubleshooting](#troubleshooting)

---

## Design principles

These five rules shaped every script in this repository.

1. **Alert on exceptions, not on every event.** A run that finds nothing is a silent
   success. Jobs only notify when something needs a human.
2. **De-duplicate.** Stateful jobs remember what they have already reported
   (`state\*.json`), so an alert is sent once, not once per run.
3. **Require corroboration before declaring failure.** A device is not "down" after one
   missed ping; it takes N consecutive failed runs. The same principle gates lockout and
   spray detection behind count thresholds.
4. **Keep secrets out of scripts and configuration.** `config.json` holds settings only.
   Credentials come from SecretManagement into process memory at run time.
5. **Log every run.** Every job writes to `logs\`, so output doubles as ITGC audit
   evidence.

**Read-only by default.** Twelve of the thirteen files only read data. There are exactly
two deliberate exceptions, both of which should be piloted first:

- `Remediate-Baseline.ps1` changes device settings.
- `sophos_isolate.py` isolates a host.

---

## Repository layout

```
scripts/
├── powershell/
│   ├── Get-EndpointBaseline.ps1        Intune Remediation detection script
│   ├── Get-IntuneCompliance.ps1        Daily Intune compliance report
│   ├── Get-LogonSecurityEvents.ps1     Daily AD logon security report
│   ├── Remediate-Baseline.ps1          Intune Remediation remediation script
│   └── Run-Job.ps1                     Wrapper that runs any Python job
└── python/
    ├── daily_digest.py                 Morning digest of all summaries
    ├── entity_common.py                Shared helpers (not run directly)
    ├── network_monitor.py              ICMP / TCP availability monitor
    ├── sophos_alert_collector.py       Sophos Central alert forwarding
    ├── sophos_common.py                Sophos Central API client (not run directly)
    ├── sophos_endpoint_health.py       Endpoint health reporting
    ├── sophos_fw_auth_parser.py        Firewall syslog logon analysis
    └── sophos_isolate.py               On-demand host isolation
```

The subfolders are a source-control convention only. The two shared Python modules must
sit in the **same directory** as the scripts that import them, and `Run-Job.ps1` resolves
scripts from a flat folder, so deploy by flattening — see [Installation](#installation).

> **Note on `entity_common.py`** — the module name uses an underscore because Python
> cannot import a module whose filename contains a hyphen. Every script imports it as
> `from entity_common import ...`.

---

## Runtime folder layout

The automation host runs from a fixed root. `SECOPS_HOME` overrides the default if needed.

```
C:\SecOps\
    config\     config.json, disabled_users.txt
    scripts\    all .ps1 and .py files
    venv\       Python virtual environment
    state\      created automatically: de-duplication and counters
    out\        created automatically: CSV reports and *.summary.json
    logs\       created automatically: one log per script
```

`state\`, `out\` and `logs\` are created on first import of `entity_common`, so there is
nothing to create by hand.

---

## Prerequisites

| Requirement | Detail |
| --- | --- |
| Automation host | Domain-joined Windows Server 2019/2022, or a dedicated hardened admin VM. 2 vCPU, 4 GB RAM, patched and covered by Sophos. Treat it as a privileged system. |
| PowerShell | 7.4 or later |
| Python | 3.11 or later |
| PowerShell modules | `Microsoft.Graph.Authentication`, `Microsoft.PowerShell.SecretManagement`, `Microsoft.PowerShell.SecretStore` |
| Outbound HTTPS 443 | `graph.microsoft.com`, `login.microsoftonline.com`, `id.sophos.com`, `api.central.sophos.com`, your Sophos data-region host, and the Teams Workflows webhook host |
| Internal access | RPC/Event Log access to the domain controllers, syslog from the firewall to a collector, ICMP/TCP to monitored devices |
| Service account | A dedicated account such as `svc-secops`, with "Log on as a batch job" on the host, no interactive logon, password in the privileged access vault |
| People and roles | Entra: Application Administrator plus someone who can grant admin consent. Sophos Central: Super Admin to create API credentials. Intune: read access for verification. Firewall: administrator. AD: rights to add the service account to Event Log Readers. |

---

## Installation

Run once in an **elevated PowerShell 7** session on the automation host. Replace
`YOURDOMAIN` with the real domain.

```powershell
# 1. Create the folder structure
New-Item -ItemType Directory -Force -Path C:\SecOps\config, C:\SecOps\scripts,
    C:\SecOps\state, C:\SecOps\out, C:\SecOps\logs | Out-Null

# 2. Install the PowerShell modules
Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force
Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore `
    -Scope AllUsers -Force

# 3. Build an isolated Python environment so jobs never depend on a system Python
py -3.11 -m venv C:\SecOps\venv
C:\SecOps\venv\Scripts\python.exe -m pip install --upgrade pip requests

# 4. Deploy the scripts from this repository (flatten the subfolders)
Copy-Item .\scripts\python\*.py    C:\SecOps\scripts\
Copy-Item .\scripts\powershell\*.ps1 C:\SecOps\scripts\

# 5. Restrict the folder: SYSTEM, administrators and the service account only
icacls C:\SecOps /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" `
    "YOURDOMAIN\svc-secops:(OI)(CI)M"
```

`requests` is the only third-party Python dependency. Everything else is in the standard
library.

---

## Connecting to the environment

### Microsoft Graph and Intune

The PowerShell reports authenticate as an **application** using a certificate. This
avoids storing a client secret and works unattended.

1. In the Entra admin center go to **Identity → Applications → App registrations → New
   registration**. Name it `Entity-SecOps-Automation`, choose single tenant, leave the
   redirect URI empty. Record the Application (client) ID and Directory (tenant) ID.
2. **API permissions → Add a permission → Microsoft Graph → Application permissions**.
   Add `DeviceManagementManagedDevices.Read.All` and
   `DeviceManagementConfiguration.Read.All`. Select **Grant admin consent**.
3. On the automation host, create the authentication certificate and note the thumbprint
   it prints (see below).
4. In Entra, open the app → **Certificates & secrets → Certificates → Upload
   certificate**, and upload `C:\SecOps\Entity-SecOps-Automation.cer`.
5. Allow the service account to read the private key: run `certlm.msc`, open **Personal →
   Certificates**, right-click the certificate → **All Tasks → Manage Private Keys**, add
   `svc-secops` with **Read**.
6. Paste the tenant ID, client ID and thumbprint into `config.json`.
7. Test the connection.

```powershell
# Run on the automation host, elevated
$cert = New-SelfSignedCertificate -Subject 'CN=Entity-SecOps-Automation' `
    -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable `
    -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(1)
Export-Certificate -Cert $cert -FilePath C:\SecOps\Entity-SecOps-Automation.cer
$cert.Thumbprint     # copy this value into config.json -> graph.certThumbprint

$thumb = '<thumbprint>'
Connect-MgGraph -ClientId '<client id>' -TenantId '<tenant id>' `
    -Certificate (Get-Item "Cert:\LocalMachine\My\$thumb") -NoWelcome
Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1'
```

A JSON response containing one device confirms the app, permissions and certificate are
all correct.

> **Certificate lifetime.** The certificate above expires after one year. Set a calendar
> reminder 30 days before expiry, create a replacement, upload it to the app
> registration, and update the thumbprint in `config.json`.

### Sophos Central API

1. In Sophos Central Admin go to **Global Settings → API Credentials Management → Add
   Credential**.
2. Name it `secops-readonly` and choose the **read-only** service principal role. This
   credential is used by the alert and health scripts.
3. Copy the Client ID and select **Show Client Secret**. The secret is shown only once —
   store it immediately.
4. To use `sophos_isolate.py`, create a **second** credential with the lowest role that
   permits endpoint isolation in your licence, and keep it separate from the read-only
   one. Only load it when isolating a host.
5. Store the values as secrets for the service account (below).
6. Test with the health script. If authentication works but data is empty, the credential
   was probably created in the wrong tenant.

```powershell
# Run ONCE while signed in as the service account that will run the scheduled tasks
Register-SecretVault -Name SecOps -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Set-SecretStoreConfiguration -Authentication None -Interaction None   # unattended use
Set-Secret -Name SophosClientId     -Secret '<client id>'
Set-Secret -Name SophosClientSecret -Secret '<client secret>'
Set-Secret -Name TeamsWebhookUrl    -Secret '<workflow webhook url>'

C:\SecOps\scripts\Run-Job.ps1 -Script sophos_endpoint_health.py
# Expected: a log line such as "412 endpoints checked, 9 flagged" and a CSV in C:\SecOps\out
```

> **Secret storage options.** The SecretStore vault above is protected by the service
> account profile. For a stronger setup, fetch the same values from Azure Key Vault or the
> enterprise privileged access vault inside `Run-Job.ps1` instead of `Get-Secret`.
> Nothing else in the scripts changes.

### Sophos Firewall logon monitoring (syslog)

The firewall sends logs to a syslog collector, which writes them to a plain text file. The
parser reads **only new lines** on each run, using a byte offset in `state\`.

1. Provision a syslog collector with a fixed IP (a small Linux VM with rsyslog is the
   simplest option). Allow UDP 514, or TCP/TLS if preferred, from the firewall IP only.
2. Configure the collector and restart rsyslog. Add a logrotate rule so the file does not
   grow without limit.
3. In the Sophos Firewall web admin open the log settings (typically **Configure → System
   services → Log settings**; menu names vary slightly between SFOS versions). Add a
   syslog server pointing at the collector, protocol UDP, port 514, format *Device
   standard*, and enable the **Authentication** and **Admin/System** event log categories
   (plus VPN events if you use SSL VPN or IPsec).
4. Make the log file readable by the automation host: either run the parser on the
   collector itself, or share the folder read-only and set `sophos_firewall.log_path` in
   `config.json` to the UNC path.
5. Schedule a **daily** export of disabled AD accounts. The parser uses it to flag logons
   by accounts that should no longer exist.
6. Let some logon events accumulate, then run the **discovery command** and confirm the
   component names match `auth_components` in `config.json`.

```bash
# rsyslog configuration: accept syslog from the firewall IP only
module(load="imudp")
input(type="imudp" port="514")
template(name="rawmsg" type="string" string="%msg%\n")

if $fromhost-ip == '10.0.0.1' then {
    action(type="omfile" file="/var/log/sophos-fw/sophos-fw.log" template="rawmsg")
    stop
}
```

```powershell
# Daily (e.g. 05:30) so the parser can flag logons by disabled accounts
Import-Module ActiveDirectory
Search-ADAccount -AccountDisabled -UsersOnly |
    Select-Object -ExpandProperty SamAccountName |
    Set-Content C:\SecOps\config\disabled_users.txt -Encoding ascii
```

```powershell
# Discovery: list every log_component value with a sample line
C:\SecOps\venv\Scripts\python.exe C:\SecOps\scripts\sophos_fw_auth_parser.py --discover
```

> **Field names are firmware-dependent.** Sophos Firewall logs are `key="value"` pairs, but
> the exact field names for logon events differ between SFOS versions and between firewall,
> VPN and user-portal logons. That is why discovery exists. **Do not schedule the parser
> until the discovery output has been checked against real logons.**

### Domain controllers (logon events)

1. Add `svc-secops` to the **Event Log Readers** group in Active Directory. This grants
   read access to the Security log without administrator rights.
2. On each domain controller, enable the firewall rule group **Remote Event Log
   Management (RPC)**. A group policy on the Domain Controllers OU is cleanest.
3. Confirm the audit policies that generate the events are enabled in the Default Domain
   Controllers Policy: Audit Logon (failure), Audit Account Lockout, Audit Security Group
   Management, Audit User Account Management.
4. Test remote access:

```powershell
Get-WinEvent -ComputerName DC01.yourdomain.local -FilterHashtable @{LogName='Security'; Id=4625} `
    -MaxEvents 1
```

> Failed-logon events (4625) cover domain account authentication handled by that
> controller. Failed sign-ins to Microsoft 365 and Entra-only accounts do **not** appear
> here.

### Teams notifications

1. In Teams, open the channel that should receive alerts (create a dedicated
   `secops-alerts` channel).
2. Open the channel menu → **Workflows** → select the template *Post to a channel when a
   webhook request is received*. Name it, confirm the team and channel, and finish.
3. Copy the webhook URL and store it as the `TeamsWebhookUrl` secret.
4. Send a test message:

```powershell
$body = '{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.4","body":[{"type":"TextBlock","text":"SecOps webhook test"}]}}]}'
Invoke-RestMethod -Uri '<workflow webhook url>' -Method Post -Body $body `
    -ContentType 'application/json'
```

Microsoft has retired the older Office 365 connector webhooks, which is why the Workflows
method is used. For email as well as Teams, set `email.enabled` to `true` in
`config.json` and ensure the SMTP relay accepts mail from the automation host (an Exchange
Online or on-premises relay connector locked to its IP address).

### Intune Remediations (endpoint baseline)

`Get-EndpointBaseline.ps1` and `Remediate-Baseline.ps1` run on the devices themselves
through Intune, so no connection from the automation host is needed. Test the detection
script locally first:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-EndpointBaseline.ps1
$LASTEXITCODE     # 0 = compliant, 1 = issues found
```

Then, in the Intune admin center: **Devices → Scripts and remediations → Remediations →
Create**. Upload the detection script and the remediation script. Set *Run this script
using the logged-on credentials* to **No** (runs as SYSTEM), *Enforce script signature
check* to **No** unless the scripts are signed, and *Run script in 64-bit PowerShell* to
**Yes**. Assign to a pilot group of about 20 devices, schedule daily, and review the
detection output under the remediation's device status before widening the assignment.

> **Licensing.** Remediations require certain Windows and Microsoft 365 licences. Check the
> current requirements in Microsoft's documentation. If unavailable, deploy the baseline
> script as a regular Intune platform script that writes to a file or custom inventory.

---

## Configuration file

Save as `C:\SecOps\config\config.json`. It holds **settings only and no secrets**.
Replace every placeholder with real values. In JSON, backslashes in Windows paths must be
doubled.

```json
{
  "graph": {
    "tenantId": "00000000-0000-0000-0000-000000000000",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "certThumbprint": "PASTE-CERTIFICATE-THUMBPRINT-HERE"
  },
  "email": {
    "enabled": false,
    "smtp_host": "smtp.yourdomain.local",
    "smtp_port": 25,
    "starttls": false,
    "from": "secops-automation@yourdomain.com",
    "to": ["security-team@yourdomain.com"]
  },
  "sophos_alerts": { "min_severity": "medium", "first_run_lookback_hours": 24 },
  "sophos_health": { "stale_days": 7 },
  "sophos_firewall": {
    "log_path": "D:\\SyslogData\\sophos-fw.log",
    "auth_components": ["authentication", "ssl vpn", "ipsec"],
    "failed_threshold": 10,
    "business_hours": [6, 19],
    "disabled_users_file": "C:\\SecOps\\config\\disabled_users.txt"
  },
  "network_monitor": {
    "failures_before_alert": 3,
    "latency_warn_ms": 150,
    "targets": [
      { "name": "Core switch", "host": "10.0.0.2", "checks": ["icmp"] },
      { "name": "Sophos Firewall", "host": "10.0.0.1", "checks": ["icmp"], "tcp": [443] },
      { "name": "Domain controller 1", "host": "10.0.10.10", "checks": ["icmp"], "tcp": [389, 445] },
      { "name": "Microsoft 365", "host": "outlook.office365.com", "checks": [], "tcp": [443] }
    ]
  },
  "digest": { "noncompliant_drift_alert": 10 }
}
```

| Setting | Meaning |
| --- | --- |
| `graph.certThumbprint` | Thumbprint of the app-only authentication certificate in `Cert:\LocalMachine\My`. |
| `email.enabled` | When `false`, `notify_email` is a no-op. |
| `sophos_alerts.min_severity` | Lowest severity forwarded: `low`, `medium` or `high`. Start at `medium`. |
| `sophos_alerts.first_run_lookback_hours` | How far back the very first run searches. |
| `sophos_health.stale_days` | Flag endpoints not seen by Sophos Central for this many days. |
| `sophos_firewall.auth_components` | Substrings matched against `log_component` to select logon events. Set from the discovery output. |
| `sophos_firewall.failed_threshold` | Failed logons by one user in one run that triggers an alert. |
| `sophos_firewall.business_hours` | Start and end hour (24h). Successful logons outside this window, or at weekends, are reported. |
| `network_monitor.failures_before_alert` | Consecutive failed runs before a device is declared down. At a 5-minute schedule, 3 means 15 minutes. |
| `network_monitor.latency_warn_ms` | Latency above this value is logged as a warning. |
| `digest.noncompliant_drift_alert` | Rise in non-compliant devices versus the previous run that marks the digest line `ATTENTION`. |

---

## Script reference

### Shared libraries

These two modules are imported by other scripts and are never run directly.

#### `python/entity_common.py`

Shared helpers: loads `config.json`, writes per-script logs, keeps de-duplication state,
writes summary files, and sends Teams and SMTP notifications.

| Function | Behaviour |
| --- | --- |
| `BASE` | Root directory, from the `SECOPS_HOME` environment variable or `C:\SecOps`. Importing the module creates `state\`, `out\` and `logs\`. |
| `load_config()` | Reads `config\config.json` as UTF-8 with optional BOM. |
| `get_logger(name)` | Returns a logger writing to `logs\<name>.log` **and** stdout. Safe to call repeatedly — handlers are attached once. |
| `need_env(name)` | Reads a required environment variable or exits with a clear message. This is how secrets reach the Python jobs. |
| `load_state(name, default)` / `save_state(name, data)` | Read and write `state\<name>.json`. Writes go to a `.tmp` file first and are then atomically renamed, so an interrupted run cannot corrupt state. |
| `write_summary(name, data)` | Writes `out\<name>.summary.json` and stamps `generated_utc`. The digest reads these. |
| `notify_teams(title, lines)` | Posts an Adaptive Card to the `TEAMS_WEBHOOK_URL` webhook. Returns `False` when the variable is unset, so notification is optional. Caps the card at 25 lines. |
| `notify_email(subject, text)` | Sends via SMTP **only** when `email.enabled` is true. Authenticates if `SMTP_USER` is set. |

#### `python/sophos_common.py`

The `SophosCentral` class: OAuth2 client-credentials authentication, regional API
discovery, token refresh, rate-limit backoff and pagination.

| Member | Behaviour |
| --- | --- |
| `__init__` | Requires `SOPHOS_CLIENT_ID` and `SOPHOS_CLIENT_SECRET`, then authenticates. |
| `_authenticate()` | Posts to `id.sophos.com`, then calls `whoami` to discover the tenant ID and the regional data host. **Fails fast** if the credential is not tenant-level, and sets the `X-Tenant-ID` header. |
| `request(method, path, **kw)` | Re-authenticates automatically when the token is within 60s of expiry. Retries up to 4 times on HTTP 429, honouring `Retry-After` with exponential fallback. Raises on any other error status. |
| `paged(method, path, params, body)` | Generator over a paginated endpoint, following `pages.nextKey` for both GET and POST. |

### PowerShell jobs

#### `powershell/Get-IntuneCompliance.ps1`

Daily Intune compliance, stale-device and OS-version report via app-only Microsoft Graph.

| | |
| --- | --- |
| **Reads from** | Microsoft Graph `/deviceManagement/managedDevices` |
| **Schedule** | Daily 06:00 |
| **Parameters** | `-ConfigPath`, `-OutDir`, `-StaleDays` (default 14) |
| **Auth** | Certificate from `config.json → graph.certThumbprint`. Falls back to `Cert:\CurrentUser\My` if not in `LocalMachine\My`. |
| **Logging** | Transcript to `logs\intune_compliance_<date>.log` |

**What it does**

1. Pages through managed devices with a `$select` of the 11 fields that matter, 200 per
   request, following `@odata.nextLink`.
2. Computes `DaysSinceSync` per device. A device that has never synced is treated as
   `2000-01-01` so it always trips the stale check.
3. For each non-compliant device, makes a second call to `deviceCompliancePolicyStates`
   to name the exact failing policies, with a 200 ms pause between calls to stay inside
   Graph throttling limits. Failures degrade to `lookup failed` rather than aborting.
4. Reads the previous `noncompliant` count from the existing summary so the digest can
   report drift.

**Outputs** — `out\intune_all_devices_<date>.csv`,
`out\intune_noncompliant_<date>.csv`, `out\intune_stale_<date>.csv`,
`out\intune_compliance.summary.json` (total, compliant, noncompliant, stale,
previous_noncompliant, os_versions, generated_utc).

---

#### `powershell/Get-EndpointBaseline.ps1`

Local security baseline check. Deployed as the **Intune Remediation detection script**, or
run ad hoc as administrator.

| | |
| --- | --- |
| **Runs on** | Each endpoint |
| **Schedule** | Daily, on device, via Intune Remediations |
| **Exit code** | `0` = compliant, `1` = issues found (this is what triggers remediation) |

**Checks performed**

| Check | Failure condition |
| --- | --- |
| BitLocker | `ProtectionStatus` is not `On` on the system drive |
| Windows Firewall | Any profile with `Enabled = false` |
| Sophos services | Any required service missing or not running |
| SMBv1 | `EnableSMB1Protocol` is true on the server |
| RDP | `fDenyTSConnections = 0` — **remove this check if RDP is permitted** |
| Local administrators | Any member not in `$approvedAdmins` |
| Disk space | Less than 10 GB free |
| Uptime | Not rebooted for more than 30 days |

**Before use — requires editing**

- `# EDIT` `$approvedAdmins` must list your real local admin accounts.
- `# VERIFY` `$requiredServices` must match the actual Sophos display names. Confirm with
  `Get-Service -DisplayName 'Sophos*'` on a healthy device.

`Get-LocalGroupMember` fails on Entra-joined devices with orphaned SIDs, so the script
falls back to parsing `net localgroup Administrators`.

Output is a single line: `COMPLIANT`, or `NONCOMPLIANT: <issue> | <issue> ...`.

---

#### `powershell/Remediate-Baseline.ps1`

Remediation script paired with `Get-EndpointBaseline.ps1`. **This one changes device
state.** Runs as SYSTEM through Intune Remediations. Always exits `0`.

| Action | Condition |
| --- | --- |
| Enable the firewall profile | Profile was disabled |
| Disable SMBv1 server | `EnableSMB1Protocol` was true |
| Start the service | Sophos service exists, is not disabled, and is not running |
| Resume BitLocker | Volume is `FullyEncrypted` but protection is not `On` |

**Deliberately not remediated:** local administrators are never removed, RDP is never
disabled, and no disk cleanup or reboot is triggered. Those are judgement calls that
should stay with a human. BitLocker failures are caught and logged rather than raised, so
a partially remediated device still reports success.

---

#### `powershell/Get-LogonSecurityEvents.ps1`

Summarises failed logons, lockouts and privileged-group changes from the domain
controllers.

| | |
| --- | --- |
| **Reads from** | Security log on each DC: **4625** failed logon, **4740** lockout, **4728 / 4732 / 4756** member added to a security group |
| **Schedule** | Daily 06:30 |
| **Parameters** | `-DomainControllers` (**EDIT**), `-LookbackHours` (24), `-FailedThreshold` (10), `-PrivilegedGroups`, `-OutDir` |
| **Access** | Event Log Readers group + Remote Event Log Management firewall rules |
| **Logging** | Transcript to `logs\logon_events_<date>.log` |

**Detections**

- **Brute force** — one account with failed logons at or above `-FailedThreshold`,
  reported with the distinct source IPs.
- **Password spray** — one source IP failing against 5 or more distinct accounts.
- **Lockouts** — every 4740, with the originating computer.
- **Privileged group changes** — additions to Domain Admins, Enterprise Admins, Schema
  Admins or Administrators, with who made the change.

Events are parsed from XML `EventData` rather than by message text, so the script is not
affected by localised event messages. A DC that cannot be queried produces a warning and
is skipped; an empty result set is not an error.

**Outputs** — `out\logon_bruteforce_<date>.csv`, `out\logon_spray_<date>.csv`,
`out\logon_lockouts_<date>.csv`, `out\logon_groupchanges_<date>.csv` (only the non-empty
ones are written), and `out\logon_events.summary.json`.

---

#### `powershell/Run-Job.ps1`

Wrapper for every Python job. It exists so secrets never have to live in a scheduled task
definition or in the Python source.

| | |
| --- | --- |
| **Usage** | `Run-Job.ps1 -Script <file.py> [arguments]` |
| **Schedule** | n/a — invoked by the Python task definitions |

Loads `SophosClientId`, `SophosClientSecret` and `TeamsWebhookUrl` from SecretManagement
**into this process's environment only**, then runs the target script with
`C:\SecOps\venv\Scripts\python.exe` and propagates the Python exit code to the caller.
Any extra arguments after `-Script` are passed straight through to the Python script.

```powershell
C:\SecOps\scripts\Run-Job.ps1 -Script sophos_alert_collector.py
```

Two lines are commented out by default and should be uncommented only if
`email.enabled` is true and the relay needs SMTP authentication.

> This script resolves paths against a flat `C:\SecOps\scripts` directory. That is why
> [Installation](#installation) copies the repository's `python` and `powershell`
> subfolders into a single folder on the host.

### Python jobs

#### `python/sophos_alert_collector.py`

Pulls new Sophos Central alerts, de-duplicates them, and forwards them to Teams and email.

| | |
| --- | --- |
| **Reads from** | Sophos Central `POST /common/v1/alerts/search` |
| **Schedule** | Every 10 minutes |
| **Secrets** | `SOPHOS_CLIENT_ID`, `SOPHOS_CLIENT_SECRET`, `TEAMS_WEBHOOK_URL` |
| **Config** | `sophos_alerts.min_severity`, `sophos_alerts.first_run_lookback_hours` |
| **State** | `state\sophos_alerts.json` |

**How de-duplication works.** Each run searches from the last successful run **minus a
15-minute overlap**, so nothing is lost if a run is late or a timestamp is skewed. The
overlap produces repeats, which are removed by tracking seen alert IDs in state. Seen IDs
older than 7 days are pruned on every run to keep the state file small.

**Failure semantics.** State is saved **only after** `notify_teams` and `notify_email`
succeed. If a notification fails, the exception propagates and the next run re-sends
rather than silently dropping alerts.

Alerts are sorted by severity so the most serious appear first in the card. Output is
`out\sophos_alerts.summary.json` with `fetched`, `new` and `high` counts.

---

#### `python/sophos_endpoint_health.py`

Reports Sophos-protected endpoints that need attention.

| | |
| --- | --- |
| **Reads from** | Sophos Central `GET /endpoint/v1/endpoints` (500 per page) |
| **Schedule** | Daily 06:15 |
| **Config** | `sophos_health.stale_days` (7) |

**Flags an endpoint when:**

- its overall health is `bad` or `suspicious`;
- tamper protection is explicitly disabled; or
- it has not checked in for longer than `stale_days`.

**Outputs** — `out\sophos_endpoint_health_<date>.csv` with columns `hostname`, `os`,
`last_seen`, `issues`; and `out\sophos_health.summary.json`. The Teams notification is
capped at 15 lines with an explicit "...and N more (see <file>)" line, so a large backlog
does not produce an unreadable card or hit card size limits.

This is also the fastest way to verify Sophos connectivity during setup.

---

#### `python/sophos_isolate.py`

Isolates or releases one endpoint by hostname. **This one changes endpoint state.**

| | |
| --- | --- |
| **Reads/writes** | Sophos Central `GET /endpoint/v1/endpoints`, `POST /endpoint/v1/endpoints/{id}/isolation` |
| **Schedule** | On demand |
| **Credential** | A **separate** write-capable Sophos credential, not the read-only one |

```
sophos_isolate.py <hostname> [--release] [--reason "Security investigation"] [--confirm]
```

Three deliberate safety properties:

1. **Dry run by default.** Without `--confirm` the script prints exactly what it would do
   and exits.
2. **Exact match required.** A substring search is used to find candidates, but the
   hostname must then match exactly. Anything other than exactly one match is an error, so
   a partial name can never isolate the wrong host.
3. **Reversible.** The same command with `--release` lifts isolation.

---

#### `python/sophos_fw_auth_parser.py`

Parses Sophos Firewall syslog for logon anomalies.

| | |
| --- | --- |
| **Reads from** | A plain text syslog file (`sophos_firewall.log_path`) |
| **Schedule** | Every 15 minutes |
| **State** | `state\sophos_fw.json` — a single byte offset |

**Incremental reading.** Each run seeks to the stored offset, reads only new bytes, then
truncates the chunk back to the last newline so a half-written line is never parsed. The
next offset advances only by the bytes actually consumed, so nothing is skipped. If the
file is **smaller** than the stored offset, the log has rotated and the parser restarts
from zero.

**Parsing.** A single regex extracts `key="value"` and `key=value` pairs. `norm()`
normalises `DOMAIN\user` and `user@domain` to a bare lowercase name, which is what allows
one identity to be matched against the disabled-accounts file.

**Detections**

| Detection | Threshold |
| --- | --- |
| Repeated failed logons by one user | `sophos_firewall.failed_threshold` (10) in one run |
| Password spray from one source IP | 5 or more distinct accounts |
| Logon by a disabled account | Any — reads `disabled_users.txt` |
| Off-hours successful logon | Outside `business_hours`, or at a weekend |

**Discovery mode.** Run `--discover` first. It counts every `log_component` value in the
file and prints one sample line per component, which is how you set `auth_components`
correctly for your firmware. **Do not schedule this script before doing that.**

---

#### `python/network_monitor.py`

ICMP and TCP availability monitor that alerts only after N consecutive failures.

| | |
| --- | --- |
| **Checks** | ICMP ping (3 packets) and TCP connect (3s timeout) per target |
| **Schedule** | Every 5 minutes |
| **Config** | `network_monitor.targets`, `failures_before_alert`, `latency_warn_ms` |
| **State** | `state\network_monitor.json` — a fail counter and an alerted flag per check |

All targets are checked **concurrently** through a 20-worker thread pool, so a slow or
unreachable host cannot delay the rest. `ping` is invoked with the correct flag for the
platform (`-n` on Windows, `-c` elsewhere) and round-trip times are parsed from the
output, so no third-party dependency is needed.

**Why it does not spam.** A single missed ping means nothing, so a device must fail
`failures_before_alert` runs in a row before an alert is sent. The `alerted` flag then
suppresses repeats until the device recovers — at which point one `RECOVERED` line is
emitted. A device flapping produces one alert and one recovery, not a stream of both.
Latency above `latency_warn_ms` is logged as a warning but is not an alert.

**Scope.** This covers availability and latency only. For SNMP interface counters,
bandwidth trending, NetFlow top-talkers and Wi-Fi health, use a monitoring platform such
as PRTG, Zabbix or LibreNMS and feed its alerts into the same Teams channel. Start with
20 to 30 critical targets and add more once alert volume is understood.

---

#### `python/daily_digest.py`

Combines the summary file written by every job into one morning digest.

| | |
| --- | --- |
| **Reads from** | The six `out\*.summary.json` files |
| **Schedule** | Daily 07:30 |
| **Config** | `digest.noncompliant_drift_alert` (10) |

**How to read the output**

- Lines are prefixed **`ATTENTION`** when a source needs a human: compliance drift at or
  above the configured threshold, any privileged group change or brute-force user, any
  logon by a disabled account, or any failing network check.
- Lines are suffixed **`[STALE - job may be failing]`** when the summary is older than 26
  hours — which means the job that produced it has not run, so its "all clear" is not
  trustworthy.
- A source that has never produced a summary reads **`NO DATA - job has never run`**.
- Lines are sorted so everything needing attention is at the top.
- The `previous_noncompliant` value in the Intune summary is what makes the `(+N vs
  previous run)` drift figure possible.

The digest reads PowerShell-written JSON with `utf-8-sig`, because
`Set-Content -Encoding utf8` in Windows PowerShell adds a BOM. This is also why missing
sources degrade to a visible `NO DATA` line instead of crashing the digest.

---

## Scheduling

Register each job as a scheduled task running as the service account. Sophos alerts and
network checks run frequently; the reports run in the early morning so the 07:30 digest
reflects fresh data.

| Task | Frequency | Job |
| --- | --- | --- |
| SecOps-NetworkMonitor | Every 5 minutes | `Run-Job.ps1 -Script network_monitor.py` |
| SecOps-SophosAlerts | Every 10 minutes | `Run-Job.ps1 -Script sophos_alert_collector.py` |
| SecOps-SophosFirewallParser | Every 15 minutes | `Run-Job.ps1 -Script sophos_fw_auth_parser.py` |
| SecOps-IntuneCompliance | Daily 06:00 | `Get-IntuneCompliance.ps1` |
| SecOps-SophosHealth | Daily 06:15 | `Run-Job.ps1 -Script sophos_endpoint_health.py` |
| SecOps-LogonEvents | Daily 06:30 | `Get-LogonSecurityEvents.ps1` |
| SecOps-DailyDigest | Daily 07:30 | `Run-Job.ps1 -Script daily_digest.py` |

Two useful properties of this design: tasks must **not** be allowed to overlap (a slow run
must not start a second copy), and a task that fails should still leave valid state behind
so the next run recovers cleanly. The Python jobs are safe to re-run because every state
write is atomic.

A weekly retention task keeps the folder from growing without limit:

```powershell
# Remove reports and logs older than 90 days (adjust to your retention policy)
```

---

## Security and operations

- **Least privilege.** The service account needs Event Log Readers on the DCs, read on the
  certificate private key, and nothing else. It does not need administrator rights.
- **Secrets never touch disk.** Credentials live in SecretStore and are injected into
  process memory by `Run-Job.ps1` for the lifetime of that process only.
- **No client secrets for Graph.** Certificate-based app-only authentication means there
  is no password to leak or rotate under pressure.
- **The write-capable Sophos credential is separate** from the read-only one, so a
  compromised alert-collector run cannot isolate hosts.
- **Personal data.** Logs contain user names, device names and IP addresses. Restrict
  access to the `C:\SecOps` folder and the Teams channel, and apply the organisation's
  retention policy and applicable data protection law.
- **Audit evidence.** Every run is logged, so the output of these jobs can serve as ITGC
  evidence.

### Required access matrix

| System | Permission | Where |
| --- | --- | --- |
| Microsoft Graph / Intune | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` (application) | Entra admin center, API permissions, admin consent |
| Sophos Central | Read-only service principal role | Sophos Central Admin, API Credentials Management |
| Sophos Central | Isolation-capable role (**separate credential**) | Sophos Central Admin |
| Active Directory | Event Log Readers; permission to read `Search-ADAccount` results | AD group membership |
| Domain controllers | Remote Event Log Management (RPC) | Firewall rule group on each DC |
| Syslog collector | Read access to the log file, or run the parser locally | File share or local access |
| Network devices | ICMP and TCP to monitored ports | Firewall / ACL |

---

## Testing and rollout

These scripts were written against the documented behaviour of Microsoft Graph, the Sophos
Central API and Sophos Firewall syslog, but **they have not been run against a production
tenant**. Items that depend on your environment — Sophos service names, firewall log field
names, group names — are marked `EDIT` or `VERIFY` in the code.

1. **Fix every `EDIT` and `VERIFY` marker** before anything else. In particular
   `Get-LogonSecurityEvents.ps1` ships with placeholder domain controllers.
2. **Run the discovery step** for the firewall parser and set `auth_components` from real
   output.
3. **Test each job manually** as the service account and check the log, the CSV and the
   summary file before scheduling anything.
4. **Point notification at a test channel** and confirm the Adaptive Card renders.
5. **Pilot the two write-capable scripts last.** `Get-EndpointBaseline.ps1` on ~20 devices
   as an Intune Remediation, reviewing detection output before widening the assignment.
   `sophos_isolate.py` on a single test endpoint — both isolate and release.
6. **Then widen** the network monitor target list and the Intune assignment.

Do not schedule the firewall parser, the Intune Remediation, or `sophos_isolate.py` before
their pilot step is complete.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `Missing environment variable: SOPHOS_CLIENT_ID` | The job was not started through `Run-Job.ps1`, so no secrets were injected. |
| `Credentials are not tenant-level` | The API credential was created outside the tenant. Recreate it inside the correct Sophos Central tenant. |
| Sophos authentication works but data is empty | Usually the wrong tenant. Confirm with the `whoami` response. |
| HTTP 429 persists | The API is throttling. The client already retries four times; reduce the alert collector frequency. |
| `A JSON response containing one device` never arrives | App registration, admin consent or certificate thumbprint. Work through the Graph test in the setup section. |
| Intune report is empty | No managed devices match, or `$select` fields were trimmed. Check the transcript log. |
| Domain controller query fails | Add the service account to Event Log Readers **and** enable Remote Event Log Management (RPC) on the DC. |
| `No events were found` | Suppressed by design — it is a warning-free empty result, not a failure. |
| Firewall parser reports 0 events | Run `--discover`. Either `auth_components` does not match, or `log_path` points at the wrong file. |
| Firewall parser re-reads the whole file | The log rotated (file shrank); the offset resets to zero by design. Check the logrotate rule. |
| Network monitor alerts on a single blip | Lower `failures_before_alert` only after confirming the target is genuinely healthy; a raised value hides real outages. |
| Digest shows `NO DATA` | That job has never completed successfully. Run it manually and read its log. |
| Digest shows `[STALE - job may be failing]` | The source job has not run in 26 hours. Check its scheduled task. |
| Teams card is truncated | Expected above 25 lines. Details are in the CSV in `out\`. |
| `ModuleNotFoundError: requests` | The job ran under a system Python. Use `Run-Job.ps1`, which uses `C:\SecOps\venv\Scripts\python.exe`. |
| `ModuleNotFoundError: entity_common` | The shared modules are not in the same folder as the importing script. Both shared `.py` files must sit alongside the jobs. |

---

## Future enhancements

- **Entra sign-in logs.** Failed sign-ins to Microsoft 365 and Entra-only accounts never
  appear in the DC Security log. Microsoft Graph `/beta/security` risk detections and
  Entra audit logs would close that gap.
- **SNMP and flow data.** Interface counters, bandwidth trending and NetFlow top-talkers
  are out of scope for the availability monitor and belong in a dedicated platform.
- **Certificate expiry alerting.** Automate the 30-day reminder described in the setup
  section rather than relying on a calendar entry.
- **Alternate secret backends.** Azure Key Vault or the enterprise privileged access
  vault can be substituted inside `Run-Job.ps1` with no change to any other script.
