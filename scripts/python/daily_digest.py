"""Combine the summary file written by every job into one morning digest."""
import json
from datetime import datetime, timedelta, timezone

from entity_common import BASE, get_logger, load_config, notify_email, notify_teams

log = get_logger("daily_digest")
MAX_AGE = timedelta(hours=26)


def load(name):
    path = BASE / "out" / f"{name}.summary.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))   # PowerShell may add a BOM


def stale_flag(data):
    ts = datetime.fromisoformat(data["generated_utc"])
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return "  [STALE - job may be failing]" if datetime.now(timezone.utc) - ts > MAX_AGE else ""


def fmt_intune(d, drift):
    prev = d.get("previous_noncompliant")
    prev = d["noncompliant"] if prev is None else prev
    delta = d["noncompliant"] - prev
    line = (f"Intune: {d['total']} devices, {d['noncompliant']} non-compliant "
            f"({delta:+d} vs previous run), {d['stale']} not synced in {d['stale_days']}+ days")
    return ("ATTENTION " if delta >= drift else "") + line


def fmt_alerts(d):
    return f"Sophos alerts: last run fetched {d['fetched']}, {d['new']} new ({d['high']} high)"


def fmt_health(d):
    return f"Sophos endpoints: {d['total']} total, {d['flagged']} need attention"


def fmt_network(d):
    if not d["failing"]:
        return f"Network: {d['checks']} checks, all passing"
    return (f"ATTENTION Network: {len(d['failing'])} failing - "
            + ", ".join(d["failing"][:5]))


def fmt_logons(d):
    flag = "ATTENTION " if d["privileged_group_changes"] or d["brute_force_users"] else ""
    return (f"{flag}AD logons ({d['window_hours']}h): {d['failed_logons']} failed, "
            f"{d['lockouts']} lockouts, {d['brute_force_users']} brute-force users, "
            f"{d['spray_ips']} spray IPs, {d['privileged_group_changes']} privileged group changes")


def fmt_fw(d):
    flag = "ATTENTION " if d["disabled_user_logons"] else ""
    return (f"{flag}Sophos Firewall logons: {d['events']} events, {d['failed']} failed, "
            f"{d['offhours']} off-hours, {d['disabled_user_logons']} by disabled accounts")


def main():
    drift = load_config().get("digest", {}).get("noncompliant_drift_alert", 10)
    sources = [("intune_compliance", lambda d: fmt_intune(d, drift)),
               ("sophos_alerts", fmt_alerts), ("sophos_health", fmt_health),
               ("network_monitor", fmt_network), ("logon_events", fmt_logons),
               ("sophos_fw_auth", fmt_fw)]
    lines = []
    for name, fn in sources:
        data = load(name)
        lines.append(f"{name}: NO DATA - job has never run" if data is None
                     else fn(data) + stale_flag(data))
    lines.sort(key=lambda s: not (s.startswith("ATTENTION") or "NO DATA" in s or "STALE" in s))
    title = f"Security digest - {datetime.now():%d %b %Y}"
    notify_teams(title, lines)
    notify_email(title, "\n".join(lines))
    log.info("Digest sent:\n%s", "\n".join(lines))


if __name__ == "__main__":
    main()
