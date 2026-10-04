"""Pull new Sophos Central alerts, de-duplicate them and forward to Teams/email."""
from datetime import datetime, timedelta, timezone

from entity_common import (get_logger, load_config, load_state, save_state,
                        notify_teams, notify_email, write_summary)
from sophos_common import SophosCentral

log = get_logger("sophos_alerts")
SEV_RANK = {"low": 1, "medium": 2, "high": 3}
FMT = "%Y-%m-%dT%H:%M:%S.000Z"


def main():
    cfg = load_config()["sophos_alerts"]
    min_rank = SEV_RANK[cfg.get("min_severity", "medium")]
    state = load_state("sophos_alerts", {"seen": {}, "last_run": None})

    now = datetime.now(timezone.utc)
    if state["last_run"]:
        last = datetime.strptime(state["last_run"], FMT).replace(tzinfo=timezone.utc)
        since = last - timedelta(minutes=15)      # overlap; de-dupe handles repeats
    else:
        since = now - timedelta(hours=cfg.get("first_run_lookback_hours", 24))

    api = SophosCentral()
    alerts = list(api.paged("POST", "/common/v1/alerts/search",
                            body={"from": since.strftime(FMT), "pageSize": 100}))
    new = [a for a in alerts
           if a["id"] not in state["seen"]
           and SEV_RANK.get(a.get("severity", "low"), 1) >= min_rank]
    new.sort(key=lambda a: SEV_RANK.get(a.get("severity", "low"), 1), reverse=True)
    log.info("Fetched %d alerts, %d new at or above threshold", len(alerts), len(new))

    if new:
        lines = []
        for a in new:
            host = (a.get("managedAgent") or {}).get("name", "n/a")
            lines.append(f"[{a.get('severity', '?').upper()}] {host}: "
                         f"{a.get('description', '')} ({a.get('raisedAt', '')})")
        title = f"Sophos Central: {len(new)} new alert(s)"
        notify_teams(title, lines)
        notify_email(title, "\n".join(lines))

    # Only update state after notifications succeed, so a failed send is retried.
    for a in new:
        state["seen"][a["id"]] = a.get("raisedAt", "")
    cutoff = (now - timedelta(days=7)).strftime(FMT)
    state["seen"] = {k: v for k, v in state["seen"].items() if v >= cutoff}
    state["last_run"] = now.strftime(FMT)
    save_state("sophos_alerts", state)
    write_summary("sophos_alerts", {
        "fetched": len(alerts), "new": len(new),
        "high": sum(1 for a in new if a.get("severity") == "high")})


if __name__ == "__main__":
    main()
