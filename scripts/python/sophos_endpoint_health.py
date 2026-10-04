"""Report Sophos-protected endpoints that need attention (health, tamper, last seen)."""
import csv
from datetime import datetime, timedelta, timezone

from entity_common import BASE, get_logger, load_config, notify_teams, write_summary
from sophos_common import SophosCentral

log = get_logger("sophos_health")


def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def main():
    cfg = load_config()["sophos_health"]
    stale_after = timedelta(days=cfg.get("stale_days", 7))
    now = datetime.now(timezone.utc)

    api = SophosCentral()
    endpoints = list(api.paged("GET", "/endpoint/v1/endpoints", params={"pageSize": 500}))
    findings = []
    for e in endpoints:
        issues = []
        overall = (e.get("health") or {}).get("overall")
        if overall in ("bad", "suspicious"):
            issues.append(f"health={overall}")
        if e.get("tamperProtectionEnabled") is False:
            issues.append("tamper protection off")
        last_seen = parse_ts(e.get("lastSeenAt"))
        if last_seen and now - last_seen > stale_after:
            issues.append(f"not seen for {(now - last_seen).days} days")
        if issues:
            findings.append({"hostname": e.get("hostname"),
                             "os": (e.get("os") or {}).get("name", ""),
                             "last_seen": e.get("lastSeenAt", ""),
                             "issues": "; ".join(issues)})

    out = BASE / "out" / f"sophos_endpoint_health_{now:%Y%m%d}.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["hostname", "os", "last_seen", "issues"])
        w.writeheader()
        w.writerows(findings)
    log.info("%d endpoints checked, %d flagged. Report: %s", len(endpoints), len(findings), out)

    if findings:
        lines = [f"{x['hostname']}: {x['issues']}" for x in findings[:15]]
        if len(findings) > 15:
            lines.append(f"...and {len(findings) - 15} more (see {out.name})")
        notify_teams(f"Sophos endpoint health: {len(findings)} need attention", lines)
    write_summary("sophos_health", {"total": len(endpoints), "flagged": len(findings)})


if __name__ == "__main__":
    main()
