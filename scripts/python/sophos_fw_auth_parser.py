"""Parse Sophos Firewall syslog (key="value" format) for logon anomalies.

Run with --discover first to confirm which log_component values your firewall emits.
"""
import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from entity_common import (get_logger, load_config, load_state, save_state,
                        notify_teams, write_summary)

log = get_logger("sophos_fw_auth")
KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse(line):
    return {k: (q or u) for k, q, u in KV.findall(line)}


def norm(user):
    """DOMAIN\\user and user@domain both become 'user'."""
    return (user or "").lower().split("\\")[-1].split("@")[0]


def event_time(d):
    try:
        return datetime.strptime(f"{d['date']} {d['time']}", "%Y-%m-%d %H:%M:%S")
    except (KeyError, ValueError):
        return None


def discover(path):
    comps, sample = Counter(), {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            c = parse(line).get("log_component", "(none)")
            comps[c] += 1
            sample.setdefault(c, line.strip()[:400])
    for c, n in comps.most_common():
        print(f"{n:8d}  {c}\n          e.g. {sample[c]}\n")


def main():
    cfg = load_config()["sophos_firewall"]
    path = Path(cfg["log_path"])
    state = load_state("sophos_fw", {"offset": 0})
    size = path.stat().st_size
    offset = state["offset"] if state["offset"] <= size else 0   # 0 = log rotated
    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read()
    chunk = chunk[: chunk.rfind(b"\n") + 1]                      # ignore partial last line
    new_offset = offset + len(chunk)

    comps = [c.lower() for c in cfg.get("auth_components",
                                        ["authentication", "ssl vpn", "ipsec"])]
    disabled = set()
    if cfg.get("disabled_users_file") and Path(cfg["disabled_users_file"]).exists():
        text = Path(cfg["disabled_users_file"]).read_text(encoding="utf-8-sig")
        disabled = {norm(x) for x in text.split()}

    start_h, end_h = cfg.get("business_hours", [6, 19])
    fails_by_user, users_by_ip = Counter(), defaultdict(set)
    offhours, disabled_hits, total, failed = [], [], 0, 0

    for line in chunk.decode("utf-8", errors="replace").splitlines():
        d = parse(line)
        if not any(c in d.get("log_component", "").lower() for c in comps):
            continue
        user = norm(d.get("user_name") or d.get("user"))
        ip = d.get("src_ip") or d.get("client_ip") or d.get("remote_ip") or "unknown"
        status = d.get("status", "").lower()
        total += 1
        if status.startswith("fail"):
            failed += 1
            fails_by_user[user] += 1
            users_by_ip[ip].add(user)
        elif status.startswith("succ"):
            ts = event_time(d)
            if user in disabled:
                disabled_hits.append(f"{user} from {ip} at {ts}")
            if ts and (ts.weekday() >= 5 or not start_h <= ts.hour < end_h):
                offhours.append(f"{user} from {ip} at {ts}")

    threshold = cfg.get("failed_threshold", 10)
    alerts = [f"Repeated failed logons: {u} x{n}"
              for u, n in fails_by_user.items() if n >= threshold]
    alerts += [f"Possible password spray from {ip}: {len(u)} accounts"
               for ip, u in users_by_ip.items() if len(u) >= 5]
    alerts += [f"LOGON BY DISABLED ACCOUNT: {x}" for x in disabled_hits]
    alerts += [f"Off-hours logon: {x}" for x in offhours[:10]]
    log.info("Auth events: %d (failed %d). Alerts: %d", total, failed, len(alerts))

    if alerts:
        notify_teams("Sophos Firewall logon anomalies", alerts)
    save_state("sophos_fw", {"offset": new_offset})
    write_summary("sophos_fw_auth", {
        "events": total, "failed": failed, "offhours": len(offhours),
        "disabled_user_logons": len(disabled_hits)})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--discover", action="store_true",
                    help="list the log_component values in the log file and exit")
    args = ap.parse_args()
    if args.discover:
        discover(Path(load_config()["sophos_firewall"]["log_path"]))
    else:
        main()
