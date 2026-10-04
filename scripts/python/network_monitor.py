"""ICMP / TCP availability monitor that alerts after N consecutive failures."""
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from entity_common import (get_logger, load_config, load_state, save_state,
                        notify_teams, write_summary)

log = get_logger("network_monitor")
IS_WIN = sys.platform.startswith("win")
RTT = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)


def ping(host, count=3):
    cmd = ["ping", "-n" if IS_WIN else "-c", str(count), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except subprocess.TimeoutExpired:
        return False, None, 100
    rtts = [float(x) for x in RTT.findall(out)]
    loss = round(100 * (count - len(rtts)) / count)
    return bool(rtts), (sum(rtts) / len(rtts) if rtts else None), loss


def tcp(host, port, timeout=3):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.perf_counter() - start) * 1000
    except OSError:
        return False, None


def check_target(t):
    results = []
    if "icmp" in t.get("checks", ["icmp"]):
        ok, rtt, loss = ping(t["host"])
        results.append((f"{t['name']} ICMP", ok, rtt, f"loss {loss}%"))
    for port in t.get("tcp", []):
        ok, rtt = tcp(t["host"], port)
        results.append((f"{t['name']} TCP/{port}", ok, rtt, ""))
    return results


def main():
    cfg = load_config()["network_monitor"]
    threshold = cfg.get("failures_before_alert", 3)
    latency_warn = cfg.get("latency_warn_ms", 150)
    state = load_state("network_monitor", {})

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = [r for group in pool.map(check_target, cfg["targets"]) for r in group]

    alerts, recoveries = [], []
    for name, ok, rtt, note in results:
        s = state.setdefault(name, {"fails": 0, "alerted": False})
        if ok:
            if s["alerted"]:
                recoveries.append(f"RECOVERED: {name}")
            s["fails"], s["alerted"] = 0, False
            if rtt and rtt > latency_warn:
                log.warning("SLOW: %s %.0f ms", name, rtt)
        else:
            s["fails"] += 1
            log.warning("FAIL: %s (%d consecutive) %s", name, s["fails"], note)
            if s["fails"] >= threshold and not s["alerted"]:
                alerts.append(f"DOWN: {name} - {s['fails']} consecutive failures {note}")
                s["alerted"] = True

    if alerts or recoveries:
        notify_teams("Network monitor", alerts + recoveries)
    save_state("network_monitor", state)
    write_summary("network_monitor", {
        "checks": len(results),
        "failing": [n for n, s in state.items() if s["fails"] > 0]})


if __name__ == "__main__":
    main()
