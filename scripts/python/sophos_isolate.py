"""Isolate (or release) one endpoint by hostname. Dry run unless --confirm is given."""
import argparse

from entity_common import get_logger
from sophos_common import SophosCentral

log = get_logger("sophos_isolate")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("hostname")
    p.add_argument("--release", action="store_true", help="remove isolation instead")
    p.add_argument("--reason", default="Security investigation")
    p.add_argument("--confirm", action="store_true", help="actually perform the action")
    args = p.parse_args()

    api = SophosCentral()
    data = api.request("GET", "/endpoint/v1/endpoints",
                       params={"hostnameContains": args.hostname})
    matches = [e for e in data.get("items", [])
               if e["hostname"].lower() == args.hostname.lower()]
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one match for {args.hostname}, found {len(matches)}")
    ep = matches[0]
    enable = not args.release
    action = "ISOLATE" if enable else "RELEASE"
    if not args.confirm:
        raise SystemExit(f"Dry run: would {action} {ep['hostname']} ({ep['id']}). "
                         "Re-run with --confirm.")
    api.request("POST", f"/endpoint/v1/endpoints/{ep['id']}/isolation",
                json={"enabled": enable, "comment": args.reason})
    log.info("%s requested for %s (%s): %s", action, ep["hostname"], ep["id"], args.reason)


if __name__ == "__main__":
    main()
