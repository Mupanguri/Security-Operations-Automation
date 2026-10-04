"""Shared helpers for the Entity's SecOps automation scripts."""
import json
import logging
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests

BASE = Path(os.environ.get("SECOPS_HOME", r"C:\SecOps"))
for _sub in ("state", "out", "logs"):
    (BASE / _sub).mkdir(parents=True, exist_ok=True)


def load_config():
    with open(BASE / "config" / "config.json", encoding="utf-8-sig") as f:
        return json.load(f)


def get_logger(name):
    log = logging.getLogger(name)
    if not log.handlers:
        log.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        fh = logging.FileHandler(BASE / "logs" / f"{name}.log", encoding="utf-8")
        fh.setFormatter(fmt)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        log.addHandler(fh)
        log.addHandler(sh)
    return log


def need_env(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing environment variable: {name}")
    return value


def load_state(name, default):
    path = BASE / "state" / f"{name}.json"
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default


def save_state(name, data):
    path = BASE / "state" / f"{name}.json"
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


def write_summary(name, data):
    data["generated_utc"] = datetime.now(timezone.utc).isoformat()
    with open(BASE / "out" / f"{name}.summary.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def notify_teams(title, lines):
    """Post an Adaptive Card to a Teams Workflows webhook. Returns False if not configured."""
    url = os.environ.get("TEAMS_WEBHOOK_URL")
    if not url:
        return False
    body = [{"type": "TextBlock", "text": title, "weight": "Bolder",
             "size": "Medium", "wrap": True}]
    body += [{"type": "TextBlock", "text": line, "wrap": True} for line in lines[:25]]
    card = {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4", "body": body}}]}
    r = requests.post(url, json=card, timeout=30)
    r.raise_for_status()
    return True


def notify_email(subject, text):
    cfg = load_config().get("email", {})
    if not cfg.get("enabled"):
        return False
    msg = EmailMessage()
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Subject"] = subject
    msg.set_content(text)
    with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 25), timeout=30) as s:
        if cfg.get("starttls"):
            s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)
    return True
