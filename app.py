"""mimamori (見守り): watches the SMART health of the drives on all your hosts.

This is the server: web page, history, alerts and the agent API.

    gunicorn "app:create_app()"   run the server (unprivileged)
    python app.py health           container health check

The agents (agent.py, their own small image) report to it. Their messages are encrypted and
signed end to end; the server keeps only each agent's public key. The protocol lives in agent.py.

The web page speaks plain HTTP and expects a reverse proxy in front that provides HTTPS.
Plain HTTP without a proxy needs UNSAFE_HTTP and is warned about in the log and on every page.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import json
import logging
import os
import queue
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Callable, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import agent as protocol

# Everything goes to stdout so it shows up in `docker logs` / Portainer
logging.basicConfig(stream=sys.stdout, level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mimamori")

VERSION = os.environ.get("APP_VERSION", "dev")
BASE_DIR = Path(__file__).resolve().parent
DAY = 86400
HEARTBEAT_SECONDS = 60
EXAMPLE_PASSWORD = "a-long-secure-password"  # the value in secrets.env.example
MIN_PASSWORD_LENGTH = 12


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_flag(name: str, default: bool = False) -> bool:
    value = env(name).lower()
    return default if not value else value in ("1", "true", "yes", "on")


def env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a whole number")
    if not lo <= value <= hi:
        raise SystemExit(f"{name} must be between {lo} and {hi}")
    return value


# ============================================================================
# Configuration (server)
# ============================================================================

@dataclass
class Config:
    admin_user: str
    admin_password: str = field(repr=False)
    data_dir: Path = Path("/data")
    public_url: str = ""
    timezone: str = "UTC"
    retention_days: int = 400
    session_hours: int = 12
    discord_webhook_url: str = field(default="", repr=False)
    webhook_url: str = field(default="", repr=False)
    webhook_secret: str = field(default="", repr=False)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = field(default="", repr=False)
    smtp_security: str = "starttls"
    mail_from: str = ""
    mail_to: list[str] = field(default_factory=list)
    behind_proxy: bool = True
    # Unsafe options, off unless switched on explicitly. Each one is announced in the log at
    # every start and on the page itself, so that nobody runs with it by accident.
    unsafe_http: bool = False
    unsafe_hide_warnings: bool = False
    unsafe_http_webhooks: bool = False
    unsafe_smtp_plaintext: bool = False


def load_config() -> Config:
    missing = [n for n in ("ADMIN_USER", "ADMIN_PASSWORD") if not env(n)]
    if missing:
        log.critical("%s missing in secrets.env. Set it, then start the container again.",
                     ", ".join(missing))
        raise SystemExit(1)
    # The values in secrets.env.example are public: never run with them
    password = os.environ.pop("ADMIN_PASSWORD")
    if password == EXAMPLE_PASSWORD:
        log.critical("ADMIN_PASSWORD still has the value from secrets.env.example. Set your own "
                     "in secrets.env, then start the container again.")
        raise SystemExit(1)
    if len(password) < MIN_PASSWORD_LENGTH:
        log.critical("ADMIN_PASSWORD must be at least %d characters long.", MIN_PASSWORD_LENGTH)
        raise SystemExit(1)

    security = env("SMTP_SECURITY", "starttls").lower()
    if security not in {"starttls", "ssl", "none"}:
        raise SystemExit("SMTP_SECURITY must be starttls, ssl or none")
    cfg = Config(
        admin_user=env("ADMIN_USER"),
        admin_password=password,
        data_dir=Path(env("DATA_DIR", "/data")),
        public_url=env("PUBLIC_URL").rstrip("/"),
        timezone=env("TZ", "UTC"),
        retention_days=env_int("RETENTION_DAYS", 400, 7, 3650),
        session_hours=env_int("SESSION_HOURS", 12, 1, 720),
        discord_webhook_url=env("DISCORD_WEBHOOK_URL"),
        webhook_url=env("WEBHOOK_URL"),
        webhook_secret=env("WEBHOOK_SECRET"),
        smtp_host=env("SMTP_HOST"),
        smtp_port=env_int("SMTP_PORT", 465 if security == "ssl" else 587, 1, 65535),
        smtp_user=env("SMTP_USER"),
        smtp_password=env("SMTP_PASSWORD"),
        smtp_security=security,
        mail_from=env("MAIL_FROM"),
        mail_to=[m.strip() for m in env("MAIL_TO").split(",") if m.strip()],
        behind_proxy=env_flag("BEHIND_PROXY", default=True),
        unsafe_http=env_flag("UNSAFE_HTTP"),
        unsafe_hide_warnings=env_flag("UNSAFE_HIDE_WARNINGS"),
        unsafe_http_webhooks=env_flag("UNSAFE_HTTP_WEBHOOKS"),
        unsafe_smtp_plaintext=env_flag("UNSAFE_SMTP_PLAINTEXT"),
    )
    if security == "none" and not cfg.unsafe_smtp_plaintext:
        raise SystemExit("SMTP_SECURITY=none needs UNSAFE_SMTP_PLAINTEXT=true")
    for name in ("DISCORD_WEBHOOK_URL", "WEBHOOK_URL"):
        url = env(name)
        if url and not url.startswith("https://") and not (
                url.startswith("http://") and cfg.unsafe_http_webhooks):
            raise SystemExit(f"{name} must start with https:// (or set UNSAFE_HTTP_WEBHOOKS)")
    if cfg.webhook_secret == "paste-random-key-here":
        log.critical("WEBHOOK_SECRET still has the value from secrets.env.example. Generate one "
                     "with: openssl rand -hex 32")
        raise SystemExit(1)
    if cfg.smtp_host and not (cfg.mail_from and cfg.mail_to):
        raise SystemExit("SMTP_HOST needs MAIL_FROM and MAIL_TO")
    return cfg


def log_unsafe(cfg: Config) -> None:
    if cfg.unsafe_http:
        log.warning("UNSAFE: UNSAFE_HTTP is on. Over plain HTTP, your password, the session and "
                    "all drive data travel unencrypted and can be read by anyone on the network.")
    if cfg.unsafe_http_webhooks:
        log.warning("UNSAFE: UNSAFE_HTTP_WEBHOOKS is on. Notifications to http:// addresses "
                    "travel unencrypted.")
    if cfg.unsafe_smtp_plaintext:
        log.warning("UNSAFE: UNSAFE_SMTP_PLAINTEXT is on. Mail, and the SMTP password, may "
                    "travel unencrypted.")
    if cfg.unsafe_hide_warnings and (cfg.unsafe_http or cfg.unsafe_http_webhooks
                                     or cfg.unsafe_smtp_plaintext):
        log.warning("UNSAFE: UNSAFE_HIDE_WARNINGS is on. The page no longer tells its users about "
                    "the unsafe options above. This log is the only place that still does.")
    if not cfg.behind_proxy:
        log.warning("BEHIND_PROXY is off: the login lockout counts the address of each "
                    "connection. Do not put a proxy in front, or all users share one address.")


# ============================================================================
# SMART data: turn `smartctl --json` output into a small, normalized record.
# The input comes from agents over the network, so it is treated as hostile:
# every field is type-checked, numbers are bounded and strings are truncated.
# ============================================================================

MAX_STR = 128
MAX_ATTRS = 64
MAX_DEVICES = 64
_BIG = 2**63 - 1
_SAFE_TEXT = re.compile(r"[^\x20-\x7e]")
DEVICE_PATH = re.compile(r"^/dev/[A-Za-z0-9_\-/.]{1,64}$")

ATTR_REALLOCATED, ATTR_PENDING, ATTR_UNCORRECTABLE, ATTR_CRC = 5, 197, 198, 199
# Normalized value counts down from 100 as the SSD wears (vendor specific).
WEAR_ATTRS = (177, 231, 233, 202, 169)
NVME_FIELDS = (
    "critical_warning", "temperature", "available_spare", "available_spare_threshold",
    "percentage_used", "data_units_read", "data_units_written", "power_cycles",
    "power_on_hours", "unsafe_shutdowns", "media_errors", "num_err_log_entries",
)


def clean_text(value: Any, limit: int = MAX_STR) -> str:
    if not isinstance(value, str):
        return ""
    return _SAFE_TEXT.sub("", value).strip()[:limit]


def _num(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -_BIG <= value <= _BIG else None
    if isinstance(value, float) and value == value:  # not NaN
        return int(max(-_BIG, min(_BIG, value)))
    return None


def _get(data: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _messages(raw: dict) -> list:
    messages = _get(raw, "smartctl", "messages")
    return messages if isinstance(messages, list) else []


def parse_smart(raw: Any, device_hint: str = "") -> dict | None:
    """Parse one device's smartctl JSON. Returns None if nothing usable is in it."""
    if not isinstance(raw, dict):
        return None
    device = clean_text(_get(raw, "device", "name")) or clean_text(device_hint)
    if not DEVICE_PATH.match(device):
        device = ""
    protocol = clean_text(_get(raw, "device", "protocol")).lower()
    serial = clean_text(_get(raw, "serial_number"), 64)
    model = clean_text(_get(raw, "model_name")) or " ".join(
        p for p in (clean_text(_get(raw, "scsi_vendor")), clean_text(_get(raw, "scsi_product"))) if p)
    out: dict[str, Any] = {
        "device": device, "serial": serial, "model": model,
        "firmware": clean_text(_get(raw, "firmware_version"), 32),
        "capacity": _num(_get(raw, "user_capacity", "bytes")),
        "rpm": None, "kind": "unknown", "smart_passed": None,
        "temp": _num(_get(raw, "temperature", "current")),
        "power_on_hours": _num(_get(raw, "power_on_time", "hours")),
        "reallocated": None, "pending": None, "uncorrectable": None, "crc_errors": None,
        "wear": None, "media_errors": None, "critical_warning": None,
        "attrs": [], "standby": False, "error": "",
    }

    if not serial:
        out["standby"] = any("standby" in clean_text(_get(m, "string"), 512).lower()
                             for m in _messages(raw))
        if out["standby"] or not (model and device):
            first_error = next((clean_text(_get(m, "string"), 200) for m in _messages(raw)
                                if _get(m, "severity") == "error"), "")
            out["error"] = "" if out["standby"] else (first_error or "no SMART data")
            return out if device else None
        # Identified but without a serial (USB bridges, virtual disks): key it by its path
        out["serial"] = f"no-serial:{device}"

    passed = _get(raw, "smart_status", "passed")
    if isinstance(passed, bool):
        out["smart_passed"] = passed
    rotation = _num(_get(raw, "rotation_rate"))
    if protocol == "nvme":
        out["kind"] = "nvme"
    elif rotation == 0:
        out["kind"] = "ssd"
    elif rotation and rotation > 0:
        out["kind"] = "hdd"
        out["rpm"] = rotation

    table = _get(raw, "ata_smart_attributes", "table")
    if isinstance(table, list):
        _parse_ata(out, table)
    nvme = _get(raw, "nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        _parse_nvme(out, nvme)
    grown = _num(_get(raw, "scsi_grown_defect_list"))
    if grown is not None and out["reallocated"] is None:
        out["reallocated"] = grown
    for key in ("temp", "power_on_hours", "wear"):
        if out[key] is not None and out[key] < 0:
            out[key] = None
    return out


def _parse_ata(out: dict, table: list) -> None:
    by_id: dict[int, dict] = {}
    for row in table[:MAX_ATTRS * 4]:
        attr_id = _num(_get(row, "id"))
        if attr_id is None or not 0 < attr_id < 256 or attr_id in by_id:
            continue
        by_id[attr_id] = {
            "id": attr_id, "name": clean_text(_get(row, "name"), 48),
            "value": _num(_get(row, "value")), "worst": _num(_get(row, "worst")),
            "thresh": _num(_get(row, "thresh")), "raw": _num(_get(row, "raw", "value")),
        }
        if len(by_id) >= MAX_ATTRS:
            break
    out["attrs"] = [by_id[k] for k in sorted(by_id)]

    def raw(attr_id: int) -> int | None:
        entry = by_id.get(attr_id)
        return entry["raw"] if entry else None

    out["reallocated"] = raw(ATTR_REALLOCATED)
    out["pending"] = raw(ATTR_PENDING)
    out["uncorrectable"] = raw(ATTR_UNCORRECTABLE)
    out["crc_errors"] = raw(ATTR_CRC)
    if out["kind"] == "ssd":
        for attr_id in WEAR_ATTRS:
            entry = by_id.get(attr_id)
            if entry and entry["value"] is not None and 0 <= entry["value"] <= 100:
                out["wear"] = 100 - entry["value"]
                break


def _parse_nvme(out: dict, nvme_log: dict) -> None:
    out["attrs"] = [{"id": None, "name": name, "value": None, "worst": None, "thresh": None,
                     "raw": _num(nvme_log.get(name))}
                    for name in NVME_FIELDS if _num(nvme_log.get(name)) is not None]
    out["wear"] = _num(nvme_log.get("percentage_used"))
    out["media_errors"] = _num(nvme_log.get("media_errors"))
    out["critical_warning"] = _num(nvme_log.get("critical_warning"))
    if out["temp"] is None:
        out["temp"] = _num(nvme_log.get("temperature"))
    if out["power_on_hours"] is None:
        out["power_on_hours"] = _num(nvme_log.get("power_on_hours"))


# ============================================================================
# Thresholds, drive status and alert transitions.
# A drive's issues are a dict  metric -> {"level": "warn"|"crit", "value": n, "text": ...}.
# Comparing the issues of two checks gives the alerts: new issue, worsened, resolved.
# ============================================================================

GROWTH_CHOICES = ("off", "warn", "crit")
KINDS = ("hdd", "ssd", "nvme", "unknown")
COUNTERS = {
    "reallocated": "reallocated sectors",
    "pending": "pending sectors",
    "uncorrectable": "uncorrectable sectors",
    "media_errors": "media errors",
    "crc_errors": "CRC errors",
}
# Any reallocated, pending or uncorrectable sector warns; growth is critical.
DEFAULT_THRESHOLDS: dict[str, Any] = {
    "temp": {
        "hdd": {"warn": 50, "crit": 55},
        "ssd": {"warn": 60, "crit": 70},
        "nvme": {"warn": 70, "crit": 80},
        "unknown": {"warn": 55, "crit": 65},
    },
    "wear": {"warn": 80, "crit": 95},
    "reallocated": {"warn": 1, "crit": None, "growth": "crit"},
    "pending": {"warn": 1, "crit": None, "growth": "crit"},
    "uncorrectable": {"warn": 1, "crit": None, "growth": "crit"},
    "media_errors": {"warn": 1, "crit": None, "growth": "crit"},
    # CRC errors are usually the cable, not the drive, and old ones never reset
    "crc_errors": {"warn": None, "crit": None, "growth": "warn"},
}
SAMPLE_FIELDS = ("temp", "power_on_hours", "smart_passed", "reallocated", "pending",
                 "uncorrectable", "crc_errors", "wear", "media_errors", "critical_warning")


def merge_thresholds(global_: dict | None, overrides: dict | None) -> dict:
    """Defaults <- global settings <- per-drive overrides."""
    out = json.loads(json.dumps(DEFAULT_THRESHOLDS))
    for layer in (global_ or {}, overrides or {}):
        for metric, conf in layer.items():
            if metric not in out or not isinstance(conf, dict):
                continue
            if metric == "temp":
                for kind, pair in conf.items():
                    if kind in out["temp"] and isinstance(pair, dict):
                        out["temp"][kind].update(_clean_pair(pair))
            else:
                out[metric].update(_clean_pair(conf))
    return out


def _clean_pair(conf: dict) -> dict:
    clean: dict[str, Any] = {}
    for key in ("warn", "crit"):
        if key in conf:
            v = conf[key]
            ok = v is None or (isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10**12)
            clean[key] = v if ok else None
    if conf.get("growth") in GROWTH_CHOICES:
        clean["growth"] = conf["growth"]
    return clean


def _level(value: int | None, warn: int | None, crit: int | None) -> str | None:
    if value is None:
        return None
    if crit is not None and value >= crit:
        return "crit"
    if warn is not None and value >= warn:
        return "warn"
    return None


def _max_level(a: str | None, b: str | None) -> str | None:
    order = {None: 0, "warn": 1, "crit": 2}
    return a if order[a] >= order[b] else b


def find_issues(sample: dict, baseline: dict | None, kind: str, thresholds: dict) -> dict:
    """Issues for the newest sample. Growth is measured against `baseline`."""
    issues: dict[str, dict] = {}
    if sample.get("smart_passed") in (False, 0):
        issues["smart"] = {"level": "crit", "value": 0, "text": "SMART overall health check FAILED"}
    cw = sample.get("critical_warning")
    if cw:
        issues["critical_warning"] = {"level": "crit", "value": cw,
                                      "text": f"NVMe critical warning flags set ({cw})"}
    temp = sample.get("temp")
    t = thresholds["temp"].get(kind) or thresholds["temp"]["unknown"]
    level = _level(temp, t["warn"], t["crit"])
    if level:
        limit = t["crit"] if level == "crit" else t["warn"]
        word = "critical" if level == "crit" else "warn"
        issues["temp"] = {"level": level, "value": temp,
                          "text": f"Temperature {temp} °C ({word} at {limit})"}
    wear = sample.get("wear")
    level = _level(wear, thresholds["wear"]["warn"], thresholds["wear"]["crit"])
    if level:
        issues["wear"] = {"level": level, "value": wear, "text": f"Wear at {wear} %"}
    for metric, label in COUNTERS.items():
        value = sample.get(metric)
        if value is None:
            continue
        conf = thresholds[metric]
        level = _level(value, conf["warn"], conf["crit"])
        prev = baseline.get(metric) if baseline else None
        grew = prev is not None and value > prev
        if grew and conf.get("growth", "off") != "off":
            level = _max_level(level, conf["growth"])
        if level:
            text = f"{value} {label}" + (f" (+{value - prev})" if grew else "")
            issues[metric] = {"level": level, "value": value, "text": text}
    return issues


def status_of(issues: dict) -> str:
    levels = {i["level"] for i in issues.values()}
    return "failing" if "crit" in levels else "watch" if "warn" in levels else "healthy"


def summary_of(issues: dict) -> str:
    if not issues:
        return ""
    return sorted(issues.values(), key=lambda i: i["level"] != "crit")[0]["text"]


def transitions(old: dict, new: dict) -> list[dict]:
    """Alerts for the change from `old` issues to `new` issues."""
    out = []
    for metric, issue in new.items():
        before = old.get(metric)
        if before is None:
            out.append({"kind": "new_issue", "level": issue["level"], "metric": metric,
                        "text": issue["text"]})
        elif (issue["level"] == "crit" and before["level"] == "warn") or (
                metric in COUNTERS and issue["value"] > before["value"]) or (
                metric == "temp" and issue["level"] != before["level"]):
            out.append({"kind": "worsened", "level": issue["level"], "metric": metric,
                        "text": issue["text"].split(" (+")[0], "from": before["value"]})
    for metric, issue in old.items():
        if metric not in new:
            out.append({"kind": "resolved", "level": "ok", "metric": metric, "text": issue["text"]})
    return out


# ============================================================================
# Storage: SQLite, one connection per thread. Writes that read-modify-write
# shared rows run under Database.lock.
# ============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL,
    last_message INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    last_report INTEGER,
    agent_version TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    scan_requested INTEGER NOT NULL DEFAULT 0,
    offline_alerted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS drives (
    id INTEGER PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    serial TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'unknown',
    capacity INTEGER,
    rpm INTEGER,
    firmware TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'healthy',
    summary TEXT NOT NULL DEFAULT '',
    issues TEXT NOT NULL DEFAULT '{}',
    overrides TEXT NOT NULL DEFAULT '{}',
    muted INTEGER NOT NULL DEFAULT 0,
    standby INTEGER NOT NULL DEFAULT 0,
    UNIQUE (agent_id, serial)
);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    drive_id INTEGER NOT NULL REFERENCES drives(id) ON DELETE CASCADE,
    ts INTEGER NOT NULL,
    temp INTEGER, power_on_hours INTEGER, smart_passed INTEGER, reallocated INTEGER,
    pending INTEGER, uncorrectable INTEGER, crc_errors INTEGER, wear INTEGER,
    media_errors INTEGER, critical_warning INTEGER,
    attrs TEXT
);
CREATE INDEX IF NOT EXISTS samples_drive_ts ON samples (drive_id, ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    agent_id TEXT REFERENCES agents(id) ON DELETE CASCADE,
    drive_id INTEGER REFERENCES drives(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    level TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    channels TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_drive ON alerts (drive_id, ts);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self._local = threading.local()
        with self.lock:
            self.conn().executescript(SCHEMA)

    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # Autocommit; multi-statement writes use transaction() explicitly
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self.conn().execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self.conn().execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn().execute(sql, params)

    def transaction(self) -> "_Tx":
        return _Tx(self)

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     (key, json.dumps(value)))


class _Tx:
    """`with db.transaction() as conn:` holds the write lock and commits at the end."""

    def __init__(self, db: Database):
        self.db = db

    def __enter__(self) -> sqlite3.Connection:
        self.db.lock.acquire()
        self.conn = self.db.conn()
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.conn.execute("COMMIT" if exc_type is None else "ROLLBACK")
        finally:
            self.db.lock.release()


# ============================================================================
# Notifications: Discord webhook, mail and a custom (HMAC-signed) webhook.
# Sending happens on a background thread so requests never wait on a slow mail
# server. URLs and passwords are never logged: they can contain tokens.
# ============================================================================

NOTIFY_TIMEOUT = 15
COLORS = {"crit": 0xEE6A5F, "warn": 0xE9B949, "ok": 0x4CC38A, "info": 0x98A6BA}
ALERT_LABELS = {
    "new_issue": "New issue", "worsened": "Worsened", "resolved": "Resolved",
    "missing": "Missing", "back": "Back", "agent_offline": "Agent offline",
    "agent_online": "Agent online", "test": "Test", "report": "Weekly report",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a redirect could lead to http:// or another host


_opener = urllib.request.build_opener(
    _NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _post_json(url: str, body: bytes, headers: dict[str, str]) -> None:
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "mimamori", **headers})
    with _opener.open(req, timeout=NOTIFY_TIMEOUT) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"HTTP {resp.status}")


def make_event(kind: str, level: str, title: str, detail: str, *, fields: dict | None = None,
               footer: str = "mimamori", url: str = "", extra: dict | None = None) -> dict:
    return {"kind": kind, "label": ALERT_LABELS.get(kind, kind), "level": level, "title": title,
            "detail": detail, "fields": fields or {}, "footer": footer, "url": url,
            "ts": int(time.time()), **(extra or {})}


class Notifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        threading.Thread(target=self._run, name="notifier", daemon=True).start()

    def channels(self) -> dict[str, bool]:
        return {"Discord": bool(self.cfg.discord_webhook_url), "mail": bool(self.cfg.smtp_host),
                "webhook": bool(self.cfg.webhook_url)}

    def configured(self) -> list[str]:
        return [name for name, on in self.channels().items() if on]

    def send(self, event: dict, on_done: Callable[[list[str]], None] | None = None) -> None:
        if not self.configured():
            if on_done:
                on_done([])
            return
        try:
            self._queue.put_nowait((event, on_done))
        except queue.Full:
            log.error("Notification queue full, dropping a %s notification", event.get("kind"))

    def _run(self) -> None:
        while True:
            event, on_done = self._queue.get()
            sent = [name for name, fn in (("Discord", self._discord), ("mail", self._mail),
                                          ("webhook", self._webhook))
                    if self.channels()[name] and self._retry(name, fn, event)]
            if on_done:
                try:
                    on_done(sent)
                except Exception:  # never let a callback kill the worker
                    log.exception("Notification callback failed")

    def _retry(self, name: str, fn: Callable[[dict], None], event: dict) -> bool:
        for attempt in range(3):
            try:
                fn(event)
                return True
            except (urllib.error.URLError, OSError, smtplib.SMTPException, RuntimeError) as exc:
                reason = getattr(exc, "reason", None) or getattr(exc, "code", None) or type(exc).__name__
                log.warning("Sending to %s failed (attempt %d): %s", name, attempt + 1, reason)
                time.sleep(2 ** attempt * 2)
        return False

    def _discord(self, event: dict) -> None:
        embed = {
            "title": event["title"][:256],
            "description": event["detail"][:4000],
            "color": COLORS.get(event["level"], COLORS["info"]),
            "fields": [{"name": k[:256], "value": str(v)[:1024] or "–", "inline": True}
                       for k, v in event.get("fields", {}).items()][:25],
            "footer": {"text": event.get("footer", "mimamori")[:2048]},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event["ts"])),
        }
        if event.get("url"):
            embed["url"] = event["url"]
        # Drive names come from hardware: never let them ping anyone
        body = json.dumps({"username": "Mimamori", "embeds": [embed],
                           "allowed_mentions": {"parse": []}}).encode()
        _post_json(self.cfg.discord_webhook_url, body, {})

    def _webhook(self, event: dict) -> None:
        body = json.dumps({k: v for k, v in event.items() if k != "html"}).encode()
        headers = {}
        if self.cfg.webhook_secret:
            ts = str(int(time.time()))
            sig = hmac.new(self.cfg.webhook_secret.encode(), ts.encode() + b"." + body,
                           hashlib.sha256).hexdigest()
            headers = {"X-Mimamori-Timestamp": ts, "X-Mimamori-Signature": f"sha256={sig}"}
        _post_json(self.cfg.webhook_url, body, headers)

    def _mail(self, event: dict) -> None:
        cfg = self.cfg
        msg = EmailMessage()
        msg["Subject"] = f"[mimamori] {event['title']}"[:200]
        msg["From"] = cfg.mail_from
        msg["To"] = ", ".join(cfg.mail_to)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="mimamori.local")
        lines = [event["title"], "", event["detail"], ""]
        lines += [f"{k}: {v}" for k, v in event.get("fields", {}).items()]
        if event.get("url"):
            lines += ["", event["url"]]
        msg.set_content("\n".join(lines))
        msg.add_alternative(event.get("html") or _mail_html(event), subtype="html")
        context = ssl.create_default_context()
        if cfg.smtp_security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port,
                                                    timeout=NOTIFY_TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=NOTIFY_TIMEOUT)
        with server:
            if cfg.smtp_security == "starttls":
                server.starttls(context=context)
            if cfg.smtp_user:
                server.login(cfg.smtp_user, cfg.smtp_password)
            server.send_message(msg)


def _mail_html(event: dict) -> str:
    e = html.escape
    color = "#%06X" % COLORS.get(event["level"], COLORS["info"])
    rows = "".join(f'<tr><td style="color:#98A6BA;padding:2px 16px 2px 0">{e(str(k))}</td>'
                   f'<td style="color:#EDF1F6">{e(str(v))}</td></tr>'
                   for k, v in event.get("fields", {}).items())
    link = (f'<p><a style="color:#4CC38A" href="{e(event["url"])}">Open in mimamori</a></p>'
            if event.get("url") else "")
    return ('<div style="background:#0B1220;padding:24px;font-family:sans-serif">'
            f'<div style="background:#131F33;border-left:4px solid {color};border-radius:8px;padding:16px">'
            f'<h2 style="color:#EDF1F6;margin:0 0 8px">{e(event["title"])}</h2>'
            f'<p style="color:#C9D2DE">{e(event["detail"])}</p><table>{rows}</table>{link}</div>'
            f'<p style="color:#98A6BA;font-size:12px">{e(event.get("footer", "mimamori"))}</p></div>')


# ============================================================================
# Monitor: ingest agent reports, keep drive status, raise alerts, and run the
# periodic jobs (offline agents, retention, weekly report).
# ============================================================================

DEFAULT_SETTINGS: dict[str, Any] = {
    "scan_interval_minutes": 60,
    "agent_offline_minutes": 10,
    "growth_window_days": 7,
    "thresholds": {},
    "report_enabled": True,
    "report_weekday": 6,  # Sunday (Monday = 0)
    "report_time": "09:00",
    "report_last_sent": 0,  # last slot handled (sent or skipped)
    "report_delivered": 0,  # last time a report was actually sent
}


def kind_label(kind: str) -> str:
    return {"hdd": "HDD", "ssd": "SSD", "nvme": "NVMe"}.get(kind, "Drive")


def drive_name(drive: dict) -> str:
    return f"{drive['model'] or 'Unknown drive'} · {drive['device'].removeprefix('/dev/')}"


def _baseline(conn, drive_id: int, sample_id: int, before_ts: int):
    """The sample growth is measured against: the newest one older than the growth
    window, or else the oldest one before `sample_id`."""
    return conn.execute(
        "SELECT * FROM samples WHERE drive_id = ? AND ts <= ? AND id < ? "
        "ORDER BY ts DESC, id DESC LIMIT 1", (drive_id, before_ts, sample_id)).fetchone() \
        or conn.execute("SELECT * FROM samples WHERE drive_id = ? AND id < ? ORDER BY id LIMIT 1",
                        (drive_id, sample_id)).fetchone()


def _advice(t: dict) -> str:
    metric = t["metric"]
    if t["kind"] == "resolved":
        return "Back within thresholds."
    if metric in {"reallocated", "pending", "uncorrectable", "media_errors"}:
        return ("The drive is remapping or failing to read sectors. "
                "Back up what lives on it and plan a replacement.")
    if metric == "crc_errors":
        return "Interface CRC errors usually mean a loose or bad cable, not a failing drive."
    if metric == "temp":
        return "Check airflow and fans around the drive."
    if metric == "wear":
        return "The SSD is nearing the end of its rated endurance."
    return "Check the drive's details in mimamori."


class Monitor:
    def __init__(self, db: Database, cfg: Config, notifier: Notifier):
        self.db = db
        self.cfg = cfg
        self.notifier = notifier
        try:
            self.tz: dt.tzinfo = ZoneInfo(cfg.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            log.warning("Unknown time zone %r, using UTC", cfg.timezone)
            self.tz = dt.timezone.utc
        self._stop = threading.Event()

    def clock(self, ts: int) -> str:
        return dt.datetime.fromtimestamp(ts, self.tz).strftime("%H:%M")

    def setting(self, key: str) -> Any:
        return self.db.get_setting(key, DEFAULT_SETTINGS[key])

    def thresholds_for(self, drive: dict | None) -> dict:
        return merge_thresholds(self.setting("thresholds"),
                                json.loads(drive["overrides"]) if drive else None)

    # agents ---------------------------------------------------------------
    def heartbeat(self, agent: dict, version: str, hostname: str) -> dict:
        self.db.execute("UPDATE agents SET last_seen = ?, agent_version = ?, hostname = ?, "
                        "scan_requested = 0 WHERE id = ?",
                        (int(time.time()), version, hostname, agent["id"]))
        if agent["offline_alerted"]:
            self.db.execute("UPDATE agents SET offline_alerted = 0 WHERE id = ?", (agent["id"],))
            self._alert(agent["id"], None, "agent_online", "ok",
                        f"Agent {agent['name']} is back online", "Reports are coming in again.")
        return {"scan_interval": int(self.setting("scan_interval_minutes")) * 60,
                "heartbeat_interval": HEARTBEAT_SECONDS,
                "scan_now": bool(agent["scan_requested"])}

    def request_scan(self) -> None:
        self.db.execute("UPDATE agents SET scan_requested = 1")

    # reports --------------------------------------------------------------
    def ingest(self, agent: dict, payload: dict) -> int:
        """Store one scan report from an agent. Returns the number of drives seen."""
        devices = payload.get("devices")
        if not isinstance(devices, list):
            raise ValueError("devices must be a list")
        records = [rec for item in devices[:MAX_DEVICES] if isinstance(item, dict)
                   for rec in [parse_smart(item.get("smartctl"), clean_text(item.get("device")))]
                   if rec]
        now = int(time.time())
        pending_alerts: list[tuple] = []
        seen_ids: set[int] = set()
        window = int(self.setting("growth_window_days")) * DAY
        global_thresholds = self.setting("thresholds")

        with self.db.transaction() as conn:
            conn.execute("UPDATE agents SET last_report = ?, last_seen = ? WHERE id = ?",
                         (now, now, agent["id"]))
            for rec in records:
                if not rec["serial"]:
                    if rec["standby"] and rec["device"]:
                        cur = conn.execute("UPDATE drives SET last_seen = ?, standby = 1 "
                                           "WHERE agent_id = ? AND device = ? RETURNING id",
                                           (now, agent["id"], rec["device"]))
                        seen_ids.update(r["id"] for r in cur.fetchall())
                    continue
                drive = conn.execute(
                    """INSERT INTO drives (agent_id, serial, model, device, kind, capacity, rpm,
                                           firmware, first_seen, last_seen, standby)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                       ON CONFLICT (agent_id, serial) DO UPDATE SET
                           model = excluded.model, device = excluded.device, kind = excluded.kind,
                           capacity = excluded.capacity, rpm = excluded.rpm,
                           firmware = excluded.firmware, last_seen = excluded.last_seen, standby = 0
                       RETURNING *""",
                    (agent["id"], rec["serial"], rec["model"], rec["device"], rec["kind"],
                     rec["capacity"], rec["rpm"], rec["firmware"], now, now)).fetchone()
                seen_ids.add(drive["id"])
                sample = {f: rec[f] for f in SAMPLE_FIELDS}
                if sample["smart_passed"] is not None:
                    sample["smart_passed"] = int(sample["smart_passed"])
                sample_id = conn.execute(
                    f"INSERT INTO samples (drive_id, ts, {', '.join(SAMPLE_FIELDS)}, attrs) "
                    f"VALUES (?, ?, {', '.join('?' * len(SAMPLE_FIELDS))}, ?)",
                    (drive["id"], now, *sample.values(), json.dumps(rec["attrs"]))).lastrowid
                baseline = _baseline(conn, drive["id"], sample_id, now - window)
                issues = find_issues(sample, dict(baseline) if baseline else None, drive["kind"],
                                     merge_thresholds(global_thresholds,
                                                      json.loads(drive["overrides"])))
                pending_alerts += self._apply_issues(conn, drive, issues)

            # Drives this agent used to have but did not report: missing
            for drive in conn.execute("SELECT * FROM drives WHERE agent_id = ?",
                                      (agent["id"],)).fetchall():
                issues = json.loads(drive["issues"])
                if drive["id"] in seen_ids or "missing" in issues:
                    continue
                issues["missing"] = {"level": "crit", "value": drive["last_seen"],
                                     "text": f"Not responding since {self.clock(drive['last_seen'])}"}
                conn.execute("UPDATE drives SET issues = ?, status = 'missing', summary = ? "
                             "WHERE id = ?",
                             (json.dumps(issues), issues["missing"]["text"], drive["id"]))
                pending_alerts.append((drive, "missing", "crit",
                                       f"{drive_name(dict(drive))} stopped responding",
                                       "The drive was not in the last report from its agent."))

        for drive, kind, level, title, detail in pending_alerts:
            self._alert(agent["id"], dict(drive), kind, level, title, detail)
        return len(seen_ids)

    def _apply_issues(self, conn, drive, issues: dict) -> list[tuple]:
        old = json.loads(drive["issues"])
        name = drive_name(dict(drive))
        out = []
        if "missing" in old:
            old = {k: v for k, v in old.items() if k != "missing"}
            out.append((drive, "back", "ok", f"{name} is responding again",
                        "The drive is back in its agent's report."))
        for t in transitions(old, issues):
            if t["kind"] == "worsened" and "from" in t:
                metric = t["metric"].replace("_", " ")
                title = f"{name}: {metric} {t['from']} → {issues[t['metric']]['value']}"
            elif t["kind"] == "resolved":
                title = f"{name}: resolved ({t['text']})"
            else:
                title = f"{name}: {t['text']}"
            out.append((drive, t["kind"], t["level"], title, _advice(t)))
        conn.execute("UPDATE drives SET issues = ?, status = ?, summary = ? WHERE id = ?",
                     (json.dumps(issues), status_of(issues), summary_of(issues), drive["id"]))
        return out

    def _alert(self, agent_id: str, drive: dict | None, kind: str, level: str,
               title: str, detail: str) -> None:
        alert_id = self.db.execute(
            "INSERT INTO alerts (ts, agent_id, drive_id, kind, level, title, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(time.time()), agent_id, drive["id"] if drive else None, kind, level, title,
             detail)).lastrowid
        if drive and drive.get("muted"):
            return
        agent = self.db.one("SELECT name FROM agents WHERE id = ?", (agent_id,))
        host = agent["name"] if agent else "unknown host"
        fields: dict[str, Any] = {"Host": host}
        url = ""
        if drive:
            latest = self.db.one("SELECT temp, power_on_hours FROM samples WHERE drive_id = ? "
                                 "ORDER BY ts DESC LIMIT 1", (drive["id"],))
            fields["Device"] = drive["device"]
            if latest and latest["temp"] is not None:
                fields["Temperature"] = f"{latest['temp']} °C"
            if latest and latest["power_on_hours"] is not None:
                fields["Power-on"] = f"{latest['power_on_hours']:,} h"
            if self.cfg.public_url:
                url = f"{self.cfg.public_url}/drive/{drive['id']}"
        serial = drive["serial"] if drive and not drive["serial"].startswith("no-serial:") else ""
        footer = " · ".join(p for p in ("mimamori", host, serial) if p)
        label = {"crit": "Failing", "warn": "Watch", "ok": "OK"}.get(level, "Info")
        if kind == "missing":
            label = "Missing"
        elif kind == "agent_offline":
            label = "Offline"
        ev = make_event(kind, level, f"{label} · {title}", detail, fields=fields, footer=footer,
                        url=url, extra={"host": host, "drive": {k: drive[k] for k in (
                            "device", "model", "serial")} if drive else None})

        def done(channels: list[str]) -> None:
            self.db.execute("UPDATE alerts SET channels = ? WHERE id = ?",
                            (", ".join(channels), alert_id))

        self.notifier.send(ev, done)

    # drives ---------------------------------------------------------------
    def reevaluate(self, drive_id: int) -> None:
        """Recompute a drive's status after its thresholds changed (no alerts)."""
        with self.db.transaction() as conn:
            drive = conn.execute("SELECT * FROM drives WHERE id = ?", (drive_id,)).fetchone()
            latest = conn.execute("SELECT * FROM samples WHERE drive_id = ? ORDER BY ts DESC, "
                                  "id DESC LIMIT 1", (drive_id,)).fetchone()
            if not drive or not latest:
                return
            window = int(self.setting("growth_window_days")) * DAY
            baseline = _baseline(conn, drive_id, latest["id"], latest["ts"] - window)
            issues = find_issues(dict(latest), dict(baseline) if baseline else None,
                                 drive["kind"], self.thresholds_for(dict(drive)))
            old = json.loads(drive["issues"])
            if "missing" in old:
                issues["missing"] = old["missing"]
                status, summary = "missing", old["missing"]["text"]
            else:
                status, summary = status_of(issues), summary_of(issues)
            conn.execute("UPDATE drives SET issues = ?, status = ?, summary = ? WHERE id = ?",
                         (json.dumps(issues), status, summary, drive_id))

    def reevaluate_all(self) -> None:
        for row in self.db.all("SELECT id FROM drives"):
            self.reevaluate(row["id"])

    # periodic jobs --------------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self._loop, name="scheduler", daemon=True).start()

    def _loop(self) -> None:
        last_retention = 0.0
        while not self._stop.wait(30):
            try:
                self.check_offline()
                if time.time() - last_retention > 6 * 3600:
                    self.retention()
                    last_retention = time.time()
                self.maybe_send_report()
            except Exception:  # keep the scheduler alive
                log.exception("Scheduled job failed")

    def check_offline(self) -> None:
        limit = int(time.time()) - int(self.setting("agent_offline_minutes")) * 60
        for agent in self.db.all("SELECT * FROM agents WHERE offline_alerted = 0 "
                                 "AND last_seen IS NOT NULL AND last_seen < ?", (limit,)):
            self.db.execute("UPDATE agents SET offline_alerted = 1 WHERE id = ?", (agent["id"],))
            self._alert(agent["id"], None, "agent_offline", "crit",
                        f"Agent {agent['name']} is offline",
                        f"No heartbeat since {self.clock(agent['last_seen'])}. "
                        "Its drives are not being checked.")

    def retention(self) -> None:
        now = int(time.time())
        cutoff = now - self.cfg.retention_days * DAY
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            # The full attribute tables are only needed for recent history
            conn.execute("UPDATE samples SET attrs = NULL WHERE ts < ? AND attrs IS NOT NULL",
                         (now - 35 * DAY,))

    def next_report_time(self, after: dt.datetime | None = None) -> dt.datetime:
        now = after or dt.datetime.now(self.tz)
        hour, minute = (int(x) for x in str(self.setting("report_time")).split(":"))
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        candidate += dt.timedelta(days=(int(self.setting("report_weekday")) - now.weekday()) % 7)
        if candidate <= now:
            candidate += dt.timedelta(days=7)
        return candidate

    def maybe_send_report(self) -> None:
        if not self.setting("report_enabled"):
            return
        now = dt.datetime.now(self.tz)
        last_due = self.next_report_time(now) - dt.timedelta(days=7)
        last_sent = int(self.setting("report_last_sent"))
        if last_sent >= last_due.timestamp():
            return
        if last_sent == 0 or now - last_due > dt.timedelta(hours=12):
            # First start, or the server was down at that time: no stale report
            self.db.set_setting("report_last_sent", int(now.timestamp()))
            return
        self.send_report()

    def send_report(self) -> None:
        self.db.set_setting("report_last_sent", int(time.time()))
        self.db.set_setting("report_delivered", int(time.time()))
        self.notifier.send(report_event(build_report(self), self.cfg.public_url))


# ============================================================================
# Weekly report
# ============================================================================

STATUS_ORDER = {"failing": 0, "missing": 1, "watch": 2, "healthy": 3}


def build_report(monitor: Monitor) -> dict:
    since = int(time.time()) - 7 * DAY
    drives = [dict(r) for r in monitor.db.all(
        "SELECT d.*, a.name AS host, "
        "(SELECT temp FROM samples s WHERE s.drive_id = d.id ORDER BY ts DESC LIMIT 1) AS temp, "
        "(SELECT MAX(temp) FROM samples s WHERE s.drive_id = d.id AND ts >= ?) AS max_temp "
        "FROM drives d JOIN agents a ON a.id = d.agent_id", (since,))]
    drives.sort(key=lambda d: (STATUS_ORDER.get(d["status"], 9), d["host"], d["device"]))
    alerts = [dict(r) for r in monitor.db.all(
        "SELECT al.*, a.name AS host FROM alerts al LEFT JOIN agents a ON a.id = al.agent_id "
        "WHERE al.ts >= ? ORDER BY al.ts DESC", (since,))]
    attention = [d for d in drives if d["status"] != "healthy"]
    if not drives:
        headline = "No drives reported yet."
    elif not attention:
        headline = "The pond is calm. Every drive is healthy."
    else:
        n = len(attention)
        headline = f"{n} drive{'s' if n != 1 else ''} need{'s' if n == 1 else ''} attention."
    return {
        "generated": int(time.time()), "since": since, "drives": drives, "alerts": alerts,
        "counts": {s: sum(1 for d in drives if d["status"] == s) for s in STATUS_ORDER},
        "warmest": max((d for d in drives if d["max_temp"] is not None),
                       key=lambda d: d["max_temp"], default=None),
        "attention": attention, "headline": headline,
    }


def report_event(data: dict, public_url: str) -> dict:
    lines = [f"{d['status'].upper()} · {d['model']} {d['device']} on {d['host']}: "
             f"{d['summary'] or 'see details'}" for d in data["attention"]]
    lines = lines or ["Nothing needs your attention."]
    lines.append(f"{len(data['alerts'])} alert(s) this week.")
    c = data["counts"]
    fields = {"Healthy": c["healthy"], "Watch": c["watch"], "Failing": c["failing"],
              "Missing": c["missing"]}
    if data["warmest"]:
        w = data["warmest"]
        fields["Warmest this week"] = f"{w['max_temp']} °C · {w['model']} on {w['host']}"
    level = "crit" if c["failing"] or c["missing"] else "warn" if c["watch"] else "ok"
    ev = make_event("report", level, f"Weekly report · {data['headline']}", "\n".join(lines),
                    fields=fields, url=f"{public_url}/report" if public_url else "")
    ev["html"] = _report_html(data, level)
    return ev


def _report_html(data: dict, level: str) -> str:
    e = html.escape
    colors = {"failing": "#EE6A5F", "watch": "#E9B949", "missing": "#98A6BA", "healthy": "#4CC38A"}
    rows = "".join(
        "<tr>"
        f'<td style="color:{colors.get(d["status"], "#98A6BA")};padding:4px 12px 4px 0">{e(d["status"])}</td>'
        f'<td style="color:#EDF1F6;padding:4px 12px 4px 0">{e(d["model"])} '
        f'<span style="color:#98A6BA">{e(d["device"])}</span></td>'
        f'<td style="color:#98A6BA;padding:4px 12px 4px 0">{e(d["host"])}</td>'
        f'<td style="color:#EDF1F6">{"" if d["temp"] is None else e(str(d["temp"])) + " °C"}</td>'
        "</tr>" for d in data["drives"])
    alerts = "".join(f'<li style="color:#C9D2DE">{e(a["title"])}</li>'
                     for a in data["alerts"][:20]) or \
        '<li style="color:#98A6BA">No alerts this week.</li>'
    return ('<div style="background:#0B1220;padding:24px;font-family:sans-serif">'
            f'<div style="background:#131F33;border-top:4px solid #{COLORS[level]:06X};'
            'border-radius:8px;padding:16px">'
            '<p style="color:#98A6BA;margin:0">mimamori · weekly report</p>'
            f'<h2 style="color:#EDF1F6;margin:4px 0 16px">{e(data["headline"])}</h2>'
            f'<table style="border-collapse:collapse;font-size:14px">{rows}</table>'
            '<h3 style="color:#EDF1F6;margin:20px 0 8px">Alerts this week</h3>'
            f'<ul style="padding-left:18px;font-size:14px">{alerts}</ul></div></div>')


# ============================================================================
# Charts: the geometry is computed here and drawn as SVG by the templates, so
# the pages need no JavaScript and the CSP stays strict.
# ============================================================================

MAX_POINTS = 300


def _downsample(points: Sequence[tuple[int, float]], how: str = "max") -> list[tuple[int, float]]:
    if len(points) <= MAX_POINTS:
        return list(points)
    size = len(points) / MAX_POINTS
    out = []
    for i in range(MAX_POINTS):
        bucket = points[int(i * size):int((i + 1) * size)] or [points[-1]]
        out.append((bucket[-1][0], max(v for _, v in bucket) if how == "max" else bucket[-1][1]))
    return out


def sparkline(points: Sequence[tuple[int, float | None]], width: int = 180, height: int = 28) -> str:
    pts = [(t, v) for t, v in points if v is not None]
    if len(pts) < 2:
        return ""
    pts = _downsample(pts)
    t0, t1 = pts[0][0], pts[-1][0]
    lo, hi = min(v for _, v in pts), max(v for _, v in pts)
    if hi - lo < 4:  # keep small wiggles small
        mid = (hi + lo) / 2
        lo, hi = mid - 2, mid + 2
    span_t = max(t1 - t0, 1)
    return " ".join(f"{(t - t0) / span_t * width:.1f},"
                    f"{height - 2 - (v - lo) / (hi - lo) * (height - 4):.1f}" for t, v in pts)


def chart(series: list[dict], t0: int, t1: int, tz: dt.tzinfo, *, width: int = 420,
          height: int = 150, ymin: float | None = None, ymax: float | None = None,
          guide: float | None = None, step: bool = False) -> dict:
    """`series` items: {"points": [(ts, value)], "cls": css class, "area": bool}."""
    left, right, top, bottom = 30, 6, 8, 20
    pw, ph = width - left - right, height - top - bottom
    series = [dict(s, points=[(t, v) for t, v in s["points"] if v is not None]) for s in series]
    values = [v for s in series for _, v in s["points"]] + ([guide] if guide is not None else [])
    lo = ymin if ymin is not None else (min(values) if values else 0)
    hi = ymax if ymax is not None else (max(values) if values else 1)
    if step:  # counters start at zero, so a jump from 0 is visible
        lo = 0 if ymin is None else ymin
        if hi - lo < 1e-9:
            hi = lo + 10
    else:
        if hi - lo < 1e-9:
            lo, hi = lo - 4, hi + 4
        if ymin is None:
            pad = (hi - lo) * 0.08
            lo, hi = lo - pad, hi + pad
    span_t = max(t1 - t0, 1)

    def x(t: int) -> float:
        return left + (t - t0) / span_t * pw

    def y(v: float) -> float:
        return top + ph - (v - lo) / (hi - lo) * ph

    lines = []
    for s in series:
        pts = _downsample(s["points"], "last" if step else "max")
        if not pts:
            continue
        coords: list[str] = []
        prev_y = None
        for t, v in pts:
            if step and prev_y is not None:
                coords.append(f"{x(t):.1f},{prev_y:.1f}")
            prev_y = y(v)
            coords.append(f"{x(t):.1f},{prev_y:.1f}")
        if step:
            coords.append(f"{x(t1):.1f},{prev_y:.1f}")
        line = {"points": " ".join(coords), "cls": s.get("cls", "")}
        if s.get("area") and len(pts) > 1:
            line["area"] = (f"{x(pts[0][0]):.1f},{top + ph:.1f} " + " ".join(coords)
                            + f" {x(pts[-1][0]):.1f},{top + ph:.1f}")
        lines.append(line)

    def label(ts: int) -> str:
        d = dt.datetime.fromtimestamp(ts, tz)
        return f"{d.day} {d.strftime('%b')}"

    return {
        "w": width, "h": height, "left": left, "right": width - right, "lines": lines,
        "grid": [{"y": round(y(lo + (hi - lo) * f), 1), "label": f"{lo + (hi - lo) * f:.0f}"}
                 for f in (0, 0.5, 1)],
        "xlabels": [{"x": left, "label": label(t0), "anchor": "start"},
                    {"x": left + pw / 2, "label": label((t0 + t1) // 2), "anchor": "middle"},
                    {"x": width - right, "label": label(t1), "anchor": "end"}],
        "label_y": height - 5,
        "guide": round(y(guide), 1) if guide is not None and lo <= guide <= hi else None,
        "empty": not any(s["points"] for s in series),
    }


# ============================================================================
# Web page and agent API
# ============================================================================

AGENT_ID = protocol.AGENT_ID
# Redirect targets: local paths only (no "//host", no scheme), so no open redirect
LOCAL_PATH = re.compile(r"^/(?!/)[A-Za-z0-9/_\-]*$")
RANGES = {"7": 7, "30": 30, "90": 90, "365": 365}
NUMBER_WORDS = ["No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
AGENT_IMAGE = "ghcr.io/pascal2108/mimamori-agent:latest"
# Simple brute-force protection: max. 5 failed logins per address in 15 minutes.
# There is no limit across all addresses: anyone could use it to keep the owner locked out.
MAX_TRIES, WINDOW = 5, 15 * 60


class RateLimiter:
    """Failures per key in a sliding window, shared between request threads."""

    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        with self._lock:
            hits = self._hits.get(key)
            while hits and hits[0] < time.monotonic() - self.window:
                hits.popleft()
            return bool(hits) and len(hits) >= self.limit

    def hit(self, key: str) -> None:
        with self._lock:
            if len(self._hits) > 10000:  # bound the memory under a flood
                self._hits.clear()
            self._hits[key].append(time.monotonic())

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


def _secret_key(path: Path) -> bytes:
    if path.exists() and len(path.read_bytes()) >= 32:
        return path.read_bytes()
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _asset_version() -> str:
    """Changes whenever a static file changes, so browsers fetch the new one."""
    digest = hashlib.sha256()
    for path in sorted((BASE_DIR / "static").glob("*")):
        digest.update(path.read_bytes())
    return digest.hexdigest()[:10]


def create_app(cfg: Config | None = None, db: Database | None = None,
               monitor: Monitor | None = None):
    """The server. gunicorn calls it without arguments; tests pass their own parts."""
    from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                       request, session, url_for)
    from werkzeug.middleware.proxy_fix import ProxyFix

    started = cfg is None
    if cfg is None:
        cfg = load_config()
        log_unsafe(cfg)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    db = db or Database(cfg.data_dir / "mimamori.db")
    monitor = monitor or Monitor(db, cfg, Notifier(cfg))
    tz = monitor.tz
    secret_key = _secret_key(cfg.data_dir / "secret_key")
    # The server's own key pair for the agent protocol. Losing it means every agent needs a
    # new key, so it lives next to the database in the data volume.
    server_keys = protocol.ServerKeys(_secret_key(cfg.data_dir / "server_key")[:32])

    app = Flask(__name__, root_path=str(BASE_DIR))
    # UNSAFE_HTTP drops the HTTPS-only flag (and the __Host- prefix, which requires it), so
    # that the browser keeps the cookie over plain HTTP
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_NAME="mimamori" if cfg.unsafe_http else "__Host-mimamori",
        SESSION_COOKIE_SECURE=not cfg.unsafe_http,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=cfg.session_hours),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=64 * 1024,
    )
    # Exactly one proxy in front: only its X-Forwarded-* entries are trusted, so a spoofed
    # header sent by the client is ignored. Without a proxy (BEHIND_PROXY off) the headers are
    # not trusted at all, since a client could otherwise choose its own address.
    if cfg.behind_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    salt = secrets.token_bytes(16)
    password_hash = hashlib.scrypt(cfg.admin_password.encode(), salt=salt, **SCRYPT)
    # Changes with the user name or password, which signs out every older session
    session_epoch = hmac.new(secret_key, b"epoch\0" + cfg.admin_user.encode() + b"\0"
                             + cfg.admin_password.encode(), hashlib.sha256).hexdigest()[:16]
    cfg.admin_password = ""  # only the hash stays in memory
    login_limiter = RateLimiter(MAX_TRIES, WINDOW)
    agent_limiter = RateLimiter(30, 300)
    asset_version = _asset_version()

    # helpers --------------------------------------------------------------
    def client_ip() -> str:
        return request.remote_addr or "?"

    def is_local_host() -> bool:
        # Browsers keep HTTPS-only cookies for these addresses even over plain HTTP
        return request.host.rsplit(":", 1)[0].strip("[]") in ("localhost", "127.0.0.1", "::1")

    def fmt_time(ts: int | None, with_day: bool = True) -> str:
        if not ts:
            return "never"
        d = dt.datetime.fromtimestamp(ts, tz)
        today = dt.datetime.now(tz).date()
        hm = d.strftime("%H:%M")
        if not with_day:
            return hm
        if d.date() == today:
            return f"today {hm}"
        if (today - d.date()).days < 7:
            return f"{d.strftime('%a')} {hm}"
        return f"{d.day} {d.strftime('%b')} {hm}"

    def ago(ts: int | None) -> str:
        if not ts:
            return "never"
        s = max(0, int(time.time()) - ts)
        if s < 90:
            return "just now" if s < 30 else "1 min ago"
        if s < 3600:
            return f"{s // 60} min ago"
        return f"{s // 3600} h ago" if s < DAY else f"{s // DAY} days ago"

    def human_bytes(n: int | None) -> str:
        if not n:
            return ""
        for unit, size in (("TB", 10**12), ("GB", 10**9), ("MB", 10**6)):
            if n >= size:
                v = n / size
                return f"{v:.0f} {unit}" if v >= 10 or v == int(v) else f"{v:.1f} {unit}"
        return f"{n} B"

    app.jinja_env.filters.update(
        time=fmt_time, ago=ago, bytes=human_bytes, kind=kind_label,
        serial=lambda s: "no serial" if s.startswith("no-serial:") else s,
        num=lambda n: "–" if n is None else f"{n:,}")

    def agent_is_online(agent: dict) -> bool:
        limit = int(monitor.setting("agent_offline_minutes")) * 60
        return bool(agent["last_seen"]) and time.time() - agent["last_seen"] < limit

    def unsafe_notes() -> list[dict]:
        """The warnings shown on every page while an unsafe option is in effect.

        "soft" is a quieter line for a setting chosen on purpose; "strong" is for what puts
        this very connection at risk.
        """
        if cfg.unsafe_hide_warnings:  # chosen by the admin: the log is the only warning left
            return []
        notes = []
        if cfg.unsafe_http and not request.is_secure:
            notes.append({"level": "strong", "text": "This connection is not encrypted. Your "
                          "password and all drive data travel in plain text and can be read by "
                          "others on the network."})
        if cfg.unsafe_http_webhooks:
            notes.append({"level": "soft", "text": "UNSAFE_HTTP_WEBHOOKS is on: notifications "
                          "may be sent unencrypted."})
        if cfg.unsafe_smtp_plaintext:
            notes.append({"level": "soft", "text": "UNSAFE_SMTP_PLAINTEXT is on: mail and the "
                          "SMTP password may be sent unencrypted."})
        return notes

    # security hooks -------------------------------------------------------
    public = {"login", "static", "health", "favicon", "agent_heartbeat", "agent_report"}
    agent_api = {"agent_heartbeat", "agent_report"}

    @app.before_request
    def guard():
        endpoint = request.endpoint or ""
        if endpoint in agent_api:
            return None
        if endpoint not in public and (session.get("user") != cfg.admin_user
                                       or session.get("epoch") != session_epoch):
            session.clear()
            if request.method == "GET":
                return redirect(url_for("login", next=request.path))
            abort(401)
        # Every form carries a token only this session knows, so that another website
        # cannot act with the user's cookie (CSRF)
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
                abort(400, "The form has expired. Reload the page and try again.")
        if "csrf" not in session and endpoint not in {"static", "health", "favicon"}:
            session["csrf"] = secrets.token_urlsafe(32)
        return None

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def common() -> dict:
        logged_in = session.get("user") == cfg.admin_user
        last_ts = db.one("SELECT MAX(last_report) AS t FROM agents")["t"] if logged_in else None
        interval = int(monitor.setting("scan_interval_minutes")) * 60
        return {
            "csrf_token": session.get("csrf", ""), "logged_in": logged_in,
            "unsafe_notes": unsafe_notes(), "v": asset_version, "version": VERSION,
            "last_check": last_ts, "next_check": (last_ts + interval) if last_ts else None,
        }

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(409)
    @app.errorhandler(413)
    def error(exc):
        if request.path.startswith("/api/"):
            return jsonify(error=exc.name), exc.code
        return render_template("error.html", error=exc), exc.code

    @app.errorhandler(429)
    def too_many(exc):
        return jsonify(error="too many requests"), 429

    # login ----------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error_msg = ""
        if request.method == "POST":
            ip = client_ip()
            if login_limiter.blocked(ip):
                error_msg = "Too many failed attempts. Wait 15 minutes."
            else:
                user = request.form.get("username", "")[:128]
                password = request.form.get("password", "")[:1024]
                ok_user = hmac.compare_digest(user.encode(), cfg.admin_user.encode())
                ok_pw = hmac.compare_digest(
                    hashlib.scrypt(password.encode(), salt=salt, **SCRYPT), password_hash)
                if ok_user and ok_pw:
                    login_limiter.clear(ip)
                    log.info("Login from %s", ip)
                    if not request.is_secure and not cfg.unsafe_http and not is_local_host():
                        log.warning("Login over plain HTTP: the browser will not keep the session "
                                    "cookie. Open the page through the HTTPS address of your "
                                    "reverse proxy (or, unsafe, set UNSAFE_HTTP).")
                    session.clear()
                    session.permanent = True
                    session.update(user=cfg.admin_user, epoch=session_epoch,
                                   csrf=secrets.token_urlsafe(32))
                    target = request.args.get("next", "")
                    return redirect(target if LOCAL_PATH.match(target) else url_for("overview"))
                login_limiter.hit(ip)
                log.warning("Failed login from %s", ip)
                time.sleep(1)
                error_msg = "Wrong user name or password."
        http_hint = not (cfg.unsafe_http or request.is_secure or is_local_host())
        return render_template("login.html", error=error_msg, http_hint=http_hint)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/health")
    def health():
        return Response("ok", mimetype="text/plain")

    @app.get("/favicon.ico")
    def favicon():
        return app.send_static_file("favicon.ico")

    # agent API ------------------------------------------------------------
    # Every agent message is signed with that agent's key and encrypted (see agent.py).
    # A message that fails counts against the sender's address, like a failed login.
    def agent_message(kind: str) -> tuple[dict, dict, Callable[[dict], Any]]:
        ip = client_ip()
        if agent_limiter.blocked(ip):
            abort(429)
        agent_id = request.headers.get("X-Mimamori-Agent", "")
        row = db.one("SELECT * FROM agents WHERE id = ?", (agent_id,)) \
            if AGENT_ID.match(agent_id) else None
        try:
            if row is None:
                raise protocol.ProtocolError("unknown agent")
            ts, request_e, data = protocol.open_request(
                server_keys, protocol.b64d(row["public_key"], 32), agent_id, kind,
                request.get_json(silent=True))
        except protocol.ProtocolError:
            agent_limiter.hit(ip)
            log.warning("Agent message from %s rejected: unknown agent or wrong key", ip)
            abort(401)
        if abs(time.time() * 1000 - ts) > protocol.MAX_CLOCK_SKEW_MS:
            log.warning("Agent %s: its clock differs from the server's by more than five "
                        "minutes", row["name"])
            abort(409)
        # Each time stamp only once and in increasing order: a recorded message cannot be replayed
        with db.transaction() as conn:
            accepted = conn.execute(
                "UPDATE agents SET last_message = ? WHERE id = ? AND last_message < ?",
                (ts, agent_id, ts)).rowcount == 1
        if not accepted:
            agent_limiter.hit(ip)
            log.warning("Agent %s: a message came twice or out of order and was rejected",
                        row["name"])
            abort(401)
        return dict(row), data, lambda payload: jsonify(protocol.seal_response(
            server_keys, agent_id, kind, ts, request_e, payload))

    @app.post("/api/agent/v1/heartbeat")
    def agent_heartbeat():
        agent, data, reply = agent_message("heartbeat")
        return reply(monitor.heartbeat(agent, clean_text(data.get("version"), 32),
                                       clean_text(data.get("hostname"), 64)))

    @app.post("/api/agent/v1/report")
    def agent_report():
        agent, data, reply = agent_message("report")
        try:
            count = monitor.ingest(agent, data)
        except ValueError:
            abort(400)
        return reply({"ok": True, "drives": count})

    # pages ----------------------------------------------------------------
    def drive_cards() -> tuple[list[dict], list[dict]]:
        agents = [dict(a) for a in db.all("SELECT * FROM agents ORDER BY name COLLATE NOCASE")]
        drives = [dict(d) for d in db.all("SELECT * FROM drives")]
        latest = {r["drive_id"]: dict(r) for r in db.all(
            "SELECT s.* FROM samples s JOIN (SELECT drive_id, MAX(id) AS id FROM samples "
            "GROUP BY drive_id) m ON m.id = s.id")}
        history: dict[int, list] = defaultdict(list)
        for r in db.all("SELECT drive_id, ts, temp FROM samples WHERE ts >= ? ORDER BY ts",
                        (int(time.time()) - 14 * DAY,)):
            history[r["drive_id"]].append((r["ts"], r["temp"]))
        by_agent: dict[str, list] = defaultdict(list)
        for d in drives:
            d["latest"] = latest.get(d["id"], {})
            d["issues"] = json.loads(d["issues"])
            d["spark"] = sparkline(history.get(d["id"], []))
            by_agent[d["agent_id"]].append(d)
        for a in agents:
            a["online"] = agent_is_online(a)
            a["drives"] = sorted(by_agent.get(a["id"], []),
                                 key=lambda d: (STATUS_ORDER.get(d["status"], 9), d["device"]))
        return agents, drives

    def headline(agents: list[dict], drives: list[dict]) -> tuple[str, str]:
        if not drives:
            return "The pond is still.", "No drives have reported yet."
        attention = [d for d in drives if d["status"] != "healthy"]
        if not attention:
            return "The pond is calm.", ""
        n = len(attention)
        count = NUMBER_WORDS[n] if n < len(NUMBER_WORDS) else str(n)
        hosts = {d["agent_id"] for d in attention}
        where = ""
        if len(hosts) == 1 and len(agents) > 1:
            where = " on " + next(a["name"] for a in agents if a["id"] in hosts)
        lead = "The pond is mostly calm." if n < len(drives) else "The pond is restless."
        return lead, f"{count} drive{'s' if n != 1 else ''}{where} need{'s' if n == 1 else ''} you."

    @app.get("/")
    def overview():
        agents, drives = drive_cards()
        lead, attention = headline(agents, drives)
        warm = [d for d in drives if d["latest"].get("temp") is not None and d["status"] != "missing"]
        return render_template(
            "overview.html", agents=agents, drives=drives, lead=lead, attention=attention,
            counts={s: sum(1 for d in drives if d["status"] == s) for s in STATUS_ORDER},
            warmest=max(warm, key=lambda d: d["latest"]["temp"], default=None),
            alerts=db.all("SELECT al.*, a.name AS host FROM alerts al LEFT JOIN agents a "
                          "ON a.id = al.agent_id ORDER BY al.ts DESC, al.id DESC LIMIT 5"),
            today=dt.datetime.now(tz),
            report_next=monitor.next_report_time() if monitor.setting("report_enabled") else None,
            report_last=int(monitor.setting("report_delivered")),
            channels=monitor.notifier.configured())

    def get_drive(drive_id: int) -> dict:
        row = db.one("SELECT d.*, a.name AS host, a.location FROM drives d JOIN agents a "
                     "ON a.id = d.agent_id WHERE d.id = ?", (drive_id,))
        if row is None:
            abort(404)
        return dict(row)

    @app.get("/drive/<int:drive_id>")
    def drive(drive_id: int):
        d = get_drive(drive_id)
        d["issues"] = json.loads(d["issues"])
        days = RANGES.get(request.args.get("range", "30"), 30)
        now = int(time.time())
        since = now - days * DAY
        samples = [dict(r) for r in db.all(
            "SELECT ts, temp, reallocated, pending, uncorrectable, crc_errors, media_errors, wear "
            "FROM samples WHERE drive_id = ? AND ts >= ? ORDER BY ts", (drive_id, since))]
        latest = db.one("SELECT * FROM samples WHERE drive_id = ? ORDER BY ts DESC, id DESC "
                        "LIMIT 1", (drive_id,))
        latest = dict(latest) if latest else {}
        week_ago = db.one(
            "SELECT * FROM samples WHERE drive_id = ? AND ts <= ? AND attrs IS NOT NULL "
            "ORDER BY ts DESC LIMIT 1", (drive_id, now - 7 * DAY)) or db.one(
            "SELECT * FROM samples WHERE drive_id = ? AND attrs IS NOT NULL ORDER BY ts LIMIT 1",
            (drive_id,))
        week_ago = dict(week_ago) if week_ago else {}
        thresholds = monitor.thresholds_for(d)
        temp_limits = thresholds["temp"].get(d["kind"]) or thresholds["temp"]["unknown"]

        attrs = json.loads(latest.get("attrs") or "[]")
        old_attrs = {(a["id"], a["name"]): a for a in json.loads(week_ago.get("attrs") or "[]")}
        for a in attrs:
            old = old_attrs.get((a["id"], a["name"]))
            a["delta"] = (a["raw"] - old["raw"]) if old and a["raw"] is not None \
                and old["raw"] is not None else None

        def series(key: str) -> list:
            return [(s["ts"], s[key]) for s in samples]

        def delta(key: str) -> int | None:
            if latest.get(key) is None or week_ago.get(key) is None:
                return None
            return latest[key] - week_ago[key]

        has = {k: any(s[k] is not None for s in samples) for k in (
            "reallocated", "pending", "uncorrectable", "crc_errors", "media_errors", "wear")}
        sectors = [{"points": series("reallocated"), "cls": "line-crit"},
                   {"points": series("pending"), "cls": "line-warn"}]
        if not has["reallocated"] and not has["pending"] and has["media_errors"]:
            sectors = [{"points": series("media_errors"), "cls": "line-crit"}]
        charts = {
            "temp": chart([{"points": series("temp"), "cls": "line-ok", "area": True}],
                          since, now, tz, guide=temp_limits["warn"]),
            "sectors": chart(sectors, since, now, tz, step=True),
            "crc": chart([{"points": series("crc_errors"), "cls": "line-ok"}], since, now, tz,
                         step=True),
            "uncorrectable": chart([{"points": series("uncorrectable"), "cls": "line-warn"}],
                                   since, now, tz, step=True),
            "wear": chart([{"points": series("wear"), "cls": "line-warn"}], since, now, tz,
                          ymin=0, ymax=100),
        }
        return render_template(
            "drive.html", d=d, latest=latest, attrs=attrs, charts=charts, has=has, delta=delta,
            range_days=days, ranges=RANGES, temp_limits=temp_limits, thresholds=thresholds,
            overrides=json.loads(d["overrides"]), growth_choices=GROWTH_CHOICES,
            alerts=db.all("SELECT * FROM alerts WHERE drive_id = ? ORDER BY ts DESC, id DESC "
                          "LIMIT 8", (drive_id,)),
            growth_days=int(monitor.setting("growth_window_days")))

    def form_int(name: str, lo: int, hi: int, *, optional: bool = False) -> int | None:
        raw = request.form.get(name, "").strip()
        if raw == "" and optional:
            return None
        try:
            v = int(raw)
        except ValueError:
            abort(400, f"{name} must be a whole number")
        if not lo <= v <= hi:
            abort(400, f"{name} must be between {lo} and {hi}")
        return v

    def threshold_form(kinds: tuple[str, ...]) -> dict:
        """The threshold fields present in the form; an empty field turns that limit off."""
        out: dict[str, Any] = {"temp": {}}
        for kind in kinds:
            pair = {lvl: form_int(f"temp_{kind}_{lvl}", 0, 120, optional=True)
                    for lvl in ("warn", "crit") if f"temp_{kind}_{lvl}" in request.form}
            if pair:
                out["temp"][kind] = pair
        if not out["temp"]:
            del out["temp"]
        for metric in ("wear", *COUNTERS):
            hi = 100 if metric == "wear" else 10**9
            conf: dict[str, Any] = {lvl: form_int(f"{metric}_{lvl}", 0, hi, optional=True)
                                    for lvl in ("warn", "crit")
                                    if f"{metric}_{lvl}" in request.form}
            growth = request.form.get(f"{metric}_growth", "")
            if growth in GROWTH_CHOICES and metric != "wear":
                conf["growth"] = growth
            if conf:
                out[metric] = conf
        return out

    @app.post("/drive/<int:drive_id>/thresholds")
    def drive_thresholds(drive_id: int):
        d = get_drive(drive_id)
        overrides = {} if request.form.get("reset") else threshold_form((d["kind"],))
        # Store only what differs from the global settings
        base = merge_thresholds(monitor.setting("thresholds"), None)
        if "temp" in overrides:
            gbase = base["temp"].get(d["kind"], base["temp"]["unknown"])
            pair = {k: v for k, v in overrides["temp"].get(d["kind"], {}).items()
                    if gbase.get(k) != v}
            if pair:
                overrides["temp"] = {d["kind"]: pair}
            else:
                del overrides["temp"]
        for metric in [m for m in overrides if m != "temp"]:
            overrides[metric] = {k: v for k, v in overrides[metric].items()
                                 if base[metric].get(k) != v}
            if not overrides[metric]:
                del overrides[metric]
        db.execute("UPDATE drives SET overrides = ? WHERE id = ?", (json.dumps(overrides), drive_id))
        monitor.reevaluate(drive_id)
        flash("Thresholds saved." if overrides else "Using the global thresholds.")
        return redirect(url_for("drive", drive_id=drive_id) + "#thresholds")

    @app.post("/drive/<int:drive_id>/mute")
    def drive_mute(drive_id: int):
        d = get_drive(drive_id)
        db.execute("UPDATE drives SET muted = ? WHERE id = ?", (0 if d["muted"] else 1, drive_id))
        flash("Alerts unmuted." if d["muted"] else
              "Alerts muted. They still show up here, but no notifications are sent.")
        return redirect(url_for("drive", drive_id=drive_id))

    @app.post("/drive/<int:drive_id>/forget")
    def drive_forget(drive_id: int):
        get_drive(drive_id)
        db.execute("DELETE FROM drives WHERE id = ?", (drive_id,))
        flash("Drive and its history removed.")
        return redirect(url_for("overview"))

    @app.get("/alerts")
    def alerts():
        page = max(1, min(request.args.get("page", 1, type=int) or 1, 10000))
        per = 50
        rows = db.all("SELECT al.*, a.name AS host FROM alerts al "
                      "LEFT JOIN agents a ON a.id = al.agent_id "
                      "ORDER BY al.ts DESC, al.id DESC LIMIT ? OFFSET ?",
                      (per + 1, (page - 1) * per))
        return render_template("alerts.html", alerts=rows[:per], page=page,
                               has_next=len(rows) > per)

    @app.get("/report")
    def report_page():
        return render_template(
            "report.html", r=build_report(monitor), enabled=monitor.setting("report_enabled"),
            next_time=monitor.next_report_time(), channels=monitor.notifier.configured(),
            last_sent=int(monitor.setting("report_delivered")))

    @app.post("/report/send")
    def report_send():
        if monitor.notifier.configured():
            monitor.send_report()
            flash("The weekly report is on its way.")
        else:
            flash("No notification channel is configured.", "error")
        return redirect(url_for("report_page"))

    @app.post("/check-now")
    def check_now():
        monitor.request_scan()
        flash("Agents will check their drives within a minute.")
        back = request.form.get("back", "")
        return redirect(back if LOCAL_PATH.match(back) else url_for("overview"))

    @app.post("/notify/test")
    def notify_test():
        if monitor.notifier.configured():
            monitor.notifier.send(make_event(
                "test", "ok", "Test notification",
                "If you can read this, mimamori can reach you here.",
                fields={"Sent from": "Settings"}))
            flash("Test notification sent to " + ", ".join(monitor.notifier.configured()) + ".")
        else:
            flash("No notification channel is configured. See secrets.env.example.", "error")
        return redirect(url_for("settings") + "#notifications")

    # settings -------------------------------------------------------------
    @app.get("/settings")
    def settings():
        agents = [dict(a) for a in db.all(
            "SELECT a.*, (SELECT COUNT(*) FROM drives d WHERE d.agent_id = a.id) AS drive_count "
            "FROM agents a ORDER BY name COLLATE NOCASE")]
        for a in agents:
            a["online"] = agent_is_online(a)
        return render_template(
            "settings.html", agents=agents, s={k: monitor.setting(k) for k in (
                "scan_interval_minutes", "agent_offline_minutes", "growth_window_days",
                "report_enabled", "report_weekday", "report_time")},
            thresholds=monitor.thresholds_for(None), kinds=KINDS, counters=COUNTERS,
            growth_choices=GROWTH_CHOICES, channels=monitor.notifier.channels(),
            weekdays=WEEKDAYS, tz_name=str(tz))

    @app.post("/settings/general")
    def settings_general():
        db.set_setting("scan_interval_minutes", form_int("scan_interval_minutes", 5, 1440))
        db.set_setting("agent_offline_minutes", form_int("agent_offline_minutes", 3, 1440))
        db.set_setting("growth_window_days", form_int("growth_window_days", 1, 90))
        monitor.reevaluate_all()
        flash("Settings saved.")
        return redirect(url_for("settings") + "#checks")

    @app.post("/settings/thresholds")
    def settings_thresholds():
        db.set_setting("thresholds", {} if request.form.get("reset") else threshold_form(KINDS))
        monitor.reevaluate_all()
        flash("Global thresholds saved.")
        return redirect(url_for("settings") + "#thresholds")

    @app.post("/settings/report")
    def settings_report():
        t = request.form.get("report_time", "")
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", t):
            abort(400, "The time must look like 09:00")
        db.set_setting("report_enabled", bool(request.form.get("report_enabled")))
        db.set_setting("report_weekday", form_int("report_weekday", 0, 6))
        db.set_setting("report_time", t)
        flash("Weekly report schedule saved.")
        return redirect(url_for("settings") + "#report")

    def agent_name_form() -> tuple[str, str]:
        name = clean_text(request.form.get("name", ""), 48)
        if not name:
            abort(400, "The agent needs a name.")
        return name, clean_text(request.form.get("location", ""), 48)

    def get_agent(agent_id: str) -> dict:
        row = db.one("SELECT * FROM agents WHERE id = ?", (agent_id,)) \
            if AGENT_ID.match(agent_id) else None
        if row is None:
            abort(404)
        return dict(row)

    def render_token(agent_id: str, token: str):
        # Shown once: the server keeps only the agent's public key
        return render_template("agent_token.html", agent=get_agent(agent_id), token=token,
                               image=AGENT_IMAGE,
                               server_url=cfg.public_url or request.host_url.rstrip("/"))

    @app.post("/agents")
    def agent_create():
        name, location = agent_name_form()
        agent_id = secrets.token_hex(6)
        token, public = server_keys.new_agent_key(agent_id)
        db.execute("INSERT INTO agents (id, name, location, public_key, created_at) "
                   "VALUES (?, ?, ?, ?, ?)", (agent_id, name, location, public, int(time.time())))
        log.info("Agent %s added", name)
        return render_token(agent_id, token)

    @app.post("/agents/<agent_id>/token")
    def agent_token(agent_id: str):
        agent = get_agent(agent_id)
        token, public = server_keys.new_agent_key(agent["id"])
        db.execute("UPDATE agents SET public_key = ?, last_message = 0 WHERE id = ?",
                   (public, agent["id"]))
        log.info("New key for agent %s", agent["name"])
        return render_token(agent["id"], token)

    @app.post("/agents/<agent_id>/edit")
    def agent_edit(agent_id: str):
        agent = get_agent(agent_id)
        name, location = agent_name_form()
        db.execute("UPDATE agents SET name = ?, location = ? WHERE id = ?",
                   (name, location, agent["id"]))
        flash("Agent saved.")
        return redirect(url_for("settings") + "#agents")

    @app.post("/agents/<agent_id>/delete")
    def agent_delete(agent_id: str):
        agent = get_agent(agent_id)
        db.execute("DELETE FROM agents WHERE id = ?", (agent["id"],))
        log.info("Agent %s removed", agent["name"])
        flash(f"Agent {agent['name']} and the history of its drives were removed.")
        return redirect(url_for("settings") + "#agents")

    if started:
        monitor.start()
        channels = monitor.notifier.configured()
        log.info("mimamori %s started, notifications: %s", VERSION,
                 ", ".join(channels) if channels else "none configured")
    return app


def health() -> int:
    """Container health check: does the server answer on its port?"""
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=5) as resp:
            return 0 if resp.status == 200 else 1
    except OSError:
        return 1


if __name__ == "__main__":
    if sys.argv[1:] == ["health"]:
        sys.exit(health())
    print("usage: python app.py health   (the server runs with gunicorn 'app:create_app()')",
          file=sys.stderr)
    sys.exit(2)
