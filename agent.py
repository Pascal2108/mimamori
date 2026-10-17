"""mimamori agent: reads the SMART data of this host's drives and reports it to the server.

    python agent.py          run the agent
    python agent.py health   container health check

The agent only connects out to the server; it opens no port. Every message in both
directions is encrypted, signed and accepted only once, so nobody in between can read,
change, forge or replay one, whether the transport is HTTPS through a reverse proxy or plain
HTTP inside a Docker network. The server stores only the agent's public key.

The server imports the protocol functions from this file, so both sides share one version.
"""

from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

log = logging.getLogger("mimamori.agent")

VERSION = os.environ.get("APP_VERSION", "dev")

# ============================================================================
# Protocol, shared with the server
#
# Keys
#   Each agent has an Ed25519 key pair. The server keeps only the public key, so a copy of
#   the server's data cannot be used to pose as an agent.
#   The server has its own key pair (Ed25519 to sign, X25519 to receive encrypted messages).
#   AGENT_KEY = "<agent id>.<agent private key + the server's two public keys>"
#
# A request  POST /api/agent/v1/<kind>, header X-Mimamori-Agent: <agent id>
#   {"ts": ms, "e": one-time X25519 public key, "n": nonce, "c": AES-256-GCM ciphertext,
#    "s": Ed25519 signature of the agent}
#   Encrypted to the server's X25519 key with a one-time key; agent id, kind, time stamp and
#   the one-time key are bound into it. The server checks the signature first, accepts each
#   time stamp only once and in increasing order (no replay), then decrypts.
# The answer
#   {"e": the server's one-time key, "n", "c", "s": signature of the server}
#   Encrypted to the request's one-time key and bound to that request, so it is readable
#   only by that request's sender and cannot be moved to another request.
# One-time keys on both sides mean that a stolen agent key cannot decrypt recorded reports,
# and a stolen server key cannot decrypt recorded answers.
# ============================================================================

PROTOCOL = "mimamori-agent-v1"
AGENT_ID = re.compile(r"^[a-f0-9]{12}$")
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000


class ProtocolError(ValueError):
    """A message that is malformed, forged, tampered with or meant for someone else."""


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text: Any, length: int | None = None) -> bytes:
    if not isinstance(text, str) or len(text) > 16 * 1024 * 1024:
        raise ProtocolError("not base64")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise ProtocolError("not base64") from None
    if length is not None and len(raw) != length:
        raise ProtocolError("wrong length")
    return raw


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


class ServerKeys:
    """The server's own key pair, derived from one 32-byte secret kept on the server."""

    def __init__(self, seed: bytes):
        self.sign = Ed25519PrivateKey.from_private_bytes(_hkdf(seed, f"{PROTOCOL} sign".encode()))
        self.kx = X25519PrivateKey.from_private_bytes(_hkdf(seed, f"{PROTOCOL} kx".encode()))
        self.sign_public = raw_public(self.sign)
        self.kx_public = raw_public(self.kx)

    def new_agent_key(self, agent_id: str) -> tuple[str, str]:
        """Returns (AGENT_KEY for agent.env, the agent's public key to store)."""
        private = os.urandom(32)
        public = raw_public(Ed25519PrivateKey.from_private_bytes(private))
        blob = private + self.sign_public + self.kx_public
        return f"{agent_id}.{b64e(blob)}", b64e(public)


def parse_agent_key(agent_key: str) -> tuple[str, Ed25519PrivateKey, Ed25519PublicKey,
                                             X25519PublicKey]:
    """AGENT_KEY -> (agent id, agent signing key, server signing key, server encryption key)."""
    agent_id, _, blob = agent_key.strip().partition(".")
    try:
        raw = b64d(blob, 96)
    except ProtocolError:
        raw = b""
    if not AGENT_ID.match(agent_id) or not raw:
        raise ProtocolError("AGENT_KEY is incomplete; copy the whole line from Settings → Agents")
    return (agent_id, Ed25519PrivateKey.from_private_bytes(raw[:32]),
            Ed25519PublicKey.from_public_bytes(raw[32:64]),
            X25519PublicKey.from_public_bytes(raw[64:]))


def _aad(direction: str, agent_id: str, kind: str, ts: int, *keys: bytes) -> bytes:
    return "|".join([PROTOCOL, direction, agent_id, kind, str(ts), *map(b64e, keys)]).encode()


def _encrypt(secret: bytes, aad: bytes, payload: dict) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    body = json.dumps(payload, separators=(",", ":")).encode()
    return nonce, AESGCM(_hkdf(secret, aad)).encrypt(nonce, body, aad)


def _decrypt(secret: bytes, aad: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    try:
        data = json.loads(AESGCM(_hkdf(secret, aad)).decrypt(nonce, ciphertext, aad))
    except (InvalidTag, ValueError):
        raise ProtocolError("message not readable") from None
    if not isinstance(data, dict):
        raise ProtocolError("not an object")
    return data


def _fields(box: Any) -> tuple[bytes, bytes, bytes, bytes]:
    if not isinstance(box, dict):
        raise ProtocolError("not a message")
    return b64d(box.get("e"), 32), b64d(box.get("n"), 12), b64d(box.get("c")), b64d(box.get("s"), 64)


def seal_request(agent_id: str, sign: Ed25519PrivateKey, server_kx: X25519PublicKey, kind: str,
                 ts: int, payload: dict) -> tuple[dict, X25519PrivateKey]:
    """Agent side. Returns the request body and the one-time key needed for the answer."""
    once = X25519PrivateKey.generate()
    e = raw_public(once)
    aad = _aad("request", agent_id, kind, ts, e)
    nonce, ct = _encrypt(once.exchange(server_kx), aad, payload)
    sig = sign.sign(aad + b"\0" + nonce + ct)
    return {"ts": ts, "e": b64e(e), "n": b64e(nonce), "c": b64e(ct), "s": b64e(sig)}, once


def open_request(server: ServerKeys, agent_public: bytes, agent_id: str, kind: str,
                 body: Any) -> tuple[int, bytes, dict]:
    """Server side. Checks the agent's signature, then decrypts. Returns (ts, e, payload).
    The caller still has to check the time stamp against replay."""
    ts = body.get("ts") if isinstance(body, dict) else None
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise ProtocolError("no time stamp")
    e, nonce, ct, sig = _fields(body)
    aad = _aad("request", agent_id, kind, ts, e)
    try:
        Ed25519PublicKey.from_public_bytes(agent_public).verify(sig, aad + b"\0" + nonce + ct)
    except (InvalidSignature, ValueError):
        raise ProtocolError("not signed by this agent") from None
    secret = server.kx.exchange(X25519PublicKey.from_public_bytes(e))
    return ts, e, _decrypt(secret, aad, nonce, ct)


def seal_response(server: ServerKeys, agent_id: str, kind: str, ts: int, request_e: bytes,
                  payload: dict) -> dict:
    """Server side: the answer, readable only with the request's one-time key."""
    once = X25519PrivateKey.generate()
    e = raw_public(once)
    aad = _aad("response", agent_id, kind, ts, request_e, e)
    nonce, ct = _encrypt(once.exchange(X25519PublicKey.from_public_bytes(request_e)), aad, payload)
    sig = server.sign.sign(aad + b"\0" + nonce + ct)
    return {"e": b64e(e), "n": b64e(nonce), "c": b64e(ct), "s": b64e(sig)}


def open_response(once: X25519PrivateKey, server_sign: Ed25519PublicKey, agent_id: str,
                  kind: str, ts: int, box: Any) -> dict:
    """Agent side. Checks the server's signature, then decrypts."""
    e, nonce, ct, sig = _fields(box)
    aad = _aad("response", agent_id, kind, ts, raw_public(once), e)
    try:
        server_sign.verify(sig, aad + b"\0" + nonce + ct)
    except InvalidSignature:
        raise ProtocolError("not signed by the server") from None
    return _decrypt(once.exchange(X25519PublicKey.from_public_bytes(e)), aad, nonce, ct)


# ============================================================================
# Client
# ============================================================================

class AgentClient:
    def __init__(self, url: str, agent_key: str):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("SERVER_URL must look like https://mimamori.example.com "
                             "or http://mimamori:8000")
        self.agent_id, self.sign, self.server_sign, self.server_kx = parse_agent_key(agent_key)
        self.https = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.https else 80)
        self.prefix = parts.path.rstrip("/")
        self.ctx = ssl.create_default_context()
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._last_ts = 0

    def _timestamp(self) -> int:
        # Strictly increasing, as the server accepts each time stamp only once and in order
        self._last_ts = max(int(time.time() * 1000), self._last_ts + 1)
        return self._last_ts

    def post(self, kind: str, payload: dict) -> dict:
        ts = self._timestamp()
        body, once = seal_request(self.agent_id, self.sign, self.server_kx, kind, ts, payload)
        conn: http.client.HTTPConnection = (
            http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=60)
            if self.https else http.client.HTTPConnection(self.host, self.port, timeout=60))
        try:
            conn.request("POST", f"{self.prefix}/api/agent/v1/{kind}",
                         body=json.dumps(body, separators=(",", ":")).encode(), headers={
                             "X-Mimamori-Agent": self.agent_id,
                             "Content-Type": "application/json",
                             "User-Agent": f"mimamori-agent/{VERSION}"})
            resp = conn.getresponse()
            data = resp.read(1024 * 1024)
        finally:
            conn.close()
        if resp.status == 401:
            raise PermissionError("the server did not accept AGENT_KEY")
        if resp.status == 409:
            raise RuntimeError("the clocks of this host and the server differ by more than five "
                               "minutes; check the time synchronisation")
        if resp.status != 200:
            raise RuntimeError(f"the server answered HTTP {resp.status}")
        try:
            return open_response(once, self.server_sign, self.agent_id, kind, ts, json.loads(data))
        except (ProtocolError, ValueError):
            raise ProtocolError("the answer is not from the mimamori server that issued this "
                                "AGENT_KEY") from None


# ============================================================================
# Reading the drives
# ============================================================================

DEVICE_PATH = re.compile(r"^/dev/[A-Za-z0-9_\-/.]{1,64}$")
DEVTYPE = re.compile(r"^[A-Za-z0-9_,+\-]{1,32}$")
SMARTCTL_TIMEOUT = 90
# Only what the server needs: error and self-test logs stay on the host
KEEP_KEYS = {
    "device", "model_name", "serial_number", "firmware_version", "user_capacity",
    "rotation_rate", "smart_status", "temperature", "power_on_time", "ata_smart_attributes",
    "nvme_smart_health_information_log", "scsi_grown_defect_list", "scsi_vendor", "scsi_product",
}


def _smartctl(args: list[str]) -> dict | None:
    try:
        proc = subprocess.run(["smartctl", "--json=c", *args], capture_output=True,
                              timeout=SMARTCTL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        log.warning("smartctl timed out for %s", args[-1])
        return None
    try:
        data = json.loads(proc.stdout or b"{}")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def find_devices() -> list[tuple[str, str]]:
    configured = os.environ.get("DEVICES", "").strip()
    out: list[tuple[str, str]] = []
    if configured:
        for item in (i.strip() for i in configured.split(",")):
            dev, _, dtype = item.partition(":")
            if DEVICE_PATH.match(dev) and (not dtype or DEVTYPE.match(dtype)):
                out.append((dev, dtype))
            elif item:
                log.warning("Ignoring invalid entry in DEVICES: %r", item[:80])
        return out
    scan = _smartctl(["--scan-open"]) or {}
    seen = set()
    for d in scan.get("devices") if isinstance(scan.get("devices"), list) else []:
        name, dtype = d.get("name", ""), d.get("type", "")
        if isinstance(name, str) and DEVICE_PATH.match(name) and name not in seen:
            seen.add(name)
            out.append((name, dtype if isinstance(dtype, str) and DEVTYPE.match(dtype) else ""))
    return out


def scan_devices() -> list[dict]:
    results = []
    for dev, dtype in find_devices():
        # -n standby: a sleeping drive is not woken up for the check
        data = _smartctl(["-a", "-n", "standby", *(["-d", dtype] if dtype else []), dev])
        if data is None:
            continue
        trimmed = {k: v for k, v in data.items() if k in KEEP_KEYS}
        messages = data.get("smartctl", {}).get("messages") if isinstance(
            data.get("smartctl"), dict) else None
        if isinstance(messages, list):
            trimmed["smartctl"] = {"messages": messages[:10]}
        results.append({"device": dev, "smartctl": trimmed})
    return results


# ============================================================================
# Main loop
# ============================================================================

# /tmp in the container; the temp folder when the agent runs directly on a host
ALIVE_FILE = Path(tempfile.gettempdir()) / "mimamori-agent-alive"
_stop = threading.Event()


def _idle(reason: str) -> int:
    # Waiting instead of exiting avoids a restart loop that floods the log
    log.error("%s The agent waits until it is configured and restarted.", reason)
    while not _stop.wait(3600):
        pass
    return 1


def run() -> int:
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    ALIVE_FILE.unlink(missing_ok=True)
    url = os.environ.get("SERVER_URL", "").strip()
    agent_key = os.environ.pop("AGENT_KEY", "").strip()
    if not url or not agent_key:
        return _idle("SERVER_URL and AGENT_KEY must be set in agent.env. Add an agent under "
                     "Settings → Agents on the mimamori page to get them.")
    try:
        client = AgentClient(url, agent_key)
    except ValueError as exc:
        return _idle(f"{exc}.")
    name = os.environ.get("AGENT_NAME", "").strip() or socket.gethostname()
    log.info("mimamori agent %s started, reporting to %s (end-to-end encrypted%s)",
             VERSION, client.host, ", over HTTPS" if client.https else "")

    next_scan, interval, beat = 0.0, 3600, 60
    while not _stop.is_set():
        try:
            info = client.post("heartbeat", {"version": VERSION, "hostname": name})
            ALIVE_FILE.touch()
            interval = max(300, int(info.get("scan_interval", interval)))
            beat = max(15, min(600, int(info.get("heartbeat_interval", beat))))
            if info.get("scan_now") or time.time() >= next_scan:
                devices = scan_devices()
                result = client.post("report", {"version": VERSION, "hostname": name,
                                                "devices": devices})
                log.info("Reported %d device(s), the server tracks %s drive(s)", len(devices),
                         result.get("drives"))
                next_scan = time.time() + interval
        except PermissionError as exc:
            log.error("%s. Copy the current key from Settings → Agents into agent.env, or "
                      "create a new one there.", exc)
            _stop.wait(300)
            continue
        except ProtocolError as exc:
            log.error("%s. Check SERVER_URL and AGENT_KEY.", exc)
            _stop.wait(300)
            continue
        except ssl.SSLCertVerificationError as exc:
            log.error("The server's certificate is not trusted: %s", exc.verify_message)
            _stop.wait(300)
            continue
        except (OSError, RuntimeError, ValueError, http.client.HTTPException) as exc:
            log.warning("Cannot reach the server: %s", str(exc)[:200] or type(exc).__name__)
            _stop.wait(60)
            continue
        _stop.wait(beat)
    return 0


def health() -> int:
    """Healthy when the last heartbeat the server answered is less than five minutes old."""
    try:
        return 0 if time.time() - ALIVE_FILE.stat().st_mtime < 5 * 60 else 1
    except OSError:
        return 1


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    sys.exit(health() if sys.argv[1:] == ["health"] else run())
