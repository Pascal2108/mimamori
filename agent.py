"""mimamori agent: reads the SMART data of this host's drives (and, if mounted, the host's
installed packages) and reports it to the server.

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
from typing import Any, Callable

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
#
# The agent only collects: it sends smartctl's own output and the server interprets it. So a
# newer server can read more from the same data, and an agent pinned to an older version keeps
# working with every newer server.
# ============================================================================

DEVICE_PATH = re.compile(r"^/dev/[A-Za-z0-9_\-/.]{1,64}$")
DEVTYPE = re.compile(r"^[A-Za-z0-9_,+\-]{1,32}$")
SMARTCTL_TIMEOUT = 90
MAX_SCAN_BYTES = 8 * 1024 * 1024


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
        # Read-only queries; -n standby: a sleeping drive is not woken up for the check
        data = _smartctl(["-a", "-n", "standby", *(["-d", dtype] if dtype else []), dev])
        if data is None:
            continue
        # Everything about the drive; nothing about the host (kernel version, local time)
        report = {k: v for k, v in data.items() if k not in {"smartctl", "local_time"}}
        messages = data.get("smartctl", {}).get("messages") if isinstance(
            data.get("smartctl"), dict) else None
        if isinstance(messages, list):
            report["smartctl"] = {"messages": messages[:10]}
        results.append({"device": dev, "smartctl": report})
    return results


# ============================================================================
# Installed packages of the host (optional)
#
# Only when the host's package database is mounted read-only under /host (see
# docker-compose.agent.yml). The agent sends the raw fields; the server works out which
# security updates are missing, so an older agent profits from a newer server here, too.
# Without the mounts nothing about the host is sent.
# ============================================================================

HOST_ROOT = Path(os.environ.get("HOST_ROOT", "/host"))
MAX_PACKAGES = 20000
MAX_FIELD = 200
DPKG_FIELDS = {"Package", "Status", "Version", "Source", "Architecture"}
APK_FIELDS = {"P": "name", "V": "version", "o": "origin", "A": "arch"}


def _read_os_release(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            key, sep, value = line.strip().partition("=")
            if sep and re.match(r"^[A-Z_]{1,32}$", key) and len(out) < 64:
                out[key] = value.strip().strip("\"'")[:MAX_FIELD]
    return out


def _read_dpkg(path: Path) -> list[list[str]]:
    """[Package, Version, Source, Architecture, Status] per stanza of /var/lib/dpkg/status."""
    out: list[list[str]] = []
    entry: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                if entry.get("Package"):
                    out.append([entry.get(k, "") for k in
                                ("Package", "Version", "Source", "Architecture", "Status")])
                    if len(out) >= MAX_PACKAGES:
                        return out
                entry = {}
                continue
            key, sep, value = line.partition(":")
            if sep and not line[0].isspace() and key in DPKG_FIELDS:
                entry[key] = value.strip()[:MAX_FIELD]
    if entry.get("Package"):
        out.append([entry.get(k, "") for k in
                    ("Package", "Version", "Source", "Architecture", "Status")])
    return out[:MAX_PACKAGES]


def _read_apk(path: Path) -> list[list[str]]:
    """[name, version, origin, arch] per package of /lib/apk/db/installed."""
    out: list[list[str]] = []
    entry: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in [*f, "\n"]:
            if not line.strip():
                if entry.get("name"):
                    out.append([entry.get(k, "") for k in ("name", "version", "origin", "arch")])
                    if len(out) >= MAX_PACKAGES:
                        break
                entry = {}
            elif line[1:2] == ":" and line[0] in APK_FIELDS:
                entry[APK_FIELDS[line[0]]] = line[2:].strip()[:MAX_FIELD]
    return out


def read_host() -> dict | None:
    """The host's OS and installed packages, or None when they are not mounted."""
    sources = (("dpkg", HOST_ROOT / "var/lib/dpkg/status", _read_dpkg),
               ("apk", HOST_ROOT / "lib/apk/db/installed", _read_apk))
    host: dict[str, Any] = {}
    try:
        if (HOST_ROOT / "etc/os-release").is_file():
            host["os_release"] = _read_os_release(HOST_ROOT / "etc/os-release")
        for kind, path, reader in sources:
            if path.is_file():
                host["packages"] = {"type": kind, "list": reader(path)}
                break
    except OSError as exc:
        log.warning("Cannot read the host's packages under %s: %s", HOST_ROOT,
                    exc.strerror or type(exc).__name__)
        return None
    if not host:
        return None
    # The container shares the host's kernel: this is the kernel the host runs right now
    host["kernel"] = os.uname().release if hasattr(os, "uname") else ""
    return host


# ============================================================================
# Privilege separation
#
# Reading raw drives needs root and the capabilities SYS_RAWIO / SYS_ADMIN. Talking to the
# network does not. So the agent splits itself in two at start, like OpenSSH:
#   - the collector keeps root and the capabilities for the drives (SETUID/SETGID it drops
#     right after the split), but does nothing except run smartctl on the configured drives
#     when asked, and hand back the result. It never touches the network and accepts exactly
#     one request, "scan", with no parameters.
#   - the reporter drops to the user "nobody" with no capabilities at all, then does everything
#     else: the connection, the encryption, reading the server's answers.
# A flaw in the network-facing code therefore gives an attacker an unprivileged process
# without any access to the drives. Where the agent does not run as root (e.g. directly on
# Windows), there is nothing to drop and it runs as one process.
# ============================================================================

NOBODY = 65534


def _send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, "big") + data)


def _recv(sock: socket.socket, limit: int) -> bytes:
    def exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("the other half of the agent stopped")
            buf += chunk
        return buf

    size = int.from_bytes(exact(4), "big")
    if size > limit:
        raise ConnectionError("message too large")
    return exact(size)


def _collector(sock: socket.socket, child: int) -> int:
    """The privileged half: answers "scan" requests until the reporter stops."""
    signal.signal(signal.SIGTERM, lambda *_: os.kill(child, signal.SIGTERM))
    signal.signal(signal.SIGINT, lambda *_: os.kill(child, signal.SIGTERM))
    try:
        while True:
            if _recv(sock, 16) != b"scan":
                log.error("The reporter sent an unknown request; stopping")
                break
            body = json.dumps(scan_devices(), separators=(",", ":")).encode()
            _send(sock, body if len(body) <= MAX_SCAN_BYTES else b"[]")
    except (ConnectionError, OSError):
        pass
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


CAP_SETGID, CAP_SETUID = 6, 7


def _status(field: str) -> int:
    """A number from /proc/self/status, e.g. CapEff (hex) or NoNewPrivs; -1 if unknown."""
    try:
        with open("/proc/self/status") as f:
            value = re.search(rf"^{field}:\s*([0-9a-f]+)$", f.read(), re.M).group(1)
        return int(value, 16 if field.startswith("Cap") else 10)
    except (OSError, AttributeError, ValueError):
        return -1


def _can_change_user() -> bool:
    """Whether this process holds CAP_SETUID and CAP_SETGID."""
    eff = _status("CapEff")
    return eff >= 0 and bool(eff & (1 << CAP_SETUID)) and bool(eff & (1 << CAP_SETGID))


def _drop_capabilities(*caps: int) -> None:
    """Removes these capabilities from this process for good. Lowering them needs no privilege;
    with no-new-privileges, the programs it starts (smartctl) cannot get them back either."""
    import ctypes

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    libc = ctypes.CDLL(None, use_errno=True)
    header, data = Header(0x20080522, 0), (Data * 2)()  # _LINUX_CAPABILITY_VERSION_3
    if libc.capget(ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "capget failed")
    for cap in caps:
        word, mask = cap // 32, ~(1 << cap % 32) & 0xFFFFFFFF
        for field in ("effective", "permitted", "inheritable"):
            setattr(data[word], field, getattr(data[word], field) & mask)
    if libc.capset(ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")
    wanted = sum(1 << cap for cap in caps)
    if any(_status(field) < 0 or _status(field) & wanted for field in ("CapEff", "CapPrm")):
        raise OSError("the capabilities are still there")


def _drop_privileges() -> None:
    try:
        os.setgroups([])
        os.setgid(NOBODY)
        os.setuid(NOBODY)
    except PermissionError:
        raise SystemExit("The agent cannot drop its privileges: add SETUID and SETGID under "
                         "cap_add in docker-compose.agent.yml (see the README)") from None
    # Changing from root to another user clears every capability; make sure of it
    with open("/proc/self/status") as f:
        status = f.read()
    if os.getuid() == 0 or not re.search(r"^CapEff:\s*0+$", status, re.M) \
            or not re.search(r"^CapPrm:\s*0+$", status, re.M):
        raise SystemExit("could not drop privileges; refusing to go on")


def _split() -> Callable[[], list[dict]]:
    """Forks off the privileged collector and returns the reporter's way to ask it for a scan.
    Only returns in the reporter, which then runs without any privileges."""
    parent_sock, child_sock = socket.socketpair()
    pid = os.fork()
    if pid:  # collector
        child_sock.close()
        # Changing users was only needed for the split: the collector gives that up at once
        try:
            _drop_capabilities(CAP_SETUID, CAP_SETGID)
        except OSError as exc:
            log.error("The collector cannot give up SETUID/SETGID (%s); stopping", exc)
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            sys.exit(1)
        if _status("NoNewPrivs") != 1:
            log.warning("no-new-privileges is not set for this container: programs the agent "
                        "starts as root could regain dropped capabilities. Keep security_opt "
                        "from docker-compose.agent.yml")
        sys.exit(_collector(parent_sock, pid))
    parent_sock.close()
    _drop_privileges()

    def remote_scan() -> list[dict]:
        _send(child_sock, b"scan")
        data = json.loads(_recv(child_sock, MAX_SCAN_BYTES))
        return data if isinstance(data, list) else []

    return remote_scan


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
    del agent_key
    name = os.environ.get("AGENT_NAME", "").strip() or socket.gethostname()

    scan = scan_devices
    separated = hasattr(os, "fork") and os.geteuid() == 0
    if separated:
        if not _can_change_user():
            return _idle("The agent cannot drop its privileges: add SETUID and SETGID under "
                         "cap_add in docker-compose.agent.yml (see the README).")
        scan = _split()  # from here on: user nobody, no capabilities
        signal.signal(signal.SIGTERM, lambda *_: _stop.set())
        signal.signal(signal.SIGINT, lambda *_: _stop.set())
    log.info("mimamori agent %s started, reporting to %s (end-to-end encrypted%s%s)",
             VERSION, client.host, ", over HTTPS" if client.https else "",
             "; network part runs without privileges" if separated else "")

    next_scan, interval, beat = 0.0, 3600, 60
    while not _stop.is_set():
        try:
            info = client.post("heartbeat", {"version": VERSION, "hostname": name})
            ALIVE_FILE.touch()
            interval = max(300, int(info.get("scan_interval", interval)))
            beat = max(15, min(600, int(info.get("heartbeat_interval", beat))))
            if info.get("scan_now") or time.time() >= next_scan:
                devices = scan()
                payload: dict[str, Any] = {"version": VERSION, "hostname": name,
                                           "devices": devices}
                host = read_host()  # in the unprivileged reporter: the files are world-readable
                if host:
                    payload["host"] = host
                result = client.post("report", payload)
                log.info("Reported %d device(s), the server tracks %s drive(s)", len(devices),
                         result.get("drives"))
                next_scan = time.time() + interval
        except ConnectionError as exc:
            log.error("Agent stopped: %s", exc)
            return 1
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
