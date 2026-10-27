# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it privately instead:

1. Open the [Security tab](https://github.com/Pascal2108/mimamori/security) of this repository.
2. Click **Report a vulnerability** and fill in the form.

Only the maintainer can see the report. A good report contains:

- what an attacker can do, and what they need for it (e.g. network access, a valid login, an agent key)
- the steps to reproduce it, or a proof of concept
- the version you tested (shown at the bottom of the page, or the image tag, e.g. `0.1.0` or `beta`)
- whether you have published it anywhere, or plan to

Leave out agent keys, passwords, host names and serial numbers of a real setup.

## What happens next

mimamori is maintained in spare time, so the times below are aims, not promises:

- an answer within **7 days**, saying whether the report is confirmed
- for a confirmed problem, a fixed version as soon as possible, released first as a beta
  and then as a stable version
- a GitHub security advisory once the fix is released, crediting you if you wish

Please give the fix time to be released before you publish details.

## Supported versions

| Version | Security fixes |
|---|---|
| The newest stable release (image tag `latest`) | Yes |
| `beta` | Yes, it receives the fix first |
| Older releases | No; update to `latest` |

The image is also rebuilt every week, so that security updates of the base image and the
libraries reach `latest` without a new release.

## Scope

In scope is mimamori itself: the server and the agent, the code in this repository and the
published images `ghcr.io/pascal2108/mimamori` and `ghcr.io/pascal2108/mimamori-agent`.
That includes the encrypted connection between agent and server: a way to read, change,
forge or replay an agent message, or to answer in the server's name, without the matching
private key is in scope.

Not in scope:

- smartmontools, the reverse proxy and other software mimamori works with; please report
  problems there to their own projects
- setups that ignore the [README](README.md#not-for-the-public-internet), e.g. mimamori
  reachable from the public internet, or running without HTTPS or without the container
  hardening of `docker-compose.yml`
- options named `UNSAFE_*`, which remove protection on purpose and are off by default
- guessing a weak password; mimamori already limits the attempts per address

The agent starts as root inside its container because reading raw drives needs it. It splits
itself at start: only the part that runs smartctl keeps root, the network-facing part runs as
`nobody` without capabilities. A way to escape that container, to gain the collector's rights
from the network side, or to make an agent run anything but smartctl, is in scope.

mimamori is built for private networks: it has one shared login, no two-factor
authentication, and it has not been audited.

## How mimamori is secured

### How agents connect

An agent never opens a port; it connects to the server once a minute and sends its report when a check is due. The connection uses public-key cryptography, like SSH:

- **Signed in both directions** (Ed25519). Each agent has its own key pair, and so does the server. The server accepts only messages signed with that agent's private key, and the agent accepts only answers signed by its server, for exactly the request it sent. Nobody can pose as an agent, pose as the server or slip in a fake "check now".
- **Encrypted** (X25519 and AES-256-GCM) with a fresh one-time key for every message, so nobody in between can read a report. A key stolen later cannot decrypt recorded reports or answers either.
- **Not replayable**: each message carries a time stamp that the server accepts only once and only in increasing order. A recorded message is rejected, and so is one from an agent whose clock is more than five minutes off.
- **Only public keys on the server**: the agent's private key exists only in its `AGENT_KEY`, which the page shows once. The server stores just the public key, so even a full copy of the server's data cannot be used to send reports as one of your agents.
- **One key per agent**: **New key** under Settings → Agents replaces it at once; the old key stops working.

This holds over plain HTTP too, which is why an agent may use `http://` inside a Docker network. Over HTTPS through the proxy, TLS adds a second layer on top.

"Check now" works the same way: the server never contacts an agent. It sets a flag, and the agent reads it from the answer to its next heartbeat, at most a minute later.

The server's own key pair is created on its first start and kept in its data volume. If that volume is lost, every agent needs a new key.

### Security of the agent

Reading SMART data needs raw access to the drives, which on Linux means root and the capability `SYS_RAWIO` (and `SYS_ADMIN` for NVMe drives). The agent keeps that power as small and as far from the network as it can:

- **Privilege separation**, like OpenSSH: at start the agent splits into two processes. The **collector** keeps root and the capabilities for the drives (it gives up `SETUID`/`SETGID` right after the split), but only ever runs `smartctl` on the configured drives when asked; it has no network code and accepts a single request, "scan", without parameters. The **reporter** becomes the user `nobody` with **no capabilities at all**, and does everything else: the connection, the cryptography, reading the server's answers. A flaw in that network-facing code gives an attacker an unprivileged process with no access to the drives.
- **No open port**: the agent only connects out, to the one server whose key is in its `AGENT_KEY`. Nothing on the network can talk to it first.
- **The server cannot command it**: the only things an answer can ask for are "check now" and the check interval. There is no way to run commands, change files or choose other devices from the server, even for someone who controls the server.
- **Host packages only when you mount them**: without the optional `volumes` lines, the agent sends nothing about the host. With them, the unprivileged reporter reads `/etc/os-release` and the package list (read-only mounts of world-readable files) and sends names and versions only.
- **Read-only**: smartctl only reads from the drives (`-a`), and sleeping drives are not woken up. Only the drives listed under `devices` exist in the container, and only for reading (`:r`): even root inside it cannot open them for writing. The container's file system is read-only, and its small `/tmp` cannot hold programs (`noexec`).
- **Contained**: every capability is dropped except `SETUID`/`SETGID` (needed once for the split), `SYS_RAWIO` and `SYS_ADMIN`; `no-new-privileges`, memory and process limits, Docker's default seccomp profile.

What remains:

- The collector is root with access to the listed drives. A flaw in smartctl itself, triggered by a manipulated drive, would run with those rights. That needs physical access to the host or a malicious drive.
- `SYS_ADMIN` is a broad capability. Leave it out if the host has no NVMe drive.
- The agent's private key is in `agent.env` on the host. Whoever can read that file can send reports in the agent's name (not more: see above). Keep the file readable only by root (`chmod 600 agent.env`), and create a new key under Settings → Agents if it may have leaked. With `AGENT_KEY_FILE` (see `docker-compose.agent.yml`) the key is not in the container's environment either, where `docker inspect` would show it.

### Security of the server

The server is separate from the agents in every respect: it holds no key that lets anyone act as an agent, and an agent can only ever affect its own drives.

- **Hardened container**: non-root, read-only, every capability dropped, `no-new-privileges`, memory and process limits.
- **The page**: one login with a lockout after five failed attempts per address (for IPv6 per /64 network, and at most 20 per /48), a session cookie that only travels over HTTPS (`__Host-`, `HttpOnly`, `SameSite=Strict`), a CSRF token on every form, a strict Content Security Policy without any JavaScript, and every value escaped. Logging out ends every session, also copies of the cookie. Over HTTPS the server sends HSTS, so browsers keep to HTTPS. Without HTTPS the login does not work, unless you allow it with `UNSAFE_HTTP`.
- **Agent messages are hostile input**: every message must carry a valid signature before it is even decrypted; every value from smartctl is type-checked, bounded and truncated. An agent can only change its own drives' data, may send at most one report every 20 seconds, and can trigger at most 20 notifications per hour; more alerts are recorded but not sent, so a compromised host cannot flood your Discord or mailbox.
- **Status monitor**: the server connects only to the targets you add on the page, and treats them as hostile input. It accepts only `http(s)://` URLs without user name or password and plain host names or addresses; it never connects to loopback, link-local (`169.254.x.x`, cloud metadata), multicast or reserved addresses, checks an IPv4 address hidden in IPv6 (mapped, NAT64, 6to4) as that address, connects to exactly the address it checked (so DNS cannot swap it in between), follows no redirects, reads no answer body and gives every check a hard time limit, so a server that answers slowly on purpose cannot hold it up. Addresses in your home network are allowed on purpose, so whoever is signed in can make the server knock on ports there, as they could from their own device. Ping uses an unprivileged ICMP socket, so the container needs no capability for it. At most 100 checks, at most 20 notifications per check and hour.
- **Docker images**: the server only reads from the registries of the images you add (the list of tags, or which image a tag points to); it never pulls an image and never touches your hosts, and the agents have no part in it. The names are treated as hostile input like the status monitor's targets: only `https://` with a valid certificate, never loopback, link-local, multicast or reserved addresses, connected to the checked address, every answer limited in size (4 MB) and time. Redirects are followed at most five times, each one checked again. Only public images: no registry password is stored. The anonymous pull-only token a registry hands out lives in memory for one check and is sent only to the host that asked for it. At most 100 images.
- **Push checks** (backups and jobs): their URLs are the only routes besides login and the agent API that work without signing in, since Backrest and scripts can send nothing but a URL. Each URL holds 256 random bits; the server stores only a hash of it and shows the URL once, and a new one replaces it at once. They accept only POST (so a link preview cannot report a run), read at most 10 kB of the body and keep it as plain text, take at most 120 pings per check and hour, and count unknown URLs against the sender's address: 20 within five minutes lock it out for a while. The log never contains the URL. Your reverse proxy may log request paths, and with them the URL: keep its access log private, or make a new URL if it got out. At most 100 push checks.
- **Read-only API** (`/api/v1/summary`, for Home Assistant and scripts): closed until you create a token under Settings → API tokens. A token holds 256 random bits and is sent only in the `Authorization` header; the server stores only a hash of it, shows it once and lets you revoke it at once. The API only answers GET, cannot change anything and never returns passwords, keys, push URLs or the query of a checked URL. A signed-in browser session does not open it, and it sends no CORS headers, so other websites cannot read it. Wrong tokens count against the sender's address: 20 within five minutes lock it out for a while. At most 50 tokens.
- **Secrets** stay in `secrets.env` and in memory; the admin password is kept only as a hash. Logs never contain passwords, keys or webhook addresses.
- **Supply chain**: the images install their Python packages only in the exact versions and with the hashes in `requirements.txt` and `requirements-agent.txt`; GitHub Actions are pinned to commit hashes; the images are rebuilt every week, and every image that is pushed is scanned with Trivy, in a job of its own that can read but never push images; a high or critical vulnerability that has a fix fails the build run.

What remains: mimamori has one shared login without two-factor authentication and has not been audited, which is why it belongs into a private network, not on the internet.
