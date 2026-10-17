<img src="https://raw.githubusercontent.com/Pascal2108/mimamori/main/static/icon-180.png" alt="mimamori" width="72" align="left">

# mimamori agent

The small agent for [mimamori](https://hub.docker.com/r/pascal2108/mimamori), the self-hosted drive health monitor. It reads the SMART data of a host's drives with smartctl and reports it to the mimamori server.

<br clear="left">

**Full documentation, setup guide and source code: [github.com/Pascal2108/mimamori](https://github.com/Pascal2108/mimamori)**

## Features

- **Small**: about 27 MB to download, about 20 MB of memory; Python on Alpine with smartmontools
- **Connects out only**: it opens no port on the host
- **End-to-end encrypted**: every message to and from the server is signed (Ed25519), encrypted with a one-time key (X25519, AES-256-GCM) and cannot be replayed. The server keeps only the agent's public key
- **Gentle on drives**: sleeping drives are not woken up for a check
- **Hardened**: read-only container, every capability dropped except the two smartctl needs

## Quick start

Create a key for the host on the mimamori page under **Settings → Agents**. Then put two files into a folder on the host.

`agent.env`:

```
SERVER_URL=https://mimamori.example.com
AGENT_KEY=paste-agent-key-here
```

`docker-compose.agent.yml`:

```yaml
services:
  mimamori-agent:
    image: pascal2108/mimamori-agent:latest
    container_name: mimamori-agent
    restart: unless-stopped
    env_file:
      - agent.env
    environment:
      AGENT_NAME: docker-host
    devices:
      - /dev/sda
      - /dev/nvme0
    tmpfs:
      - /tmp:size=1m
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - SYS_RAWIO
      - SYS_ADMIN
    security_opt:
      - no-new-privileges:true
    mem_limit: 64m
    pids_limit: 32
```

List every drive of the host under `devices`; remove `SYS_ADMIN` if the host has no NVMe drive. Then `docker compose -f docker-compose.agent.yml up -d`. Reading raw drives needs root inside the container, so the agent runs as root with every other capability dropped.

## Tags

The same tags as the server image: `latest`, `0.1.0`, …, `beta`. Use the same tag for the server and its agents. Built for `linux/amd64` and `linux/arm64`, also published as `ghcr.io/pascal2108/mimamori-agent`.

## License

[AGPL-3.0](https://github.com/Pascal2108/mimamori/blob/main/LICENSE). The image also contains smartmontools (GPL-2.0) and other software under its own licenses.
