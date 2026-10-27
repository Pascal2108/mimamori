<img src="https://raw.githubusercontent.com/Pascal2108/mimamori/main/static/icon-180.png" alt="mimamori" width="72" align="left">

# mimamori 見守り

A self-hosted **monitor for your hosts and services**: failing drives, missing security updates, full disks, websites that stop answering, backups that failed or did not run, and Docker images with a newer version, on one page. *Mimamori* means "watching over".

<br clear="left">

**Full documentation, setup guide and source code: [github.com/Pascal2108/mimamori](https://github.com/Pascal2108/mimamori)**

This is the **server** image with the web page. It checks websites, services and Docker images itself and receives the reports of backups and jobs. Every host to watch runs the small agent image [`pascal2108/mimamori-agent`](https://hub.docker.com/r/pascal2108/mimamori-agent).

## Features

- **Drives**: SMART data of every drive on every host, with history charts and thresholds you set; any bad sector marks a drive as *Watch*, a growing count as *Failing*
- **Systems**: missing security updates of Debian, Ubuntu and Alpine hosts, pending reboots, drive firmware with known bugs, and how full each filesystem is
- **Sites and services**: HTTP(S) with certificate expiry, TCP ports and ping, checked by the server
- **Backups and jobs**: Backrest, cron jobs and scripts report each run to a secret URL; mimamori tells you when one fails or does not run in time
- **Docker images**: tells you when a newer version of the images you run exists
- **Notifications** to Discord, mail and your own signed webhook, plus a weekly report; a read-only API and a Home Assistant integration
- **Safe agent connection**: every message between agent and server is encrypted, signed in both directions and cannot be replayed; the server keeps only public keys
- **Hardened container**: runs as non-root, read-only, all capabilities dropped

## Quick start

mimamori runs behind a reverse proxy that provides HTTPS. You need two files.

`secrets.env`, with your own values (mimamori refuses to start with the example password):

```
ADMIN_USER=your-username
ADMIN_PASSWORD=a-long-secure-password
```

`docker-compose.yml`:

```yaml
services:
  mimamori:
    image: pascal2108/mimamori:latest
    container_name: mimamori
    restart: unless-stopped
    env_file:
      - secrets.env
    environment:
      TZ: Europe/Berlin
    volumes:
      - data:/data
    tmpfs:
      - /tmp:size=16m
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    pids_limit: 100
    networks:
      - proxy

volumes:
  data:

networks:
  proxy:
    external: true
    name: nginx_reverse_proxy
```

This is the shortest working setup. The full [`docker-compose.yml`](https://github.com/Pascal2108/mimamori/blob/main/docker-compose.yml) on GitHub also lists optional settings that are not shown here, such as mail, the public address for links, history retention and running without a reverse proxy. They are explained under [Configuration](https://github.com/Pascal2108/mimamori/blob/main/docs/configuration.md).

Then `docker compose up -d`, add a proxy host for port `8000` of the container `mimamori`, sign in and add your hosts under **Settings → Agents**. The [setup guide](https://github.com/Pascal2108/mimamori#getting-started) explains every step.

## Tags

| Tag | Contains |
|---|---|
| `latest` | The current stable version, rebuilt weekly with security updates |
| `0.1.0`, … | Exactly that release; never changes and receives no security updates |
| `beta` | The next release while it is being tested; may break |

Images are built for `linux/amd64` and `linux/arm64` (e.g. Raspberry Pi). The same images are published as `ghcr.io/pascal2108/mimamori`. Use the same tag for the server and its agents.

## Security

mimamori is meant for **private networks only**, not for the public internet: it has one shared login, no two-factor authentication, and has not been audited. Please report vulnerabilities privately as described in the [security policy](https://github.com/Pascal2108/mimamori/security/policy), not in a public issue.

## License

[AGPL-3.0](https://github.com/Pascal2108/mimamori/blob/main/LICENSE). The image also contains other software under its own licenses.
