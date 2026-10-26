# Configuration

All settings of the server and the agents, the custom webhook and the unsafe options. Back to the [README](../README.md).

## Server

These are set under `environment:` in `docker-compose.yml`. Only `TZ` needs your value. The others are listed there as comments with their default value:

```yaml
      # RETENTION_DAYS: 400       # (optional) days of history and alerts that are kept
```

To change one, remove the `#` at the start of its line and set the value. The comment behind the value can stay. Then apply it with `docker compose up -d`.

| Variable | Default | Meaning |
|---|---|---|
| `TZ` | `UTC` | Time zone for the page and the weekly report |
| `PUBLIC_URL` | – | HTTPS address of mimamori; used for links in notifications and shown when adding an agent |
| `RETENTION_DAYS` | `400` | How long history and alerts are kept |
| `SESSION_HOURS` | `12` | How long you stay signed in |
| `LOG_LEVEL` | `INFO` | `DEBUG` for more detail |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `MAIL_FROM`, `MAIL_TO` | – | Mail; `SMTP_SECURITY` is `starttls` (port 587) or `ssl` (port 465). Several recipients are separated by commas |
| `UNSAFE_HTTP` | `false` | ⚠️ **Unsafe.** Login works over plain HTTP; see [Unsafe options](#unsafe-options) |
| `UNSAFE_HTTP_WEBHOOKS` | `false` | ⚠️ **Unsafe.** Discord and webhook addresses may use `http://` |
| `UNSAFE_SMTP_PLAINTEXT` | `false` | ⚠️ **Unsafe.** Allows `SMTP_SECURITY: none` |
| `UNSAFE_HIDE_WARNINGS` | `false` | ⚠️ **Unsafe.** The page no longer shows the notices of the options above |
| `BEHIND_PROXY` | `true` | `false` when mimamori is reached directly through a published port, without a reverse proxy |

`secrets.env` holds the values that must stay secret:

| Variable | Meaning |
|---|---|
| `ADMIN_USER` | User name for the page |
| `ADMIN_PASSWORD` | Password for the page; choose a long one. Shorter than 12 characters works, but the log advises against it at every start |
| `DISCORD_WEBHOOK_URL` | Optional: a Discord channel webhook (Server Settings → Integrations → Webhooks) |
| `SMTP_PASSWORD` | Optional: password of the mail account |
| `WEBHOOK_URL`, `WEBHOOK_SECRET` | Optional: your own webhook, see [Custom webhook](#custom-webhook) |

## Agent

The agent is configured in `docker-compose.agent.yml` and `agent.env`:

| Variable | Default | Meaning |
|---|---|---|
| `SERVER_URL` | required | Address of mimamori as the agent's host reaches it: the HTTPS address of the proxy, or `http://mimamori:8000` inside the server's Docker network |
| `AGENT_KEY` | required | The key from Settings → Agents; belongs into `agent.env` |
| `AGENT_KEY_FILE` | – | Read the key from this file instead, e.g. a Docker secret (see the comments in `docker-compose.agent.yml`). Unlike `AGENT_KEY`, it does not show in `docker inspect`. The file can be readable by root only |
| `AGENT_NAME` | host name of the container | Name of the host, shown on the page; set it, since the container's own host name is a random ID |
| `DEVICES` | all listed devices | Only check these, e.g. `/dev/sda,/dev/sdb:sat`; after a colon, a `smartctl -d` type for drives behind USB bridges or RAID controllers |
| `LOG_LEVEL` | `INFO` | `DEBUG` for more detail |

**On the server's own host** the agent can skip the proxy: remove the `#` from the `networks:` lines at the end of `docker-compose.agent.yml` and set `SERVER_URL=http://mimamori:8000`. This is safe, because the messages are encrypted anyway.

## Custom webhook

With `WEBHOOK_URL` set, mimamori sends every alert as a JSON `POST`:

```json
{"kind": "worsened", "label": "Worsened", "level": "crit",
 "title": "Failing · WDC WD40EFRX-68N32N0 · sdc: reallocated 264 → 312",
 "detail": "The drive is remapping or failing to read sectors. …",
 "fields": {"Host": "docker-host-2", "Device": "/dev/sdc", "Temperature": "47 °C"},
 "host": "docker-host-2", "severity": "high", "topics": ["drive_high"],
 "drive": {"device": "/dev/sdc", "model": "…", "serial": "…"},
 "url": "https://mimamori.example.com/drive/3", "ts": 1792270094}
```

`kind` is one of `new_issue`, `worsened`, `resolved`, `missing`, `back`, `agent_offline`, `agent_online`, `updates`, `firmware`, `storage`, `monitor_down`, `monitor_up`, `monitor_tls`, `push_fail`, `push_late`, `push_ok`, `docker`, `report` and `test`; `level` is `crit`, `warn`, `info` or `ok`. Alerts also carry `severity` (`low`, `middle`, `high`, or empty; the page shows them as low, medium and critical) and `topics`, the rule names from Settings → Notifications (e.g. `["drive_high"]`, `["updates_middle"]`). Only alerts whose topic you allowed for the webhook are sent to it. Alerts of the status monitor have an empty `host` and `drive: null`, and carry `"monitor": {"name": "…", "kind": "http", "target": "https://…"}` instead (the target without its query string, which may hold a token). Alerts of the push checks carry `"heartbeat": {"name": "…", "interval": 86400, "last_success": 1767225600}` (seconds, unix time or `null`). Alerts of the Docker image check carry `"image": {"name": "…", "image": "nginx", "version": "1.27.2", "track": "stable", "latest": "1.27.3"}`; `track` is `stable`, `major`, `beta` or `digest` (a followed tag such as `latest`, where `latest` is the new image's digest).

With `WEBHOOK_SECRET` set, every request carries the headers `X-Mimamori-Timestamp` and `X-Mimamori-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<raw body>` with the secret as key. Check the signature with a constant-time comparison and reject timestamps older than a few minutes.

## Unsafe options

> [!WARNING]
> These options remove protection. Use them only in a network where you trust **every device and every person**, and never when mimamori can be reached from the internet. While one is on, the container log warns at every start and every page shows a notice that cannot be hidden: a quiet one for a setting, a red one for an unencrypted connection.

**`UNSAFE_HTTP: "true"`** lets the login work over plain HTTP, without a reverse proxy that provides HTTPS. Everything then travels unencrypted: your password, the session cookie and all drive data. Anyone on the same network, such as the Wi-Fi, can read it and take over your session. Over HTTPS the page keeps working as before. Agents are not affected: their messages are encrypted either way.

**`UNSAFE_HTTP_WEBHOOKS: "true"`** allows `http://` addresses for Discord and the custom webhook, for a receiver in your own network without TLS. Alerts then travel unencrypted, and so does a webhook address that contains a token.

**`UNSAFE_SMTP_PLAINTEXT: "true"`** allows `SMTP_SECURITY: none`, for a mail relay in your own network without TLS. Mails, and the SMTP password if one is set, then travel unencrypted.

**`UNSAFE_HIDE_WARNINGS: "true"`** removes the notices that the options above put on every page. It changes nothing about what they do; the people using the page are just no longer told. The container log keeps warning at every start, and says that the page no longer does.

With the normal setup behind a reverse proxy, `UNSAFE_HTTP` alone is enough for a proxy host that is reachable over HTTP; leave `BEHIND_PROXY` as it is. To keep that from happening by accident, switch on **Force SSL** for the proxy host instead: plain HTTP then redirects to HTTPS.

To reach mimamori without a reverse proxy, also publish its port and switch off `BEHIND_PROXY`, so that the login lockout counts real addresses instead of trusting a header that any client could fake:

```yaml
    environment:
      UNSAFE_HTTP: "true"
      BEHIND_PROXY: "false"
    ports:
      - "8000:8000"
```

The page is then at `http://<address of the server>:8000`.
