# API

mimamori offers a read-only API for Home Assistant, dashboards and your own scripts. It returns in one answer what the overview shows: the overall state, everything that needs attention, hosts, drives, status checks, backups and jobs, and Docker images. Back to the [README](../README.md).

The API only reads. Nothing can be changed through it, no check started, no setting or secret read. It is closed until you create a token.

## Tokens

1. Open **Settings → API tokens** and create a token. Give it a name that says who uses it, e.g. *Home Assistant*.
2. Copy the token (`mmr_` and 43 characters). It is shown only once; mimamori keeps only a hash of it.
3. Revoke a token under **Settings → API tokens** when it is no longer used or may have leaked. It stops working at once. The table shows when each token was last used.

Use one token per client, so that you can revoke one without touching the others. Anyone with a token can read hosts, drives, checks and their addresses, so treat it like a password: keep it out of git, issues and screenshots, and send it only over HTTPS.

## Requests

Send the token in the `Authorization` header:

```sh
curl -H "Authorization: Bearer $MIMAMORI_TOKEN" https://mimamori.example.com/api/v1/summary
```

| | |
|---|---|
| Method | `GET` only |
| Address | `/api/v1/summary` |
| Authentication | `Authorization: Bearer mmr_…` (a signed-in browser session does not count) |
| Answer | `application/json`, UTF-8, never cached (`Cache-Control: no-store`) |
| Poll interval | Once a minute is plenty. Drives are checked hourly by default, status checks every minute or more |

### Errors

| Status | Meaning |
|---|---|
| `401` | The token is missing, malformed, wrong or revoked |
| `429` | Too many wrong tokens from your address: 20 within 5 minutes lock the address out for up to 5 minutes, even with a correct token |
| `5xx` | The server or the reverse proxy has a problem; try again later |

Error answers are JSON as well: `{"error": "Unauthorized"}`.

## Stability

The answer is versioned by its address (`/api/v1/`) and by `api_version` in the answer.

- Within v1, fields are only **added**, never removed, renamed or changed in meaning. Ignore fields you do not know.
- Lists of values (e.g. `status` of a drive) may get new values. Treat an unknown value as "something else", not as an error.
- A change that would break a client gets a new address (`/api/v2/…`), and v1 stays.

## Conventions

- **Times** are Unix time stamps in seconds (UTC), or `null` when there is none (never checked, never seen).
- **Sizes** are bytes.
- **Severity** is one of `none`, `low`, `medium`, `critical`: how urgent something is, the same ranking the overview uses.
- **IDs** are stable for as long as the item exists. Host IDs are strings, all others integers. A drive that is removed and comes back on the same host keeps its ID, since drives are recognized by their serial number.
- **`url`** fields link to the matching page of mimamori (`PUBLIC_URL` if set, otherwise the address of the request). They need a login.
- Texts (`headline`, `text`, `summary`, `title`) are in English and meant for people, not for parsing.

## `GET /api/v1/summary`

An example answer, shortened to one item per list (all values made up):

```json
{
  "api_version": 1,
  "server": {"version": "v0.3.5", "generated": 1793092800, "url": "https://mimamori.example.com"},
  "status": {
    "severity": "medium",
    "problems": 2,
    "headline": "Ripples on the pond.",
    "by_severity": {"critical": 0, "medium": 2, "low": 0},
    "by_kind": {"updates": 0, "drive": 1, "firmware": 0, "agent": 0, "storage": 0,
                "monitor": 0, "push": 0, "docker": 1}
  },
  "attention": [
    {"severity": "medium", "kind": "drive", "count": 1, "host": "nas",
     "text": "TestCorp HD4000 · sda on nas: 200 reallocated sectors",
     "url": "https://mimamori.example.com/drive/3"}
  ],
  "counts": {
    "hosts": 2, "hosts_offline": 0,
    "drives": {"failing": 0, "missing": 0, "watch": 1, "healthy": 7},
    "security_updates": {"critical": 0, "medium": 0, "low": 0},
    "reboot_required": 0, "storage_problems": 0,
    "monitors": {"up": 4, "down": 0, "pending": 0, "paused": 0},
    "push_checks": {"up": 2, "late": 0, "failed": 0, "new": 0, "paused": 0},
    "docker_images": {"current": 5, "available": 1, "error": 0, "pending": 0}
  },
  "hosts": [
    {"id": "3f9a1c0b2d4e", "name": "nas", "location": "basement", "online": true,
     "last_seen": 1793092790, "last_report": 1793090000, "agent_version": "v0.3.4",
     "hostname": "nas", "os": {"name": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-26-amd64"},
     "reboot_required": false,
     "security_updates": {"critical": 0, "medium": 0, "low": 0, "total": 0},
     "updates_checked": 1793080000,
     "filesystems": [
       {"name": "root", "type": "ext4", "total": 250790436864, "used": 61234561024,
        "free": 176768491520, "used_percent": 26, "level": "ok"}
     ],
     "url": "https://mimamori.example.com/host/3f9a1c0b2d4e"}
  ],
  "drives": [
    {"id": 3, "host_id": "3f9a1c0b2d4e", "host": "nas", "name": "TestCorp HD4000 · sda",
     "model": "TestCorp HD4000", "device": "/dev/sda", "serial": "TESTHDD001",
     "firmware": "01.00A01", "kind": "hdd", "capacity": 4000787030016,
     "status": "watch", "summary": "200 reallocated sectors",
     "issues": [{"metric": "reallocated", "level": "warn", "text": "200 reallocated sectors"}],
     "muted": false, "standby": false, "no_smart": false, "temperature_ignored": false,
     "temperature": 38, "power_on_hours": 20000, "wear_percent": null,
     "reallocated_sectors": 200, "pending_sectors": 0, "media_errors": null,
     "firmware_update": null, "last_seen": 1793090000,
     "url": "https://mimamori.example.com/drive/3"}
  ],
  "monitors": [
    {"id": 1, "name": "Website", "kind": "http", "target": "https://www.example.com",
     "status": "up", "last_check": 1793092780, "response_ms": 84, "last_error": "",
     "certificate_expires": 1798000000, "certificate_expiring": false,
     "uptime_24h": 1.0, "uptime_30d": 0.9993,
     "url": "https://mimamori.example.com/status/1"}
  ],
  "push_checks": [
    {"id": 1, "name": "Backup nas", "status": "up", "running": false,
     "last_ping": 1793066400, "last_success": 1793066400, "deadline": 1793160000,
     "interval": 86400, "url": "https://mimamori.example.com/status/push/1"}
  ],
  "docker_images": [
    {"id": 2, "name": "nginx", "image": "nginx", "version": "1.27.2", "latest": "1.27.3",
     "state": "available", "checked": 1793080000, "error": "",
     "url": "https://mimamori.example.com/docker#image-2"}
  ],
  "alerts": [
    {"ts": 1793089000, "kind": "new_issue", "level": "warn",
     "title": "TestCorp HD4000 · sda: 200 reallocated sectors", "host": "nas"}
  ]
}
```

### `server`

| Field | Type | Meaning |
|---|---|---|
| `version` | string | Version of the mimamori server, e.g. `v0.3.5` (`dev` for a local build) |
| `generated` | time | When this answer was made |
| `url` | string | Address of mimamori, the start of every `url` field |

### `status`: the one value to watch

| Field | Type | Meaning |
|---|---|---|
| `severity` | severity | The most urgent open problem; `none` when all is fine |
| `problems` | int | Number of open problems (the length of `attention`, counting items with `count` > 1 that many times) |
| `headline` | string | The headline of the overview |
| `by_severity` | object | Problems per severity: `critical`, `medium`, `low` |
| `by_kind` | object | Problems per kind (see `attention[].kind`) |

### `attention[]`: what needs you, most urgent first

| Field | Type | Meaning |
|---|---|---|
| `severity` | severity | `critical`, `medium` or `low` |
| `kind` | string | `drive` (a drive's health), `firmware` (a firmware update is recommended), `agent` (a host stopped reporting), `updates` (missing security updates or a reboot for a new kernel), `storage` (a filesystem fills up), `monitor` (a status check is down or its certificate expires), `push` (a backup or job failed or is overdue), `docker` (a newer image) |
| `count` | int | How many things the item stands for, e.g. 3 missing updates |
| `host` | string | The host it is about, `""` if none |
| `text` | string | A sentence for people |
| `url` | string | The page with the details |

Like on the overview, paused checks are left out, while muted items stay: muting only stops the notifications.

### `counts`

| Field | Meaning |
|---|---|
| `hosts`, `hosts_offline` | Hosts with an agent, and those whose agent stopped reporting |
| `drives` | Drives per `status` (see below) |
| `security_updates` | Missing security updates of all hosts per severity |
| `reboot_required` | Hosts that run an older kernel than the one installed |
| `storage_problems` | Filesystems that are filling up or almost full |
| `monitors`, `push_checks`, `docker_images` | Items per `status` / `state` (see below) |

### `hosts[]`: one per agent

| Field | Type | Meaning |
|---|---|---|
| `id` | string | The agent's ID |
| `name`, `location` | string | As set under Settings → Agents |
| `online` | bool | The agent reported within the time set under Settings → Checks |
| `last_seen`, `last_report` | time | Last heartbeat, last full report with drive data |
| `agent_version`, `hostname` | string | As reported by the agent |
| `os.name`, `os.kernel` | string | The system and running kernel; `""` if the agent does not report them |
| `reboot_required` | bool | A newer kernel is installed than the one running |
| `security_updates` | object | Missing security updates per severity, and `total` |
| `updates_checked` | time | Last check for missing updates; `null` if the check is off or not run yet |
| `filesystems[]` | list | `name`, `type`, `total`, `used`, `free` (bytes), `used_percent` (rounded up, like `df`), `level`: `ok`, `warn` (filling up) or `crit` (almost full), by the limits under Settings → Checks |

### `drives[]`

| Field | Type | Meaning |
|---|---|---|
| `id`, `host_id`, `host` | | The drive and the host it is in |
| `name` | string | Model and device, as the page shows it |
| `model`, `device`, `serial`, `firmware` | string | `serial` is `""` for drives that report none |
| `kind` | string | `hdd`, `ssd`, `nvme` or `unknown` |
| `capacity` | int or null | Bytes |
| `status` | string | `healthy`, `watch` (something to keep an eye on), `failing` or `missing` (no longer reported by its host) |
| `summary` | string | Why, in a few words; `""` when healthy |
| `issues[]` | list | Each finding: `metric` (e.g. `temp`, `reallocated`, `pending`, `wear`, `smart`), `level` (`warn` or `crit`) and `text` |
| `muted` | bool | Alerts for the drive are muted |
| `standby` | bool | The drive was asleep at the last check and was not woken; its values are from before |
| `no_smart` | bool | The drive answers, but without health values (virtual disks, some USB enclosures) |
| `temperature_ignored` | bool | Its sensor was marked as faulty; `temperature` is then `null` |
| `temperature` | int or null | °C at the last check |
| `power_on_hours` | int or null | |
| `wear_percent` | int or null | SSD/NVMe: share of the rated endurance used (100 = used up) |
| `reallocated_sectors`, `pending_sectors` | int or null | HDD/SSD (ATA) |
| `media_errors` | int or null | NVMe |
| `firmware_update` | severity or null | A firmware update is recommended, and how urgently |
| `last_seen` | time | Last report that included the drive |

Values a drive does not report are `null`.

### `monitors[]`: the status monitor

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `http`, `tcp` or `ping` |
| `target` | string | What is checked: the URL, or host and port |
| `status` | string | `up`, `down`, `pending` (not checked yet) or `paused` |
| `last_check` | time | |
| `response_ms` | int or null | Response time of the last check |
| `last_error` | string | Why the last failed check failed |
| `certificate_expires` | time | HTTPS and TLS: when the certificate expires |
| `certificate_expiring` | bool | It expires within the days set for the check |
| `uptime_24h`, `uptime_30d` | float or null | Share of checks that were up, 0 to 1; `null` without checks |

### `push_checks[]`: backups and jobs

| Field | Type | Meaning |
|---|---|---|
| `status` | string | `up` (last run was fine), `late` (no run in time), `failed` (the last run reported a failure), `new` (never ran) or `paused` |
| `running` | bool | A run has started and not ended yet |
| `last_ping`, `last_success` | time | |
| `deadline` | time | When it is overdue without another successful run; `null` while paused |
| `interval` | int | Seconds between two runs |

### `docker_images[]`

| Field | Type | Meaning |
|---|---|---|
| `image`, `version` | string | The image and the version you run |
| `latest` | string or null | The newest version found, `null` if you run it |
| `state` | string | `current`, `available` (a newer version exists), `error` (the registry could not be asked) or `pending` (not checked yet) |
| `checked` | time | Last check against the registry |
| `error` | string | Why the last check failed |

### `alerts[]`: the last ten alerts, newest first

| Field | Type | Meaning |
|---|---|---|
| `ts` | time | |
| `kind` | string | e.g. `new_issue`, `worsened`, `resolved`, `missing`, `agent_offline`, `monitor_down`, `push_fail`, `docker` |
| `level` | string | `crit`, `warn`, `ok` or `info` |
| `title` | string | |
| `host` | string | `""` if the alert belongs to no host |

## Home Assistant

The [mimamori integration for Home Assistant](https://github.com/Pascal2108/mimamori-homeassistant) uses this API. It adds the overall state, every host, drive, status check, backup check and Docker image as devices and sensors.

Without the integration, a REST sensor gives you the overall state:

```yaml
# configuration.yaml; the token goes into secrets.yaml as
# mimamori_auth: "Bearer mmr_…"
rest:
  - resource: https://mimamori.example.com/api/v1/summary
    headers:
      Authorization: !secret mimamori_auth
    scan_interval: 60
    sensor:
      - name: mimamori
        value_template: "{{ value_json.status.severity }}"
        json_attributes_path: "$.status"
        json_attributes: [problems, headline, by_severity, by_kind]
```
