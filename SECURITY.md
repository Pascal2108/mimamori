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

The agent runs as root inside its container because reading raw drives needs it; it keeps
only the capabilities `SYS_RAWIO` and `SYS_ADMIN`. A way to escape that container, or to make
an agent run anything but smartctl, is in scope.

mimamori is built for private networks: it has one shared login, no two-factor
authentication, and it has not been audited.
