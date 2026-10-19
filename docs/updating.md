# Updating

Image tags, and why server and agents are updated separately. Back to the [README](../README.md).

## Versions

Both images are published under these tags. Set the one you want in the `image:` line of `docker-compose.yml` and `docker-compose.agent.yml`.

| Tag | Contains | Changes |
|---|---|---|
| `latest` | The current stable version | With every release, and weekly for security updates |
| `0`, `1`, … | The newest stable version within that major version | With every release of that major version, and weekly for security updates |
| `0.1.0`, `0.2.0`, … | Exactly that [release](https://github.com/Pascal2108/mimamori/releases) | Never; it also receives no security updates |
| `beta` | What is being tested for the next release | Often; it may break |
| `0.1.1-beta.1`, … | Exactly that test version ([pre-release](https://github.com/Pascal2108/mimamori/releases)) | Never |

Use `latest` unless you have a reason not to. A version number is for going back when an update causes trouble: the release notes say what changed and whether you have to adjust your `docker-compose.yml`.

New images are published on every release and once a week, so that security updates of the base image and the libraries are included. Tools such as Watchtower pick them up automatically.

## Server and agents are updated separately

The server is backwards compatible with older agents: **every newer server works with every agent that was released before it.** So you can keep the server on `latest` to get every improvement of the page, and update the agents on your hosts only when you choose to.

This works because the agent only collects: it sends smartctl's full output, and the server does all the interpreting. A newer server can read more from the same data, so even an old agent benefits from it. New features never require a newer agent; at most they appear only when the agent is updated too, and the release notes say so.

**Recommended:** keep the server on `latest`, and update the agents by hand when you choose to. Docker only fetches a new agent image when you run `docker compose -f docker-compose.agent.yml pull`, so an agent never changes on its own (unless a tool such as Watchtower does it for you). Before updating an agent, read the release notes: a new agent version may need a change in `docker-compose.agent.yml`, for example a new capability. The server never needs that: it keeps working with the agents you have not updated yet.

`docker-compose.agent.yml` uses `ghcr.io/pascal2108/mimamori-agent:0`, the newest version of major version 0, which also receives the weekly security updates. To freeze an agent at one version, use it exactly, e.g. `mimamori-agent:0.1.0`.

The other way round is not promised: an agent newer than its server may use features the server does not know yet. Update the server first.
