# Troubleshooting

Back to the [README](../README.md).

Read the logs with `docker compose logs` on the server and `docker compose -f docker-compose.agent.yml logs` on a host with an agent, or in Portainer.

| Message | Cause |
|---|---|
| Container keeps restarting, log says `ADMIN_PASSWORD …` | `secrets.env` is missing the password, or it is still the example |
| Login works, but the page asks to sign in again | The page was opened over plain HTTP; open it through the HTTPS address of the proxy |
| `Too many failed attempts` | Five wrong logins from one address; wait 15 minutes |
| `502 Bad Gateway` from the proxy | The container is not running, or the forward hostname or network is wrong |
| Agent: `SERVER_URL and AGENT_KEY must be set` | `agent.env` is empty; create a key under Settings → Agents |
| Agent: `the server did not accept AGENT_KEY` | The key is wrong, or a new one was created; copy the current one into `agent.env` |
| Agent: `the clocks of this host and the server differ` | Set up time synchronisation (NTP) on both hosts |
| Agent: `the answer is not from the mimamori server that owns this AGENT_KEY` | `SERVER_URL` points to another server, or something in between changed the answer |
| Agent: `The server's certificate is not trusted` | `SERVER_URL` points to an address whose certificate is self-signed or for another name; use the proxy's address with a valid certificate |
| Agent: `Cannot reach the server` | `SERVER_URL` is wrong or not reachable from the agent's host |
| Agent: `cannot drop its privileges` | `SETUID` and `SETGID` are missing under `cap_add` in `docker-compose.agent.yml` |
| A drive is missing on the page | It is not listed under `devices` of its agent, or the agent cannot open it; drives behind USB bridges may need a type in `DEVICES`, e.g. `/dev/sdb:sat` |
| A card says `no SMART data from this device` | The drive or its controller does not pass SMART through, e.g. a virtual disk or some USB enclosures |
| A drive shows a temperature that cannot be right | A faulty sensor or firmware; use **Ignore temperature** in the Thresholds section of its page |
| Agent shows as offline | No heartbeat for 10 minutes; check the agent's log and that its host is running |
