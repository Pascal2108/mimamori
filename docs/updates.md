# Missing updates

mimamori checks two things besides the drives' health: missing security updates of the host's packages, and drive firmware with a known bug. Back to the [README](../README.md).

## Host packages

An agent from 0.3.0 on reports the host's installed packages when its package list is mounted. To set that up, remove the `#` in front of the `volumes:` lines for your system in `docker-compose.agent.yml` (Debian, Ubuntu and Proxmox: `os-release` and `dpkg`; Alpine: `os-release` and `apk`), recreate the agent, and turn the check on under **Settings → Updates** on the page.

The server looks the packages up in the [OSV database](https://osv.dev), which carries the security trackers of Debian, Ubuntu and Alpine, twice a day and right after the list changes. A package counts as missing an update when a known vulnerability affects the installed version and the distribution has released a fixed version. Each one is rated by the distribution's own priority (Ubuntu priority, Debian urgency) or else by its CVSS score: **critical** from 7.0, **medium** from 4.0, **low** below; unrated ones count as medium. Vulnerabilities without a fixed version are only counted.

The host's page (click its name on the overview) lists every package with the version that fixes it, the vulnerabilities, the running kernel and all installed packages. While a check runs, the host's page and the overview show how far it has got in percent. The first check of a host takes a few minutes, later ones only fetch what changed.

The check sends the package names, versions and the release (e.g. `Debian:12`) to `api.osv.dev`, run by Google; no host names, addresses or drive data. That is why it is off until you turn it on. The server needs outbound HTTPS for it, like for Discord.

After a release upgrade of the host (e.g. Debian 12 to 13), restart the agent or reboot the host, as you would after such an upgrade anyway: the agent sees the new `os-release` only from its next start, and until then the packages are checked against the old release.

## Drive firmware

Every report is compared with a list of firmware versions with known, serious bugs (e.g. the Samsung 980 PRO and 990 PRO health bugs, the Intel D3-S4510/S4610 1,700-hour bug, and the warnings from the drive database of smartmontools that name the affected firmware, such as the Crucial m4 5,184-hour bug and older Seagate drives), kept in `app.py`. This needs no outside connection and works with every agent.

There is no public database of drive firmware, so a drive without a listed bug may still have a newer firmware: check the vendor's tool. New known bugs are welcome as issues.

## Notifications

Drive problems and missing updates share one ranking: **critical** (a Failing or missing drive, an agent offline, a critical update or firmware bug), **medium** (Watch for sectors or wear, a medium update) and **low** (Watch for temperature or cable CRC errors, a low update). Everything counts together on the overview, and its headline follows the worst: *The pond is calm*, *A light breeze on the pond* (low), *Ripples on the pond* (medium), *The pond is restless* (critical).

A new finding raises one alert per host or drive. Under **Settings → Notifications** you choose for each channel which ranks it gets, for drive issues and missing updates separately (low updates are off by default), plus recoveries, agent offline and the weekly report.
