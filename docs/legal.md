# Legal

This is information from the author, not legal advice. Back to the [README](../README.md).

## License

mimamori is free software under the [GNU Affero General Public License, version 3](../LICENSE) (AGPL-3.0).
Copyright (C) 2026 Pascal2108.

- You may use, study, change and share it.
- If you share it, changed or not, you have to pass on the same rights: keep the license and the copyright notice, and make the source code available.
- This also applies if you change it and let other people use your version over a network, without handing them a copy. They are entitled to the source code of your version.

The images also contain other software under its own licenses, among them smartmontools (GPL-2.0) in the agent image, which the agent runs as a separate program.

## No warranty, no liability

mimamori is a private project, provided as it is and without warranty of any kind, as sections 15 and 16 of the license state. You run it at your own risk. It can only report what the drives themselves report: many drives fail without warning in their SMART data, so **mimamori is no replacement for backups**. To the extent the law permits, the author is not liable for damage, data loss, missed or false alerts, or any other consequence of installing, running or misconfiguring it. You are responsible for securing your server, for keeping it updated and for backing up your data.

## Cookies and personal data

- **One cookie:** mimamori sets a single cookie, `__Host-mimamori`, when you sign in. It holds your signed-in session, lasts for `SESSION_HOURS`, and is removed when you sign out. Without it the login cannot work.
- **No tracking:** there are no analytics, advertising or third-party cookies, and the page loads nothing from other servers.
- **Consent:** a cookie that is strictly necessary for a service the user asked for generally needs no consent banner under the EU ePrivacy rules (in Germany § 25 TDDDG). This fits a login cookie, but the assessment for your own installation is yours.
- **Personal data:** the container log records the address of each device that signs in or fails to. The database holds drive data (models, serial numbers, SMART values), the names you give to hosts and the agents' public keys. When the update check is on, the host's package names and versions go to `api.osv.dev`. The status monitor connects only to the sites and services you add, and stores their names, addresses and response times. Notifications are sent only to the channels you configure.

If other people use your installation, you are its operator: informing them and complying with data protection law, such as the GDPR, is your responsibility.
