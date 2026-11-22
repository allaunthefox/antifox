# Changelog

A summary of version updates for this project. Format follows [Keep a Changelog](https://keepachangelog.com/), and versioning follows [SemVer](https://semver.org/).

## v2.0.3

- **Custom LLM session headers**: each LLM configuration can set one HTTP header, whose value is automatically the current session ID — for gateways like opencode that do prompt caching / sticky routing per session.
- **Global egress proxy**: all agent target traffic can go out through one egress proxy (http/https/socks5), hiding the source IP / routing through a jump host; includes a "Test availability" check (echoes the egress IP through the proxy).
- **Per-task egress selection**: when creating a task, choose whether that task uses the global proxy or connects directly.
- **Confirm to enrich**: after a human confirms a vulnerability, it is automatically enriched into structured data — confirm and it is ready to deliver.
- **Report management**: new reports list only confirmed vulnerabilities by default (showing status / CVSS); the body reuses already-enriched data.
- **Evidence caption auto-fill**: evidence screenshot captions are auto-generated from the reproduction-step text and are editable.
- **Vulnerability detail polish**: status dropdown, section headings, one-click copy.
- **Traffic task-filter fix**: task filtering now also applies the task activity time window, so repeated tests against the same target no longer mix traffic together.
- System settings page changed to a two-column responsive layout.

## v2.0.2

- **One-click update**: check for and install new GitHub versions from the system settings page (SHA256 verification / atomic swap / automatic rollback on failure); data is unaffected.
- Release packages now include the `start.sh` watchdog script and the systemd template.

## v2.0.1

- Reproduction steps are automatically linked to the real traffic packets when saved to the database.

## v2.0.0

- Evidence-driven delivery: reproduction captured in place, findings shown step by step as an exploitation chain, every step linked to its real traffic packet; human-grade trilingual reports.
