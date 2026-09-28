# VPS Security Audit

A dependency-light, read-only Bash auditor for Linux VPS hosts. It collects a practical security snapshot without changing firewall rules, SSH settings, packages, users, or services.

## What it checks

- Operating system, kernel, uptime, and privilege level
- Default OpenSSH daemon settings (`PermitRootLogin`, `PasswordAuthentication`, public-key authentication, and authentication attempt limits); conditional `Match` contexts are identified as unresolved rather than treated as passing
- Listening TCP/UDP ports and known high-risk legacy services
- UFW, firewalld, or nftables status
- Fail2ban availability and jail status
- Pending package upgrades using local package metadata
- UID 0 and interactive-login accounts
- Recent logins
- systemd timers and system cron locations
- A concise PASS/WARN/FAIL/INFO summary

## Safety

The auditor is **read-only**. It does not harden the server automatically. This is intentional: firewall and SSH changes can lock operators out of a remote VPS.

Reports can contain hostnames, usernames, ports, and service information. Output files are created atomically with mode `600`, and an existing path is never overwritten; review and redact reports before sharing.

## Requirements

- Linux
- Bash 4 or newer
- Common system tools such as `awk`, `grep`, `sort`, and `head`
- Recommended: `ss` from `iproute2`
- Optional integrations: OpenSSH server, UFW/firewalld/nftables, Fail2ban, APT/DNF/YUM, systemd

## Installation

```bash
git clone https://github.com/DrowLink/vps-security-audit.git
cd vps-security-audit
chmod +x vps-audit.sh
```

Inspect scripts before running them with elevated privileges.

## Usage

Run without root for a limited audit:

```bash
./vps-audit.sh
```

Run with root for complete SSH, firewall, Fail2ban, and login information:

```bash
sudo ./vps-audit.sh
```

Save a private report while also printing it:

```bash
sudo ./vps-audit.sh --output "vps-audit-$(date +%F).txt"
```

Display CLI help:

```bash
./vps-audit.sh --help
```

## Understanding results

- `PASS`: the observed setting follows the auditor's baseline.
- `WARN`: incomplete visibility or a condition that deserves attention.
- `FAIL`: a risky condition was detected and should be investigated.
- `INFO`: context requiring an administrator's judgment.

A finding is not proof of compromise. Review it against the VPS role and provider network controls before changing production configuration.

## Tests

The test suite uses only Bash:

```bash
./tests/test_audit.sh
```

## Scope and limitations

This project provides host-level reconnaissance, not a full compliance assessment, malware scanner, vulnerability scanner, or external port scan. Provider firewalls and security groups are outside the VPS and must be reviewed separately.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
