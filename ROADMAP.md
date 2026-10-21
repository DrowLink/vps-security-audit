# Roadmap

Small, testable improvements are completed in order. Each behavior change must start with a failing regression test and keep the auditor read-only.

- [x] Reject malformed `ss` peer endpoints before classifying listening ports.
- [x] Reject malformed `netstat` foreign endpoints before classifying listening ports.
- [x] Add a bounded active-connection inventory that warns when its probe is incomplete.
- [ ] Reject malformed local endpoints in `ss` and `netstat` listener rows before classifying ports.
- [ ] Validate successful `sshd -T` output before classifying audited settings, warning on missing or duplicate keys.
- [ ] Warn when a bounded command capture is truncated instead of presenting it as complete.
- [ ] Add a bounded inventory of standard periodic and per-user cron locations that warns when any location is unreadable.
