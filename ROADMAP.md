# Roadmap

Small, testable improvements are completed in order. Each behavior change must start with a failing regression test and keep the auditor read-only.

- [x] Reject malformed `ss` peer endpoints before classifying listening ports.
- [x] Reject malformed `netstat` foreign endpoints before classifying listening ports.
- [x] Add a bounded active-connection inventory that warns when its probe is incomplete.
- [x] Reject malformed local endpoints in `ss` and `netstat` listener rows before classifying ports.
- [x] Validate successful `sshd -T` output before classifying audited settings, warning on missing or duplicate keys.
- [ ] Warn when a bounded command capture is truncated instead of presenting it as complete.
  - Study WIP: bounded captures now expose truncation and fail closed for several write paths, but review still found unresolved report-integrity issues: raw evidence can forge summary finding counts, NUL bytes are not preserved, and active-connection truncation/write-failure precedence needs correction. Add end-to-end truncation tests for every changed report section before completing this item.
- [ ] Add a bounded inventory of standard periodic and per-user cron locations that warns when any location is unreadable.
