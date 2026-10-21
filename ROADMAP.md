# Roadmap

Small, testable improvements are completed in order. Each behavior change must start with a failing regression test and keep the auditor read-only.

- [x] Reject malformed `ss` peer endpoints before classifying listening ports.
- [x] Reject malformed `netstat` foreign endpoints before classifying listening ports.
- [ ] Add a bounded active-connection inventory that warns when its probe is incomplete.
