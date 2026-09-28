# Contributing

Contributions that improve portability, detection accuracy, tests, or documentation are welcome.

## Development workflow

1. Fork and clone the repository.
2. Create a focused branch.
3. Add or update a failing test before changing behavior.
4. Implement the smallest safe change.
5. Run the complete test suite:

   ```bash
   ./tests/test_audit.sh
   ```

6. If ShellCheck is installed, run:

   ```bash
   shellcheck vps-audit.sh lib/audit.sh tests/test_audit.sh
   ```

7. Open a pull request explaining the risk addressed and the distributions tested.

Keep the auditor read-only. Changes that automatically alter firewall, SSH, users, packages, or services are outside the project's scope.
