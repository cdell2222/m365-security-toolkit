# Contributing

Fixes and improvements are welcome, particularly:

- A cmdlet or property that has changed behavior or been renamed
- A finding that's misclassified, or a case the script doesn't handle
- A tool that fits the ground rules in the README

## Before opening a pull request

- **Read-only.** A tool that changes a tenant needs to say so in its name and README, and should default to a dry run.
- **No real tenant data.** No tenant IDs, domains, user names, mailbox names or exported config — in code, comments, issues or screenshots. Synthetic examples only.
- **State the permissions.** Every tool lists the exact Exchange role or Graph scope it needs.
- **Test it.** Say what you tested against.
