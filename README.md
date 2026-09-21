# M365 Security Toolkit

Small, practical tools for Microsoft 365 identity, security and tenant work.

Each one solves a specific problem I've run into in real environments — tenant merges, cross-tenant trust, access that outlived its reason. Nothing here is a platform. Each tool does one job, reads what it needs, and tells you what it found.

## Tools

| Folder | Tool | What it's for |
|---|---|---|
| [`cross-tenant/`](cross-tenant/) | `Get-CrossTenantInventory.ps1` | Inventory organization relationships before cross-tenant Free/Busy moves to Entra Cross-Tenant Access Policy. Flags stale partners and missing CTAP entries. |
| [`cross-tenant/`](cross-tenant/) | `Get-CrossTenantAccessReview.ps1` | Review Entra Cross-Tenant Access Policy: guest and Teams shared-channel access, trusted external MFA and devices, cross-tenant sync, dead partner entries. |

More get added over time.

## Ground rules

**Read-only by default.** Unless a tool says otherwise in its name and its README, it reads and reports. Cleanup is always your decision, made with the output in front of you.

**Least privilege.** Each tool lists the exact roles and scopes it needs, and asks for nothing more.

**No tenant data in this repo.** The `.gitignore` blocks CSV, JSON and HTML output. If you contribute, never include real tenant IDs, domains, user names or configuration — synthetic examples only.

**Test before you trust.** Run anything here against a test tenant, or with read-only credentials, before relying on it. Microsoft changes APIs and module behavior more often than anyone would like.

## Requirements

Most tools need PowerShell 7 plus some combination of:

- `ExchangeOnlineManagement` 3.x
- `Microsoft.Graph.*` modules

Each tool's README lists exactly which.

## Related

- [copilot-readiness-framework](https://github.com/cdell2222/copilot-readiness-framework) — a method for assessing content exposure before a Microsoft 365 Copilot rollout

## Who

[Charlie Delmotte](https://www.linkedin.com/in/charliedelmotte) — hybrid cloud and security architect, Geneva.

## License

[MIT](LICENSE)
