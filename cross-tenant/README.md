# Cross-tenant inventory

Microsoft is moving cross-tenant Free/Busy, MailTips and calendar sharing out of Exchange organization relationships and into **Entra ID Cross-Tenant Access Policy**.

Good change. It should have lived there all along — deciding which tenant can see your calendars is an identity trust decision, not a mail routing one.

But if you've ever merged or split a tenant, you know these relationships pile up. Every acquisition leaves one behind. Nobody removes them, because nobody's sure what breaks.

`Get-CrossTenantInventory.ps1` tells you what you actually have before the migration asks.

## What it finds

| Finding | Meaning |
|---|---|
| `STALE` | The partner domain no longer resolves to any Microsoft 365 tenant. Usually a company you don't work with anymore — a standing trust nobody removed. |
| `DISABLED` | The relationship exists but is switched off. Candidate for removal. |
| `ACTION` | Shares Free/Busy, but there's no Cross-Tenant Access Policy partner entry for that tenant yet. Will need one. |
| `OK` | Nothing to flag. |

It also counts availability address spaces and intra-organization connectors, since those tend to accumulate alongside.

## Run it

```powershell
./Get-CrossTenantInventory.ps1
```

Write the results to CSV:

```powershell
./Get-CrossTenantInventory.ps1 -OutputPath ./reports
```

Only the things that need a look:

```powershell
./Get-CrossTenantInventory.ps1 | Where-Object Finding -ne 'OK'
```

Exchange only, if you can't consent to the Graph scope:

```powershell
./Get-CrossTenantInventory.ps1 -SkipGraph
```

## Requirements

- PowerShell 7
- `ExchangeOnlineManagement` 3.x
- `Microsoft.Graph.Identity.SignIns`
- Exchange: **View-Only Organization Management** is enough
- Graph: **Policy.Read.All** — read-only

## How the tenant check works

Organization relationships are keyed by **domain**. Cross-Tenant Access Policy is keyed by **tenant ID**. You can't compare them directly.

The script resolves each domain to its tenant ID through the public OpenID configuration endpoint — the same lookup any Microsoft sign-in page performs. No authentication needed, and it reveals nothing beyond the tenant ID.

A domain that returns nothing is the interesting case. It's almost always a relationship that outlived the company on the other end.

## Read-only

Nothing is created, changed or removed. The script reads configuration and reports on it. Cleanup is your decision, made with the output in front of you.
