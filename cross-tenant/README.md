# Cross-tenant tools

Two read-only scripts covering how other tenants reach into yours.

| Script | Question it answers |
|---|---|
| [`Get-CrossTenantInventory.ps1`](#cross-tenant-inventory) | Which tenants can see our calendars, and are we ready for that to move into Entra? |
| [`Get-CrossTenantAccessReview.ps1`](#cross-tenant-access-review) | Who can get in, and whose MFA and device decisions have we agreed to trust? |

---

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
- Graph: **Policy.Read.All** — read-only, needs admin consent once per tenant (see [Consent](#consent) below). Skip it with `-SkipGraph`.

## Known issue: `Method not found ... WithLogging`

If `Connect-MgGraph` fails with:

```
InteractiveBrowserCredential authentication failed: Method not found:
'... BaseAbstractApplicationBuilder`1.WithLogging(...IIdentityLogger, Boolean)'
```

That's not your tenant. `ExchangeOnlineManagement` and `Microsoft.Graph` each ship their own version of MSAL, and whichever loads first wins for the whole session. If Exchange loads first, Graph breaks.

The script connects to Graph first to avoid this. But if you've already run `Connect-ExchangeOnline` in the same window, the older library is already loaded. Open a **fresh PowerShell 7 window** and run the script there.

If it still fails, update both modules so their MSAL versions line up:

```powershell
Update-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, ExchangeOnlineManagement
```

Or skip the Graph check entirely with `-SkipGraph`.

## Known issue: `NullReferenceException` at `RuntimeBroker`

ExchangeOnlineManagement 3.7+ signs in through the Windows authentication broker (WAM). When there's no usable console window — `pwsh` launched from another shell, some terminals, remote sessions — it fails with `Object reference not set to an instance of an object` inside `RuntimeBroker..ctor`.

The script avoids this by always connecting with `-DisableWAM`, which uses the normal browser sign-in. If your module version is too old to have that switch and you hit this error, run `Update-Module ExchangeOnlineManagement`.

## How the tenant check works

Organization relationships are keyed by **domain**. Cross-Tenant Access Policy is keyed by **tenant ID**. You can't compare them directly.

The script resolves each domain to its tenant ID through the public OpenID configuration endpoint — the same lookup any Microsoft sign-in page performs. No authentication needed, and it reveals nothing beyond the tenant ID.

A domain that returns nothing is the interesting case. It's almost always a relationship that outlived the company on the other end.

## Read-only

Nothing is created, changed or removed. The script reads configuration and reports on it. Cleanup is your decision, made with the output in front of you.

---

# Cross-tenant access review

Cross-Tenant Access Policy is where Entra decides how every other tenant interacts with yours. Guest access, Teams shared channels, cross-tenant sync — and, less visibly, whether your Conditional Access accepts **someone else's** MFA and device compliance claims.

Those trust settings are the ones that matter. Turn on "trust MFA from external tenants" in the default policy and a user who passed MFA in *any* Entra tenant satisfies your MFA requirement. Turn on compliant-device trust and a laptop that some other company's Intune calls compliant counts as compliant for you. You don't control their bar.

They're usually switched on to make a pilot or a partner project work, and nobody switches them off afterwards.

`Get-CrossTenantAccessReview.ps1` reads the default policy and every partner entry and tells you what's open, what's trusted, and what's dead.

## What it flags

| Severity | Finding |
|---|---|
| `HIGH` | Default policy trusts external MFA, compliant devices or hybrid-joined devices — from every tenant |
| `HIGH` | Partner entry for a tenant that no longer exists |
| `MEDIUM` | Default policy lets any tenant's users be invited as guests to all apps (Microsoft's default — should be a decision, not an accident) |
| `MEDIUM` | Default policy allows inbound B2B direct connect (Teams shared channels) — Microsoft's default is blocked, so someone changed it |
| `MEDIUM` | Partner can sync users into your directory (cross-tenant sync inbound) |
| `MEDIUM` | Partner invitations are redeemed automatically, with no consent prompt |
| `MEDIUM` | Partner's device compliance or hybrid join is trusted |
| `MEDIUM` | Partner's users can reach all your Teams shared channels |
| `INFO` | Partner's MFA is trusted — usually deliberate, confirm it still holds |
| `INFO` | Partner flagged as service provider (GDAP / CSP) |
| `INFO` | Partner entry that overrides nothing — inherits every default |

It also prints the default policy posture and a one-line-per-partner overview: exists, MFA trusted, devices trusted, sync, auto-redeem.

## Run it

```powershell
./Get-CrossTenantAccessReview.ps1
```

Findings and partner overview to CSV:

```powershell
./Get-CrossTenantAccessReview.ps1 -OutputPath ./reports
```

Only the serious ones:

```powershell
./Get-CrossTenantAccessReview.ps1 | Where-Object Severity -eq 'HIGH'
```

## Requirements

- PowerShell 7
- `Microsoft.Graph.Authentication` — Graph only, no Exchange module, so the MSAL conflict above doesn't apply
- Graph: **Policy.Read.All** — read-only
- Graph: **CrossTenantInformation.ReadBasic.All** — read-only, used only to turn tenant IDs into names. Without it, partners show as tenant IDs.
- Entra role: **Security Reader** is the least-privileged role that can read Cross-Tenant Access Policy. Global Reader also works. Without a role, Graph returns 403.

### Consent

`Policy.Read.All` always needs **admin consent**, whatever your tenant's user consent settings are. A Security Reader can't grant it alone.

- **Already granted** (someone has used Graph PowerShell with this scope before): nothing to do.
- **Admin consent workflow enabled**: the user gets a "Need admin approval" screen and can submit a request. An admin approves it under *Entra → Enterprise apps → Admin consent requests*.
- **Admin consent workflow disabled**: the user is blocked and has to ask an admin.
- **"Assignment required" on Microsoft Graph Command Line Tools**: the user (or a group) must be assigned to that app first.

The simplest fix is for a Global Administrator, Privileged Role Administrator or Cloud Application Administrator to run this once and tick *Consent on behalf of your organization*:

```powershell
Connect-MgGraph -Scopes Policy.Read.All, CrossTenantInformation.ReadBasic.All
```

After that, any Security Reader can run the script.

## What it doesn't cover

Cross-Tenant Access Policy is the Entra side. It doesn't look at Teams external access (federation), SharePoint and OneDrive external sharing, or the guest accounts already in your directory. Those are separate controls, and a review of them belongs in a separate tool.

## Read-only

Nothing is created, changed or removed.
