# Consent posture

Consent is how an application gets access to your organization's data. Since agent identities arrived in Entra, it's also how **agents** get in: the same setting now reads *"applications and agent identities"*.

Most tenants set the policy once. Few ever open the queue it creates.

`Get-ConsentPosture.ps1` reads the whole picture in one command.

## What it reports

| Section | What you get |
|---|---|
| **Who can consent** | The grant policies assigned to the default user role, translated into plain words. Blocked, low-risk only, legacy "anything goes", or managed by Microsoft. |
| **Low-risk classifications** | Which delegated permissions you've told Entra are low risk. These decide what users can approve by themselves when consent isn't blocked. |
| **Admin consent workflow** | Enabled or not, who the reviewers are, whether they're notified, and after how many days a request expires. |
| **The request queue** | Every request with its status and age: pending, completed, denied, expired. The portal shows these one at a time, which is why nobody counts them. |

## What it flags

| Severity | Finding |
|---|---|
| `HIGH` | Users can consent to any app under the legacy policy — the setting consent-phishing campaigns rely on |
| `HIGH` | Users can neither consent nor request: a dead end, and the point where people start using personal accounts |
| `HIGH` | The workflow is on but has no reviewers |
| `MEDIUM` | Consent limits are delegated to Microsoft's "recommended" setting and can change without your decision |
| `MEDIUM` | `offline_access` is classified low risk — the permission that keeps access alive after the user has gone |
| `MEDIUM` | One named user is the only reviewer |
| `MEDIUM` | Requests pending, with the age of the oldest |
| `MEDIUM` | Requests still pending past the expiry window, so expiry may not be applied |
| `MEDIUM` | Requests that expired without a decision |

## Run it

```powershell
./Get-ConsentPosture.ps1
```

Keep the queue as a CSV:

```powershell
./Get-ConsentPosture.ps1 -OutputPath ./reports
```

Only the findings, as objects:

```powershell
./Get-ConsentPosture.ps1 -PassThru | Where-Object Severity -eq 'HIGH'
```

## Requirements

- PowerShell 7
- `Microsoft.Graph.Authentication`
- Graph: **Policy.Read.All**, **ConsentRequest.Read.All**, **Directory.Read.All** — all read-only, admin consent needed once per tenant
- Entra role: **Global Reader** is enough

If the consent request queue can't be read, the report says so and everything else still works.

## Why the queue matters

A consent request that nobody answers is still an answer. The user asked for a tool, heard nothing, and either gave up or used it with a personal account. The second outcome leaves no record in your tenant at all.

## A note on the Graph API

`GET /identityGovernance/appConsent/appConsentRequests` accepts `$expand=userConsentRequests` and then ignores it: the parent objects come back with no user requests attached. Statuses and dates have to be fetched per request, which is what this script does. Expanding would have shown an empty queue in a tenant that had dozens of requests.

Note also that the portal's **My Pending** queue shows only the requests waiting for *you*. The totals here cover every request in the tenant, which is usually a much larger number.

## Read-only

Nothing is created, changed or removed.
