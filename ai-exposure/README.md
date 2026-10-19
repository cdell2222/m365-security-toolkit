# AI exposure

Shadow AI rarely arrives as a project. Someone signs in to a note taker with their work account, clicks through a consent screen, and from then on that tool holds a grant on your tenant.

`Get-AIAppGrants.ps1` answers one question: **which AI tools already have access, and what can they reach?**

## What it reports

| Column | Why it matters |
|---|---|
| **App / Publisher / Verified** | An unverified publisher means nothing stops an app being called anything |
| **ConsentType** | "whole tenant" means an admin approved it for everyone. "5 user(s)" means five people let it in one at a time |
| **RiskyScopes** | Only the scopes that reach real content: mail, files, sites, chats, meeting transcripts, calendars, directory, and `offline_access` |
| **LastSignIn** | Separates live tools from forgotten grants. Needs `AuditLog.Read.All` and an Entra ID P1 licence; the rest of the report works without it |

## What it flags

| Severity | Finding |
|---|---|
| `HIGH` | Consented for the whole tenant **and** holding scopes that reach content: every user is in scope, whether they use the tool or not |
| `MEDIUM` | Individual users consented to scopes that reach content |
| `MEDIUM` | Publisher is not verified |
| `MEDIUM` | Holds `offline_access`, so it keeps working when the user isn't there |
| `INFO` | No recent sign-in: a grant nobody uses is still a grant |
| `INFO` | Five or more individual consents: a demand signal, not a security event |

## Run it

```powershell
./Get-AIAppGrants.ps1
```

Add your own terms (internal tools, vendors specific to your sector):

```powershell
./Get-AIAppGrants.ps1 -Pattern 'acme-copilot|internal-llm'
```

Review every third-party app with a grant, not only the AI matches:

```powershell
./Get-AIAppGrants.ps1 -AllApps -OutputPath ./reports
```

## Requirements

- PowerShell 7
- `Microsoft.Graph.Authentication`
- Graph: **Application.Read.All**, **Directory.Read.All**, **AuditLog.Read.All** — all read-only
- Entra role: **Global Reader** is enough

## Honest limits

**Name matching is a heuristic.** It finds apps whose name or publisher looks like an AI tool. It will catch things that aren't, and miss anything named neutrally. Use `-AllApps` for a real review, and `-Pattern` to add what you know.

**It only sees OAuth grants.** A user pasting source code into a chatbot in their browser leaves no grant at all. This script finds the tools that were connected to your tenant, not every tool in use.

**First-party Microsoft apps are listed but not flagged.** Copilot holding broad permissions is a different conversation from a note taker holding them.

## Where to go next, from Microsoft

Grants are one of three layers, and the other two need the products, not a script:

| Layer | Microsoft's tool | Guidance |
|---|---|---|
| **Discover** what's in use, including tools with no grant | Defender for Cloud Apps app catalog, filtered to Generative AI, then sanctioned or unsanctioned | [Discover AI apps](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-data-leak-shadow-ai-step1) |
| **See the data** going into AI tools | Purview DSPM for AI, which needs devices onboarded to Purview | [DSPM for AI](https://learn.microsoft.com/en-us/purview/data-security-posture-management-learn-about) |
| **Stop the leak** | Endpoint DLP on pasting and uploading, Browser Data Security in Edge for prompts, sensitivity labels with encryption | [Block sensitive data to AI apps](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-data-leak-shadow-ai-step3) |

Microsoft's own sequence is discover, then block unsanctioned apps, then protect the data going to the sanctioned ones. Start DLP in simulation mode: the first run tells you how much of the business already depends on these tools.

## Read-only

Nothing is created, changed or removed. Removing a grant is your decision, and it will break whatever the user was doing with that tool.
