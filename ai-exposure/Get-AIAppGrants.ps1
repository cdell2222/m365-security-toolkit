#Requires -Version 7.0
<#
.SYNOPSIS
    Finds the AI tools that already hold access to your tenant, who let them in,
    and what they can reach.

.DESCRIPTION
    Shadow AI rarely arrives through a project. Someone signs in to a note taker
    with their work account, clicks through a consent screen, and the tool holds a
    grant on your tenant from then on.

    READ-ONLY. It connects, reads and reports. Nothing is created, changed or removed.

    For every service principal whose name or publisher looks like an AI tool, it
    reports:
      - how it got in: admin consent for everyone, or user by user
      - the delegated scopes and application roles it holds
      - whether the publisher is verified, and who published it
      - when it last signed in, so you can tell live tools from forgotten ones

    Name matching is a heuristic, not an inventory. Use -Pattern to add your own
    terms, and -AllApps to review every third-party app with a grant.

.PARAMETER Pattern
    Extra regex terms to treat as AI tools, on top of the built-in list.

.PARAMETER AllApps
    Report every third-party application with a grant, not only the AI matches.

.PARAMETER OutputPath
    Optional folder. Writes a timestamped CSV of the apps there.

.PARAMETER PassThru
    Also return the findings as objects.

.EXAMPLE
    ./Get-AIAppGrants.ps1

.EXAMPLE
    ./Get-AIAppGrants.ps1 -Pattern 'acme-copilot|internal-llm' -OutputPath ./reports

.NOTES
    Modules : Microsoft.Graph.Authentication
    Graph   : Application.Read.All, Directory.Read.All, AuditLog.Read.All
              all read-only. AuditLog.Read.All is only used for last sign-in and
              the report still works without it.

    Role    : Global Reader is enough.
#>
[CmdletBinding()]
param(
    [string] $Pattern,
    [switch] $AllApps,
    [string] $OutputPath,
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'

# Vendors and products seen consenting in real tenants. Deliberately broad: a false
# positive costs you one line to read, a miss costs you an unseen grant.
$AiPattern = @(
    'openai', 'chatgpt', 'anthropic', 'claude', 'perplexity', 'mistral', 'cohere',
    'gemini', 'bard', 'copilot', 'huggingface', 'replicate', 'midjourney',
    'otter\.ai', 'fireflies', 'fathom', 'read\.ai', 'tldv', 'sembly', 'supernormal',
    'krisp', 'avoma', 'grain', 'chorus', 'gong', 'rewind',
    'jasper', 'writer\.com', 'grammarly', 'notion', 'mem\.ai', 'glean',
    'synthesia', 'descript', 'elevenlabs', 'runway', 'heygen', 'gamma\.app',
    'cursor', 'codeium', 'tabnine', 'sourcegraph', 'lovable', 'bolt\.new',
    '\bai\b', 'a\.i\.', 'gpt', 'llm', 'genai', 'assistant'
) -join '|'

if ($Pattern) { $AiPattern = "$AiPattern|$Pattern" }

# Scopes worth stopping on, with the reason in plain words.
$RiskyScopes = @{
    'Mail.Read'                = 'read all mail the user can read'
    'Mail.ReadWrite'           = 'read and change mail'
    'Mail.Send'                = 'send mail as the user'
    'Files.Read.All'           = 'read every file the user can reach'
    'Files.ReadWrite.All'      = 'read and change every file the user can reach'
    'Sites.Read.All'           = 'read every SharePoint site the user can reach'
    'Sites.ReadWrite.All'      = 'read and change SharePoint content'
    'Chat.Read'                = 'read Teams chats'
    'Chat.ReadWrite'           = 'read and write Teams chats'
    'ChannelMessage.Read.All'  = 'read Teams channel messages'
    'OnlineMeetings.Read'      = 'read meeting details'
    'OnlineMeetingTranscript.Read.All' = 'read meeting transcripts'
    'Calendars.Read'           = 'read calendars'
    'Calendars.ReadWrite'      = 'read and change calendars'
    'Directory.Read.All'       = 'read the whole directory'
    'User.Read.All'            = 'read every user profile'
    'Group.Read.All'           = 'read every group'
    'offline_access'           = 'keep working when the user is not there'
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Severity, $App, $Finding)
    $findings.Add([pscustomobject]@{ Severity = $Severity; App = $App; Finding = $Finding })
}

function Get-GraphAll {
    param([Parameter(Mandatory)][string] $Uri, [switch] $Quiet)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        try { $page = Invoke-MgGraphRequest -Method GET -Uri $Uri }
        catch {
            if (-not $Quiet) { Write-Verbose "GET $Uri failed: $($_.Exception.Message)" }
            return $null
        }
        foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
        $Uri = $page.'@odata.nextLink'
    }
    $items
}

# --- connect ---------------------------------------------------------------

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All' -NoWelcome
}
catch {
    if ($_.Exception.Message -match 'Method not found') {
        Write-Host ''
        Write-Host 'Graph could not load its authentication library.' -ForegroundColor Red
        Write-Host 'Another module (usually ExchangeOnlineManagement) loaded an older MSAL in this session.' -ForegroundColor Yellow
        Write-Host 'Fix: open a NEW PowerShell 7 window and run the script there.' -ForegroundColor Yellow
        return
    }
    throw
}

$tenantId = (Get-MgContext).TenantId

# --- collect ---------------------------------------------------------------

Write-Host 'Reading service principals...' -ForegroundColor Cyan
$sps = Get-GraphAll -Uri ('v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,' +
                          'verifiedPublisher,publisherName,servicePrincipalType,accountEnabled,tags&$top=999')
if ($null -eq $sps) { throw 'Could not read service principals. Application.Read.All is needed.' }

$spById = @{}
foreach ($sp in $sps) { $spById["$($sp.id)"] = $sp }

Write-Host 'Reading delegated grants...' -ForegroundColor Cyan
$grants = Get-GraphAll -Uri 'v1.0/oauth2PermissionGrants?$top=999'
if ($null -eq $grants) { $grants = @() }

Write-Host 'Reading sign-in activity...' -ForegroundColor Cyan
$signIns = Get-GraphAll -Uri 'v1.0/reports/servicePrincipalSignInActivities?$top=999' -Quiet
$lastSignIn = @{}
if ($signIns) {
    foreach ($s in $signIns) {
        $dates = @(
            $s.lastSignInActivity.lastSignInDateTime,
            $s.delegatedClientSignInActivity.lastSignInDateTime,
            $s.applicationAuthenticationClientSignInActivity.lastSignInDateTime
        ) | Where-Object { $_ }
        # @() matters: with one date, indexing a bare string returns its first character.
        if ($dates) { $lastSignIn["$($s.appId)"] = @($dates | Sort-Object -Descending)[0] }
    }
}
else {
    Write-Host '  (no sign-in data - AuditLog.Read.All or an Entra ID P1 licence is needed)' -ForegroundColor Yellow
}

# Delegated grants, grouped per client application.
$grantsByClient = $grants | Group-Object clientId

# --- assess ----------------------------------------------------------------

$rows = foreach ($g in $grantsByClient) {
    $sp = $spById["$($g.Name)"]
    if (-not $sp) { continue }

    $isMicrosoft = ("$($sp.appOwnerOrganizationId)" -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a') -or
                   ("$($sp.publisherName)" -match '^Microsoft')
    # Agents built in your own tenant are governed through Entra Agent ID, not through
    # a publisher. Treating them as unverified vendors is noise.
    $isInternalAgent = ("$($sp.displayName)" -match '\(Microsoft Copilot Studio\)|\(Security Copilot\)|\(Azure AI Foundry\)')
    $isOwnTenant = ("$($sp.appOwnerOrganizationId)" -eq "$tenantId")
    $name        = "$($sp.displayName)"
    $looksAi     = ($name -match $AiPattern) -or ("$($sp.publisherName)" -match $AiPattern)

    if (-not $AllApps) {
        if (-not $looksAi) { continue }
        # Your own app registrations are not shadow IT. Agents built here are still worth seeing.
        if ($isOwnTenant -and -not $isInternalAgent) { continue }
    }

    $scopes = @($g.Group | ForEach-Object { "$($_.scope)".Trim() -split '\s+' } | Where-Object { $_ } | Sort-Object -Unique)
    $tenantWide = @($g.Group | Where-Object { $_.consentType -eq 'AllPrincipals' }).Count -gt 0
    $userCount  = @($g.Group | Where-Object { $_.consentType -eq 'Principal' -and $_.principalId }).Count
    $risky      = @($scopes | Where-Object { $RiskyScopes.ContainsKey($_) })
    $verified   = [bool] $sp.verifiedPublisher.displayName
    $last       = $lastSignIn["$($sp.appId)"]

    [pscustomobject]@{
        App          = $name
        Origin       = $(if ($isInternalAgent) { 'agent built here' }
                         elseif ($isMicrosoft) { 'Microsoft' }
                         elseif ($isOwnTenant) { 'own registration' }
                         else { 'external vendor' })
        Publisher    = $(if ($sp.verifiedPublisher.displayName) { "$($sp.verifiedPublisher.displayName)" }
                         elseif ($sp.publisherName) { "$($sp.publisherName)" } else { '(none)' })
        Verified     = $verified
        Microsoft    = $isMicrosoft
        ConsentType  = $(if ($tenantWide) { 'whole tenant' } else { "$userCount user(s)" })
        Users        = $userCount
        RiskyScopes  = ($risky -join ', ')
        AllScopes    = ($scopes -join ' ')
        LastSignIn   = $(if ($last) { ([datetime]$last).ToString('yyyy-MM-dd') } else { '' })
        AppId        = "$($sp.appId)"
        Enabled      = [bool] $sp.accountEnabled
    }
}

$rows = @($rows | Sort-Object { $_.RiskyScopes.Length } -Descending)

foreach ($r in $rows) {
    if ($r.Microsoft) { continue }   # first-party Microsoft apps are a different conversation

    if ($r.Origin -eq 'agent built here') {
        if ($r.RiskyScopes) {
            Add-Finding MEDIUM $r.App ("Agent built in this tenant, holding: {0}. Review it as an agent identity, not as a vendor app." -f $r.RiskyScopes)
        }
        else {
            Add-Finding INFO $r.App 'Agent built in this tenant. Its permissions may also be inherited from its blueprint, which does not show here.'
        }
        continue
    }

    if ($r.ConsentType -eq 'whole tenant' -and $r.RiskyScopes) {
        Add-Finding HIGH $r.App ("Consented for the whole tenant, holding: {0}. Every user's data is in scope, whether they use the tool or not." -f $r.RiskyScopes)
    }
    elseif ($r.RiskyScopes) {
        Add-Finding MEDIUM $r.App ("{0} user(s) consented, holding: {1}." -f $r.Users, $r.RiskyScopes)
    }
    if (-not $r.Verified) {
        Add-Finding MEDIUM $r.App 'Publisher is not verified. Anyone can name an app anything.'
    }
    if ($r.AllScopes -match '\boffline_access\b') {
        Add-Finding MEDIUM $r.App 'Holds offline_access: it keeps working when the user is not there, until the grant is removed.'
    }
    if (-not $r.LastSignIn -and $signIns) {
        Add-Finding INFO $r.App 'No recent sign-in. A grant nobody uses is still a grant.'
    }
    if ($r.Users -ge 5) {
        Add-Finding INFO $r.App ("{0} people consented individually. That is a demand signal, not a security event." -f $r.Users)
    }
}

# --- report ----------------------------------------------------------------

Write-Host ''
Write-Host ('Third-party apps with delegated grants: {0}' -f @($grantsByClient).Count) -ForegroundColor White
Write-Host ($(if ($AllApps) { 'Showing all of them, no filter' } else { "{0} of them look like AI tools" -f $rows.Count })) -ForegroundColor White

if ($rows.Count) {
    Write-Host ''
    $rows | Format-Table App, Origin, Publisher, ConsentType, LastSignIn, RiskyScopes -AutoSize -Wrap | Out-Host
}
else {
    Write-Host ''
    Write-Host 'No AI tools matched. Try -Pattern with your own terms, or -AllApps to see everything.' -ForegroundColor Green
}

$rank   = @{ HIGH = 0; MEDIUM = 1; INFO = 2 }
$sorted = @($findings | Sort-Object { $rank[$_.Severity] }, App)

if ($sorted.Count) {
    Write-Host ('Findings: {0}' -f (($sorted | Group-Object Severity | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ')) -ForegroundColor Yellow
    foreach ($f in $sorted) {
        $color = switch ($f.Severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }
        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $f.Severity, $f.App) -ForegroundColor $color
        Write-Host ('    {0}' -f $f.Finding) -ForegroundColor Gray
    }
}

if ($OutputPath -and $rows.Count) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $file = Join-Path $OutputPath ('ai-app-grants-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date))
    $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Written: $file" -ForegroundColor Cyan
}

if ($PassThru) { $sorted }
