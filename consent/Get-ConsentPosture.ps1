#Requires -Version 7.0
<#
.SYNOPSIS
    Reports who can consent to apps and agents in your tenant, and what happens to
    the requests nobody answers.

.DESCRIPTION
    Consent is how applications - and now agent identities - get access to your
    organization's data. Most tenants set the policy once and never look at the
    queue it creates.

    READ-ONLY. It connects, reads and reports. Nothing is created, changed or removed.

    It reports on:
      - who can consent, from the tenant's authorization policy
      - which delegated permissions are classified low risk
      - the admin consent request workflow: enabled, reviewers, expiry
      - the request queue: pending, approved, denied, expired, and how old they are

    The queue is the part the portal makes painful: it shows requests one at a time,
    so nobody counts them. This counts them.

.PARAMETER OutputPath
    Optional folder. Writes a timestamped CSV of the consent requests there.

.PARAMETER PassThru
    Also return the findings as objects. Without it, the script only prints the report.

.EXAMPLE
    ./Get-ConsentPosture.ps1

.EXAMPLE
    ./Get-ConsentPosture.ps1 -OutputPath ./reports

.NOTES
    Modules : Microsoft.Graph.Authentication
    Graph   : Policy.Read.All, ConsentRequest.Read.All, Directory.Read.All
              all read-only, admin consent needed once per tenant

    Role    : Global Reader is enough to read everything here.

    Microsoft's documentation:
    https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'

$GraphAppId = '00000003-0000-0000-c000-000000000000'

# The built-in grant policies, in plain words.
$GrantPolicyMeaning = @{
    'ManagePermissionGrantsForSelf.microsoft-user-default-low'      = 'users may consent to low-risk permissions, for apps from verified publishers or registered in this tenant'
    'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'   = 'users may consent to ANY permission that does not require admin consent, for ANY app'
    'ManagePermissionGrantsForSelf.microsoft-user-default-recommended' = 'Microsoft manages the limits, and can change them without you'
    'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat' = 'Teams chat resource-specific consent'
    'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team' = 'Teams team resource-specific consent'
}

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param($Severity, $Area, $Finding)
    $findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Finding = $Finding })
}

function Get-Graph {
    <# GET that returns $null instead of throwing, so one missing scope doesn't kill the report. #>
    param([Parameter(Mandatory)][string] $Uri)
    try { Invoke-MgGraphRequest -Method GET -Uri $Uri }
    catch {
        Write-Verbose "GET $Uri failed: $($_.Exception.Message)"
        $null
    }
}

function Get-GraphAll {
    param([Parameter(Mandatory)][string] $Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Get-Graph -Uri $Uri
        if ($null -eq $page) { return $null }
        foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
        $Uri = $page.'@odata.nextLink'
    }
    $items
}

# --- connect ---------------------------------------------------------------

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes 'Policy.Read.All', 'ConsentRequest.Read.All', 'Directory.Read.All' -NoWelcome
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

# --- 1. who can consent ----------------------------------------------------

$authz     = Get-Graph -Uri 'v1.0/policies/authorizationPolicy'
$assigned  = @($authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
$userGrant = @($assigned | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })

$consentState =
    if     ($null -eq $authz)      { 'unknown - could not read the authorization policy' }
    elseif (-not $userGrant.Count) { 'blocked - users cannot consent to anything' }
    else                           { 'allowed - see the policies below' }

if ($userGrant -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
    Add-Finding HIGH 'User consent' 'Users can consent to any app for any permission that does not require admin consent. This is the legacy setting and the one consent phishing relies on.'
}
if ($userGrant -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended') {
    Add-Finding MEDIUM 'User consent' "Consent limits are managed by Microsoft. They can change without a decision on your side - fine if that's deliberate, worth knowing if it isn't."
}

# --- 2. what counts as low risk -------------------------------------------

$classifications = @(Get-GraphAll -Uri "v1.0/servicePrincipals(appId='$GraphAppId')/delegatedPermissionClassifications")
$lowNames = @($classifications | Where-Object { $_.classification -eq 'low' } | ForEach-Object { "$($_.permissionName)" })

if ($lowNames -contains 'offline_access') {
    Add-Finding MEDIUM 'Classifications' 'offline_access is classified low risk. It is the permission that keeps an app working after the user has gone - the difference between a session and a standing grant.'
}

# --- 3. the workflow -------------------------------------------------------

$policy = Get-Graph -Uri 'v1.0/policies/adminConsentRequestPolicy'
$reviewerScopes = @($policy.reviewers | ForEach-Object { "$($_.query)" })

function Resolve-Reviewer {
    <# Reviewer scopes are raw Graph queries. Turn them into names. #>
    param([string] $Query)

    if ($Query -match '/users/([0-9a-f-]{36})') {
        $u = Get-Graph -Uri "v1.0/users/$($Matches[1])?`$select=displayName,userPrincipalName"
        if ($u) { return "user: $($u.displayName)" }
        return "user: $($Matches[1])"
    }
    if ($Query -match "roleDefinitionId eq '([0-9a-f-]{36})'") {
        $r = Get-Graph -Uri "v1.0/roleManagement/directory/roleDefinitions/$($Matches[1])?`$select=displayName"
        if ($r) { return "role: $($r.displayName)" }
        return "role: $($Matches[1])"
    }
    if ($Query -match '/groups/([0-9a-f-]{36})') {
        $g = Get-Graph -Uri "v1.0/groups/$($Matches[1])?`$select=displayName"
        if ($g) { return "group: $($g.displayName)" }
        return "group: $($Matches[1])"
    }
    return $Query
}

$reviewerNames = @($reviewerScopes | ForEach-Object { Resolve-Reviewer -Query $_ })

if ($policy -and -not $policy.isEnabled) {
    if (-not $userGrant.Count) {
        Add-Finding HIGH 'Workflow' 'Users cannot consent AND cannot request. They hit a wall with no route - the point where people start using a personal account instead.'
    }
    else {
        Add-Finding MEDIUM 'Workflow' 'The admin consent request workflow is off, so users have no way to ask.'
    }
}
if ($policy.isEnabled -and -not $reviewerScopes.Count) {
    Add-Finding HIGH 'Workflow' 'The workflow is on but no reviewers are configured. Requests go nowhere.'
}
if ($policy.isEnabled -and -not $policy.notifyReviewers) {
    Add-Finding MEDIUM 'Workflow' 'Reviewers are not notified by email. Someone has to remember to open the blade.'
}
$singleUserReviewer = @($reviewerScopes | Where-Object { $_ -like '*/users/*' })
if ($policy.isEnabled -and $singleUserReviewer.Count -eq 1 -and $reviewerScopes.Count -eq 1) {
    Add-Finding MEDIUM 'Workflow' 'One named user is the only reviewer. Holidays and leavers stall the queue - add a role or a group.'
}

# --- 4. the queue ----------------------------------------------------------

# $expand=userConsentRequests is accepted and then ignored by this endpoint: the
# parent objects come back with no user requests, which looks like an empty queue.
# The statuses and dates have to be fetched per request.
$requests = Get-GraphAll -Uri 'v1.0/identityGovernance/appConsent/appConsentRequests'
$queue = @()

if ($null -eq $requests) {
    Add-Finding CHECK 'Queue' 'Could not read the consent request queue. ConsentRequest.Read.All is needed, and the workflow must have been enabled at some point.'
}
else {
    Write-Host ("Reading {0} consent request(s)..." -f $requests.Count) -ForegroundColor Cyan
    $i = 0
    $now = Get-Date
    $queue = foreach ($r in $requests) {
        $i++
        Write-Progress -Activity 'Reading consent requests' -Status "$i of $($requests.Count)" -PercentComplete ($i * 100 / [Math]::Max($requests.Count, 1))
        $userReqs = Get-GraphAll -Uri "v1.0/identityGovernance/appConsent/appConsentRequests/$($r.id)/userConsentRequests"
        if ($null -eq $userReqs) { $userReqs = @() }
        foreach ($u in $userReqs) {
            $created = if ($u.createdDateTime) { [datetime] $u.createdDateTime } else { $null }
            [pscustomobject]@{
                App       = "$($r.appDisplayName)"
                AppId     = "$($r.appId)"
                Status    = "$($u.status)"
                Created   = $created
                AgeDays   = if ($created) { [int] ($now - $created).TotalDays } else { $null }
                Reason    = "$($u.reason)"
                Scopes    = (@($r.pendingScopes | ForEach-Object { $_.displayName }) -join ', ')
            }
        }
    }

    Write-Progress -Activity 'Reading consent requests' -Completed
    $pending = @($queue | Where-Object Status -eq 'InProgress')
    $stale   = @($pending | Where-Object { $_.AgeDays -gt 30 })
    $expired = @($queue | Where-Object Status -eq 'Expired')

    if ($pending.Count) {
        $oldest = ($pending | Sort-Object AgeDays -Descending | Select-Object -First 1).AgeDays
        Add-Finding MEDIUM 'Queue' ("{0} request(s) pending, the oldest {1} day(s) old. A request nobody answers is a decision, just not a recorded one." -f $pending.Count, $oldest)
    }
    if ($policy.requestDurationInDays -and $stale.Count) {
        Add-Finding MEDIUM 'Queue' ("{0} request(s) have been pending longer than the {1}-day expiry. Check whether expiry is actually being applied." -f $stale.Count, $policy.requestDurationInDays)
    }
    if ($expired.Count) {
        Add-Finding MEDIUM 'Queue' ("{0} request(s) expired without a decision. The user was refused by silence, and still needed the tool." -f $expired.Count)
    }
}

# --- report ----------------------------------------------------------------

Write-Host ''
Write-Host 'Who can consent' -ForegroundColor White
Write-Host ('  User consent        : {0}' -f $consentState)
foreach ($p in $userGrant) {
    $meaning = if ($GrantPolicyMeaning.ContainsKey($p)) { $GrantPolicyMeaning[$p] } else { 'custom policy - read it before trusting it' }
    Write-Host ('    {0}' -f $p) -ForegroundColor Gray
    Write-Host ('      {0}' -f $meaning) -ForegroundColor Gray
}
Write-Host ('  Group owners consent: {0}' -f [bool] $authz.defaultUserRolePermissions.allowedToCreateApps)
Write-Host ('  Low-risk permissions: {0}' -f $(if ($lowNames.Count) { $lowNames -join ', ' } else { 'none classified' }))

Write-Host ''
Write-Host 'Admin consent workflow' -ForegroundColor White
if ($policy) {
    Write-Host ('  Enabled   : {0}' -f [bool] $policy.isEnabled)
    Write-Host ('  Reviewers : {0}' -f $(if ($reviewerNames.Count) { $reviewerNames -join ', ' } else { 'none' }))
    Write-Host ('  Notify    : {0}, reminders: {1}' -f [bool] $policy.notifyReviewers, [bool] $policy.remindersEnabled)
    Write-Host ('  Expires   : after {0} day(s)' -f $policy.requestDurationInDays)
}
else {
    Write-Host '  Could not read the workflow policy.' -ForegroundColor Yellow
}

if ($queue.Count) {
    Write-Host ''
    Write-Host 'Request queue' -ForegroundColor White
    $queue | Group-Object Status | ForEach-Object {
        Write-Host ('  {0,-12}: {1}' -f $_.Name, $_.Count)
    }
    Write-Host ''
    $queue | Sort-Object AgeDays -Descending | Select-Object -First 10 |
        Format-Table App, Status, AgeDays, Scopes -AutoSize -Wrap | Out-Host
}

$rank   = @{ HIGH = 0; MEDIUM = 1; CHECK = 2; INFO = 3 }
$sorted = @($findings | Sort-Object { $rank[$_.Severity] })

Write-Host ''
if ($sorted.Count) {
    Write-Host ('Findings: {0}' -f (($sorted | Group-Object Severity | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ')) -ForegroundColor Yellow
    foreach ($f in $sorted) {
        $color = switch ($f.Severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $f.Severity, $f.Area) -ForegroundColor $color
        Write-Host ('    {0}' -f $f.Finding) -ForegroundColor Gray
    }
}
else {
    Write-Host 'Nothing flagged.' -ForegroundColor Green
}

if ($OutputPath -and $queue.Count) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $file = Join-Path $OutputPath ('consent-requests-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date))
    $queue | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Written: $file" -ForegroundColor Cyan
}

if ($PassThru) { $sorted }
