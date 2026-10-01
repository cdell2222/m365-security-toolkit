#Requires -Version 7.0
<#
.SYNOPSIS
    Inventories cross-tenant Free/Busy, MailTips and calendar sharing, and reports
    what is still missing for Microsoft 365 Cross-Tenant Access Policy.

.DESCRIPTION
    Cross-tenant Free/Busy, MailTips and calendar sharing are moving out of Exchange
    and into Microsoft 365 Cross-Tenant Access Policy - a capability layer on top of
    the Entra cross-tenant access partner entries. The Exchange side depends on EWS,
    which Microsoft starts disabling in October 2026 and finishes in April 2027.

    Three Exchange configurations are in scope:
      - organization relationships  (Free/Busy, MailTips)
      - availability address spaces (Free/Busy, OrgWideFBToken only)
      - sharing policies            (calendar sharing, including anonymous publishing)

    READ-ONLY. It connects, reads and reports. Nothing is created, changed or removed.

    For each one it reports what is shared today, and whether the matching Microsoft 365
    capability already exists:

      READY    - the partner has the trust and the capability. Nothing to do.
      ACTION   - something is missing: partner entry, Microsoft 365 collaboration trust,
                 or the capability itself. This is what breaks when EWS goes away.
      STALE    - the partner domain no longer resolves to a Microsoft 365 tenant.
      DISABLED - the configuration is switched off already.
      HYBRID   - points at your own tenant (Exchange hybrid). Out of scope for now.
      CHECK    - needs a manual look, or your role can't read the capabilities.

.PARAMETER OutputPath
    Optional folder. Writes timestamped CSVs there: sharing and sharing policies.

.PARAMETER SkipGraph
    Skip every Entra check and report the Exchange side only.

.PARAMETER PassThru
    Also return the results as objects, for filtering or further processing.
    Without it, the script only prints the report.

.EXAMPLE
    ./Get-CrossTenantInventory.ps1

.EXAMPLE
    ./Get-CrossTenantInventory.ps1 -OutputPath ./reports

.EXAMPLE
    ./Get-CrossTenantInventory.ps1 -PassThru | Where-Object Finding -like 'ACTION*'

.NOTES
    Modules  : ExchangeOnlineManagement 3.x, Microsoft.Graph.Authentication
    Exchange : View-Only Organization Management is enough
    Graph    : Policy.Read.All (read-only), admin consent needed once per tenant

    Role     : reading Microsoft 365 capabilities needs Global Administrator, or
               Exchange Administrator for the Free/Busy, MailTips and calendar
               sharing ones. With a lesser role those checks report CHECK and
               everything else still works.

    Microsoft's migration guide:
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $SkipGraph,
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'

# Exchange sharing level -> the Microsoft 365 capability that replaces it.
$FreeBusyCapability = @{
    'AvailabilityOnly' = 'crossTenantCalendarAvailabilityBasic'
    'LimitedDetails'   = 'crossTenantCalendarAvailabilityLimitedDetails'
}
$MailTipsCapability = @{
    'Limited' = 'crossTenantMailTipsLimited'
    'All'     = 'crossTenantMailTipsAll'
}
$SharingCapability = @{
    'CalendarSharingFreeBusySimple'   = 'crossTenantCalendarSharingFreeBusySimple'
    'CalendarSharingFreeBusyDetail'   = 'crossTenantCalendarSharingFreeBusyDetail'
    'CalendarSharingFreeBusyReviewer' = 'crossTenantCalendarSharingFreeBusyReviewer'
}
$AnonymousCapability = @{
    'CalendarSharingFreeBusySimple'   = 'anonymousCalendarSharingFreeBusySimple'
    'CalendarSharingFreeBusyDetail'   = 'anonymousCalendarSharingFreeBusyDetail'
    'CalendarSharingFreeBusyReviewer' = 'anonymousCalendarSharingFreeBusyReviewer'
}

function Resolve-TenantId {
    <# Returns the Entra tenant ID a domain belongs to, or $null if it doesn't resolve. #>
    param([Parameter(Mandatory)] [string] $Domain)

    $uri = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
    try {
        $cfg = Invoke-RestMethod -Uri $uri -TimeoutSec 10 -ErrorAction Stop
        if ($cfg.issuer -match '([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})') {
            return $Matches[1]
        }
    }
    catch {
        Write-Verbose "No tenant found for $Domain"
    }
    return $null
}

function Get-M365Capability {
    <#
    Capabilities configured for a partner, or for the default policy when no tenant ID
    is given. Returns a hashtable of capability name -> isAllowed, or $null when the
    signed-in role isn't allowed to read them.
    #>
    param([string] $TenantId)

    $uri = if ($TenantId) {
        "v1.0/policies/crossTenantAccessPolicy/partners/$TenantId/m365Capabilities"
    } else {
        'v1.0/policies/crossTenantAccessPolicy/default/m365Capabilities'
    }
    try {
        $caps = @{}
        foreach ($c in @((Invoke-MgGraphRequest -Method GET -Uri $uri).value)) {
            $name = if ($c.name) { "$($c.name)" } else { "$($c.'@odata.type')" -replace '^#?microsoft\.graph\.', '' }
            $caps[$name] = [bool] $c.inboundAccess.isAllowed
        }
        return $caps
    }
    catch {
        Write-Verbose "Could not read m365Capabilities for '$TenantId': $($_.Exception.Message)"
        return $null
    }
}

function Test-Capability {
    <# $true when the capability is configured and allowed. #>
    param($Capabilities, [string] $Name)
    return ($Capabilities -and $Capabilities.ContainsKey($Name) -and $Capabilities[$Name])
}

function Test-M365Trust {
    <# $true when the partner entry has Microsoft 365 collaboration trust inbound. #>
    param($Partner)
    return ($Partner.m365CollaborationInbound.users.accessType -eq 'allowed')
}

# --- connect ---------------------------------------------------------------
#
# Graph FIRST, then Exchange. ExchangeOnlineManagement and Microsoft.Graph each ship
# their own MSAL (Microsoft.Identity.Client.dll) and whichever loads first wins for
# the session. Loading Exchange first breaks Connect-MgGraph with
# "Method not found ... WithLogging". See the README.

$partners    = @{}
$defaultCaps = $null
if (-not $SkipGraph) {
    Write-Host 'Connecting to Microsoft Graph (Policy.Read.All)...' -ForegroundColor Cyan
    try {
        Connect-MgGraph -Scopes 'Policy.Read.All' -NoWelcome
    }
    catch {
        if ($_.Exception.Message -match 'Method not found') {
            Write-Host ''
            Write-Host 'Graph could not load its authentication library.' -ForegroundColor Red
            Write-Host 'Exchange Online is already loaded in this session with an older MSAL version.' -ForegroundColor Yellow
            Write-Host 'Fix: open a NEW PowerShell 7 window and run the script there.' -ForegroundColor Yellow
            Write-Host 'Or run it with -SkipGraph for an Exchange-only inventory.' -ForegroundColor Yellow
            return
        }
        throw
    }
    foreach ($p in @((Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/crossTenantAccessPolicy/partners').value)) {
        $partners["$($p.tenantId)"] = $p
    }
    $defaultCaps = Get-M365Capability
    if ($null -eq $defaultCaps) {
        Write-Host 'Note: this role cannot read Microsoft 365 capabilities - see the README (Global Admin, or Exchange Admin).' -ForegroundColor Yellow
    }
}

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
    # ExchangeOnlineManagement 3.7+ signs in through the Windows broker (WAM), which
    # crashes without a usable console window. -DisableWAM uses the browser instead.
    $exoParams = @{ ShowBanner = $false }
    if ((Get-Command Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM')) {
        $exoParams.DisableWAM = $true
    }
    Connect-ExchangeOnline @exoParams
}

# --- collect ---------------------------------------------------------------

# Our own tenant ID, so the Exchange hybrid relationship isn't mistaken for a partner.
$ownTenantId = "$(@(Get-ConnectionInformation)[0].TenantID)"
if (-not $ownTenantId -and -not $SkipGraph) { $ownTenantId = "$((Get-MgContext).TenantId)" }

$capsCache = @{}
function Get-PartnerCapabilityCached {
    param([string] $TenantId)
    if (-not $capsCache.ContainsKey($TenantId)) {
        $capsCache[$TenantId] = Get-M365Capability -TenantId $TenantId
    }
    return $capsCache[$TenantId]
}

$relationships   = @(Get-OrganizationRelationship)
$addressSpaces   = @(Get-AvailabilityAddressSpace)
$sharingPolicies = @(Get-SharingPolicy)
$connectors      = @(Get-IntraOrganizationConnector)

Write-Host ("Found {0} organization relationship(s), {1} availability address space(s), {2} sharing polic(y/ies)." -f `
    $relationships.Count, $addressSpaces.Count, $sharingPolicies.Count) -ForegroundColor Cyan

# --- organization relationships and availability address spaces -------------

function New-SharingRow {
    param(
        [string]   $Source,     # OrgRelationship | AvailabilityAddressSpace
        [string]   $Name,
        [bool]     $Enabled,
        [string]   $Domain,
        [string]   $Shares,     # what is shared today, in words
        [string[]] $Needed      # capabilities required to replace it
    )

    $tenantId = Resolve-TenantId -Domain $Domain
    $own      = ($tenantId -and $ownTenantId -and $tenantId -eq $ownTenantId)
    $partner  = if ($tenantId) { $partners["$tenantId"] } else { $null }
    $caps     = if ($partner -and -not $SkipGraph) { Get-PartnerCapabilityCached -TenantId $tenantId } else { $null }

    $missing = @()
    if ($caps) { $missing = @($Needed | Where-Object { -not (Test-Capability -Capabilities $caps -Name $_) }) }

    $finding =
        if     ($own)                           { 'HYBRID: your own tenant (Exchange hybrid) - not covered by the new model yet' }
        elseif (-not $tenantId)                 { 'STALE: domain no longer resolves to a Microsoft 365 tenant' }
        elseif (-not $Enabled)                  { 'DISABLED: switched off already - candidate for removal' }
        elseif (-not $Needed)                   { 'OK: nothing shared through this entry' }
        elseif ($SkipGraph)                     { 'CHECK: run without -SkipGraph to check the Microsoft 365 capabilities' }
        elseif (-not $partner)                  { 'ACTION: no Entra partner entry - create one with Microsoft 365 collaboration trust' }
        elseif (-not (Test-M365Trust $partner)) { 'ACTION: partner entry exists but Microsoft 365 collaboration trust is not enabled' }
        elseif ($null -eq $caps)                { 'CHECK: this role cannot read Microsoft 365 capabilities - see the README' }
        elseif ($missing.Count)                 { 'ACTION: missing capability - ' + ($missing -join ', ') }
        else                                    { 'READY: trust and capabilities already in place' }

    [pscustomobject]@{
        Source       = $Source
        Name         = $Name
        Enabled      = $Enabled
        Domain       = $Domain
        TenantId     = $tenantId
        Shares       = $Shares
        PartnerEntry = [bool] $partner
        M365Trust    = if ($partner) { Test-M365Trust $partner } else { $false }
        Needed       = ($Needed -join ', ')
        Missing      = ($missing -join ', ')
        Finding      = $finding
    }
}

$sharing = @(foreach ($rel in $relationships) {
    $needed = @()
    $shares = @()
    if ($rel.FreeBusyAccessEnabled -and $FreeBusyCapability.ContainsKey("$($rel.FreeBusyAccessLevel)")) {
        $needed += $FreeBusyCapability["$($rel.FreeBusyAccessLevel)"]
        $shares += "Free/Busy ($($rel.FreeBusyAccessLevel))"
    }
    if ($rel.MailTipsAccessEnabled -and $MailTipsCapability.ContainsKey("$($rel.MailTipsAccessLevel)")) {
        $needed += $MailTipsCapability["$($rel.MailTipsAccessLevel)"]
        $shares += "MailTips ($($rel.MailTipsAccessLevel))"
    }
    foreach ($domain in $rel.DomainNames) {
        New-SharingRow -Source 'OrgRelationship' -Name "$($rel.Name)" -Enabled ([bool] $rel.Enabled) `
                       -Domain "$domain" -Shares ($shares -join ' + ') -Needed $needed
    }
})

$sharing += @(foreach ($aas in $addressSpaces) {
    # Only OrgWideFBToken can move to a Microsoft 365 capability. Anything else is
    # cross-forest or legacy, and has to be handled separately.
    if ("$($aas.AccessMethod)" -ne 'OrgWideFBToken') {
        [pscustomobject]@{
            Source = 'AvailabilityAddressSpace'; Name = "$($aas.ForestName)"; Enabled = $true
            Domain = "$($aas.ForestName)"; TenantId = "$($aas.TargetTenantId)"
            Shares = "Free/Busy (AccessMethod $($aas.AccessMethod))"
            PartnerEntry = $false; M365Trust = $false; Needed = ''; Missing = ''
            Finding = "CHECK: AccessMethod $($aas.AccessMethod) can't move to Microsoft 365 Cross-Tenant Access Policy - review separately"
        }
    }
    else {
        New-SharingRow -Source 'AvailabilityAddressSpace' -Name "$($aas.ForestName)" -Enabled $true `
                       -Domain "$($aas.ForestName)" -Shares 'Free/Busy (address space)' `
                       -Needed @('crossTenantCalendarAvailabilityBasic')
    }
})

# --- sharing policies (calendar sharing) ------------------------------------

$policyRows = @(foreach ($pol in $sharingPolicies) {
    foreach ($entry in $pol.Domains) {
        # Each entry looks like "contoso.com: CalendarSharingFreeBusyDetail".
        $parts  = @(("$entry" -split ':', 2) | ForEach-Object { $_.Trim() })
        $domain = $parts[0]
        $level  = if ($parts.Count -gt 1) { $parts[1] } else { '' }

        $anonymous = ($domain -eq 'Anonymous')
        $wildcard  = ($domain -eq '*')
        $needed    = if ($anonymous) { $AnonymousCapability["$level"] } else { $SharingCapability["$level"] }

        $tenantId = if ($anonymous -or $wildcard) { $null } else { Resolve-TenantId -Domain $domain }
        $caps =
            if     ($SkipGraph)                { $null }
            elseif ($anonymous -or $wildcard)  { $defaultCaps }
            elseif ($tenantId -and $partners.ContainsKey("$tenantId")) { Get-PartnerCapabilityCached -TenantId $tenantId }
            else                               { $null }

        $finding =
            if     (-not $pol.Enabled) { 'DISABLED: policy is off' }
            elseif (-not $needed)      { "CHECK: no Microsoft 365 capability maps to '$level'" }
            elseif ($SkipGraph)        { 'CHECK: run without -SkipGraph to check the Microsoft 365 capabilities' }
            elseif ($anonymous -and $level -eq 'CalendarSharingFreeBusyReviewer') {
                # Anonymous publishing at Reviewer level means a user can publish a calendar
                # to the open internet with subjects, attendees and locations. Worth knowing
                # about whatever happens with EWS.
                'CHECK: users can publish calendars anonymously with FULL details (subjects, attendees, locations). Consider lowering this to FreeBusySimple'
            }
            elseif ($anonymous -or $wildcard) {
                if     ($null -eq $caps)                                   { 'CHECK: this role cannot read Microsoft 365 capabilities - see the README' }
                elseif (Test-Capability -Capabilities $caps -Name $needed) { 'READY: capability set on the default policy' }
                elseif ($pol.Default) {
                    # Every tenant ships with a default sharing policy covering '*' and
                    # 'Anonymous'. Untouched, it means nothing - only worth migrating if
                    # users actually share calendars outside the organization.
                    "CHECK: Microsoft's out-of-the-box default sharing policy. Migrate only if your users really share calendars externally, then add $needed"
                }
                else                                                       { "ACTION: missing capability on the default policy - $needed" }
            }
            elseif (-not $tenantId)                          { 'STALE: domain no longer resolves to a Microsoft 365 tenant' }
            elseif (-not $partners.ContainsKey("$tenantId")) { 'ACTION: no Entra partner entry - create one with Microsoft 365 collaboration trust' }
            elseif ($null -eq $caps)                         { 'CHECK: this role cannot read Microsoft 365 capabilities - see the README' }
            elseif (Test-Capability -Capabilities $caps -Name $needed) { 'READY: capability already in place' }
            else                                             { "ACTION: missing capability - $needed" }

        [pscustomobject]@{
            Policy   = "$($pol.Name)"
            Enabled  = [bool] $pol.Enabled
            Default  = [bool] $pol.Default
            Domain   = $domain
            Level    = $level
            TenantId = $tenantId
            Needed   = $needed
            Finding  = $finding
        }
    }
})

# --- report ----------------------------------------------------------------

$all    = @($sharing) + @($policyRows)
$action = @($all | Where-Object { $_.Finding -like 'ACTION*' })
$check  = @($all | Where-Object { $_.Finding -like 'CHECK*' })

Write-Host ''
Write-Host 'Summary' -ForegroundColor White
Write-Host ('  Organization relationships : {0}' -f $relationships.Count)
Write-Host ('  Availability address spaces: {0}' -f $addressSpaces.Count)
Write-Host ('  Sharing policies           : {0}' -f $sharingPolicies.Count)
Write-Host ('  Intra-organization conns.  : {0}' -f $connectors.Count)
if (-not $SkipGraph) {
    Write-Host ('  Entra partner entries      : {0}' -f $partners.Count)
}

function Write-Finding {
    <# One block per item. Format-Table shreds long findings in a narrow window. #>
    param([string] $Title, [string[]] $Detail, [string] $Finding)

    $color = switch -regex ($Finding) {
        '^ACTION'   { 'Yellow' }
        '^STALE'    { 'Yellow' }
        '^CHECK'    { 'Cyan' }
        '^READY'    { 'Green' }
        '^OK'       { 'Green' }
        default     { 'Gray' }
    }
    Write-Host ''
    Write-Host "  $Title" -ForegroundColor White
    foreach ($d in $Detail) { if ($d) { Write-Host "    $d" -ForegroundColor Gray } }
    Write-Host "    $Finding" -ForegroundColor $color
}

if ($sharing.Count) {
    Write-Host ''
    Write-Host 'Free/Busy and MailTips' -ForegroundColor White
    foreach ($row in $sharing) {
        $detail = @("shares : $($row.Shares)")
        if (-not $SkipGraph -and $row.TenantId -and $row.Finding -notlike 'HYBRID*') {
            $detail += "entra  : partner entry $(if ($row.PartnerEntry) { 'yes' } else { 'no' }), Microsoft 365 trust $(if ($row.M365Trust) { 'yes' } else { 'no' })"
        }
        if ($row.Needed -and $row.Finding -notlike 'HYBRID*') { $detail += "needs  : $($row.Needed)" }
        Write-Finding -Title "$($row.Name)  [$($row.Domain)]" -Detail $detail -Finding $row.Finding
    }
}

if ($policyRows.Count) {
    Write-Host ''
    Write-Host 'Calendar sharing (sharing policies)' -ForegroundColor White
    foreach ($row in $policyRows) {
        $detail = @("shares : $($row.Domain) at $($row.Level)")
        if ($row.Needed) { $detail += "needs  : $($row.Needed)" }
        Write-Finding -Title "$($row.Policy)$(if (-not $row.Enabled) { ' (disabled)' })" -Detail $detail -Finding $row.Finding
    }
}

Write-Host ''
if ($action.Count) {
    Write-Host ("{0} configuration(s) need work before EWS is disabled." -f $action.Count) -ForegroundColor Yellow
}
else {
    Write-Host 'Nothing needs action.' -ForegroundColor Green
}
if ($check.Count) {
    Write-Host ("{0} item(s) need a manual look - see the CHECK findings." -f $check.Count) -ForegroundColor Yellow
}

if ($OutputPath) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $stamp = '{0:yyyyMMdd-HHmm}' -f (Get-Date)
    $f1 = Join-Path $OutputPath "cross-tenant-sharing-$stamp.csv"
    $f2 = Join-Path $OutputPath "cross-tenant-sharing-policies-$stamp.csv"
    $sharing    | Export-Csv -Path $f1 -NoTypeInformation -Encoding UTF8
    $policyRows | Export-Csv -Path $f2 -NoTypeInformation -Encoding UTF8
    Write-Host "Written: $f1" -ForegroundColor Cyan
    Write-Host "Written: $f2" -ForegroundColor Cyan
}

if ($PassThru) { $all }
