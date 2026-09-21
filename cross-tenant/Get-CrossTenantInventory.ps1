#Requires -Version 7.0
<#
.SYNOPSIS
    Inventories cross-tenant Free/Busy and calendar sharing before the move to
    Entra Cross-Tenant Access Policy.

.DESCRIPTION
    Microsoft is moving cross-tenant Free/Busy, MailTips and calendar sharing out of
    Exchange organization relationships and into Entra ID Cross-Tenant Access Policy.

    Most tenants have collected organization relationships for years - acquisitions,
    divestments, partner projects - and few can account for all of them. This script
    tells you what you actually have before the migration asks the question for you.

    READ-ONLY. It connects, reads and reports. Nothing is created, changed or removed.

    For every organization relationship it reports:
      - the partner domains and what is shared (Free/Busy level, MailTips)
      - whether each domain still resolves to a live Microsoft 365 tenant
      - whether that tenant already has an Entra Cross-Tenant Access Policy partner entry

    The last two are the useful part.

    A domain that no longer resolves is usually a company you don't work with
    anymore - a standing trust nobody removed.

    A relationship sharing Free/Busy with no matching CTAP partner is one that will
    need attention when the move reaches your tenant.

.PARAMETER OutputPath
    Optional folder. Writes the findings to a timestamped CSV there.

.PARAMETER SkipGraph
    Skip the Entra Cross-Tenant Access Policy check and report Exchange only.
    Useful if you can't consent to Policy.Read.All.

.EXAMPLE
    ./Get-CrossTenantInventory.ps1

.EXAMPLE
    ./Get-CrossTenantInventory.ps1 -OutputPath ./reports

.EXAMPLE
    ./Get-CrossTenantInventory.ps1 | Where-Object Finding -ne 'OK'

.NOTES
    Modules : ExchangeOnlineManagement 3.x, Microsoft.Graph.Identity.SignIns
    Exchange: View-Only Organization Management is enough
    Graph   : Policy.Read.All (read-only)

    Tenant resolution uses the public OpenID configuration endpoint, which needs no
    authentication and reveals only a tenant ID - the same thing any sign-in page does.
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $SkipGraph
)

$ErrorActionPreference = 'Stop'

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

function Get-Finding {
    param($Row, [bool] $GraphChecked)

    if (-not $Row.DomainResolves) {
        return 'STALE: domain no longer resolves to a Microsoft 365 tenant'
    }
    if (-not $Row.RelationshipEnabled) {
        return 'DISABLED: relationship is off - candidate for removal'
    }
    if ($GraphChecked -and $Row.FreeBusyEnabled -and -not $Row.HasCtapPartner) {
        return 'ACTION: shares Free/Busy but has no Cross-Tenant Access Policy partner'
    }
    return 'OK'
}

# --- connect ---------------------------------------------------------------

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
    Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
    Connect-ExchangeOnline -ShowBanner:$false
}

$ctapPartners = @{}
if (-not $SkipGraph) {
    Write-Host 'Connecting to Microsoft Graph (Policy.Read.All)...' -ForegroundColor Cyan
    Connect-MgGraph -Scopes 'Policy.Read.All' -NoWelcome
    foreach ($p in Get-MgPolicyCrossTenantAccessPolicyPartner -All) {
        $ctapPartners[$p.TenantId] = $p
    }
}

# --- collect ---------------------------------------------------------------

$relationships = @(Get-OrganizationRelationship)
Write-Host ("Found {0} organization relationship(s)." -f $relationships.Count) -ForegroundColor Cyan

$results = foreach ($rel in $relationships) {
    foreach ($domain in $rel.DomainNames) {
        $tenantId = Resolve-TenantId -Domain $domain

        $row = [pscustomobject]@{
            Relationship        = $rel.Name
            RelationshipEnabled = $rel.Enabled
            Domain              = "$domain"
            TenantId            = $tenantId
            DomainResolves      = [bool] $tenantId
            FreeBusyEnabled     = $rel.FreeBusyAccessEnabled
            FreeBusyLevel       = $rel.FreeBusyAccessLevel
            MailTipsEnabled     = $rel.MailTipsAccessEnabled
            HasCtapPartner      = if ($SkipGraph) { $null }
                                  elseif ($tenantId) { $ctapPartners.ContainsKey($tenantId) }
                                  else { $false }
            Finding             = $null
        }
        $row.Finding = Get-Finding -Row $row -GraphChecked (-not $SkipGraph)
        $row
    }
}

$addressSpaces = @(Get-AvailabilityAddressSpace)
$connectors    = @(Get-IntraOrganizationConnector)

# --- report ----------------------------------------------------------------

Write-Host ''
Write-Host 'Summary' -ForegroundColor White
Write-Host ('  Organization relationships : {0}' -f $relationships.Count)
Write-Host ('  Partner domains            : {0}' -f @($results).Count)
Write-Host ('  Availability address spaces: {0}' -f $addressSpaces.Count)
Write-Host ('  Intra-organization conns.  : {0}' -f $connectors.Count)
if (-not $SkipGraph) {
    Write-Host ('  CTAP partner entries       : {0}' -f $ctapPartners.Count)
}

$flagged = @($results | Where-Object Finding -ne 'OK')
Write-Host ''
if ($flagged.Count) {
    Write-Host ("{0} finding(s) need a look:" -f $flagged.Count) -ForegroundColor Yellow
    $flagged | Format-Table Relationship, Domain, Finding -AutoSize | Out-Host
}
else {
    Write-Host 'Nothing flagged.' -ForegroundColor Green
}

if ($OutputPath) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $file = Join-Path $OutputPath ("cross-tenant-inventory-{0:yyyyMMdd-HHmm}.csv" -f (Get-Date))
    $results | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "Written: $file" -ForegroundColor Cyan
}

$results
