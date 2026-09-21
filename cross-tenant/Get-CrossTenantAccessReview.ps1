#Requires -Version 7.0
<#
.SYNOPSIS
    Reviews Entra Cross-Tenant Access Policy: who you let in, and whose security
    decisions you've agreed to trust.

.DESCRIPTION
    Cross-Tenant Access Policy decides how other Entra tenants interact with yours:
    guest access, Teams shared channels, cross-tenant sync, and whether you accept
    MFA and device compliance claims made by someone else's tenant.

    Most of these settings are set once and never looked at again. Partner entries
    get added for a project and outlive it. Trust settings get switched on to make
    a pilot work and stay on.

    READ-ONLY. It connects, reads and reports. Nothing is created, changed or removed.

    It reports on:
      - the default policy, which applies to every tenant you have no partner entry for
      - every partner entry, with the settings that actually apply to it
      - whether each partner tenant still exists
      - cross-tenant sync and automatic invitation redemption per partner

    Findings are graded:
      HIGH   - lowers your security posture for every external tenant, or dead config
      MEDIUM - an open door that should be a deliberate, documented decision
      INFO   - worth knowing, usually fine, confirm it's still intended

.PARAMETER OutputPath
    Optional folder. Writes two timestamped CSVs there: findings and partner overview.

.EXAMPLE
    ./Get-CrossTenantAccessReview.ps1

.EXAMPLE
    ./Get-CrossTenantAccessReview.ps1 -OutputPath ./reports

.EXAMPLE
    ./Get-CrossTenantAccessReview.ps1 | Where-Object Severity -eq 'HIGH'

.NOTES
    Modules : Microsoft.Graph.Authentication
    Graph   : Policy.Read.All                       (read-only)
              CrossTenantInformation.ReadBasic.All  (read-only, partner names only)

    Uses Graph only - no Exchange module, so no MSAL conflict.
#>
[CmdletBinding()]
param(
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param($Severity, $Scope, $TenantId, $TenantName, $Setting, $Finding)
    $findings.Add([pscustomobject]@{
        Severity   = $Severity
        Scope      = $Scope
        TenantId   = $TenantId
        TenantName = $TenantName
        Setting    = $Setting
        Finding    = $Finding
    })
}

function Get-GraphAll {
    <# Follows @odata.nextLink until the collection is complete. #>
    param([Parameter(Mandatory)] [string] $Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri
        foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
        $Uri = $page.'@odata.nextLink'
    }
    $items
}

function Test-TenantExists {
    <#
    Uses the public OpenID configuration endpoint. Returns $true if the tenant
    exists, $false if Entra says it doesn't, $null if the check itself failed.
    #>
    param([Parameter(Mandatory)] [string] $TenantId)
    $uri = "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid-configuration"
    try {
        Invoke-RestMethod -Uri $uri -TimeoutSec 10 -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -in 400, 404) { return $false }
        Write-Verbose "Could not check tenant $TenantId : $($_.Exception.Message)"
        return $null
    }
}

function Get-TenantInfo {
    <# Display name and default domain of a tenant ID. Blank if the lookup isn't allowed. #>
    param([Parameter(Mandatory)] [string] $TenantId)
    try {
        Invoke-MgGraphRequest -Method GET -Uri "v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')"
    }
    catch {
        Write-Verbose "No tenant information for $TenantId"
        $null
    }
}

function Test-OpenToAll {
    <# True when a B2B setting allows all users AND all applications. #>
    param($Setting)
    if (-not $Setting) { return $false }
    $u = $Setting.usersAndGroups
    $a = $Setting.applications
    return ($u.accessType -eq 'allowed' -and @($u.targets.target) -contains 'AllUsers' -and
            $a.accessType -eq 'allowed' -and @($a.targets.target) -contains 'AllApplications')
}

function Format-Access {
    <# 'allowed: all users / all apps', 'blocked: 3 users / all apps', or 'inherits default'. #>
    param($Setting)
    if (-not $Setting) { return 'inherits default' }
    $u = $Setting.usersAndGroups
    $a = $Setting.applications
    $who  = if (@($u.targets.target) -contains 'AllUsers')        { 'all users' } else { '{0} user/group target(s)' -f @($u.targets).Count }
    $what = if (@($a.targets.target) -contains 'AllApplications') { 'all apps' }  else { '{0} app target(s)' -f @($a.targets).Count }
    '{0}: {1} / {2}' -f $u.accessType, $who, $what
}

# --- connect ---------------------------------------------------------------

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes 'Policy.Read.All', 'CrossTenantInformation.ReadBasic.All' -NoWelcome
}
catch {
    if ($_.Exception.Message -match 'Method not found') {
        Write-Host ''
        Write-Host 'Graph could not load its authentication library.' -ForegroundColor Red
        Write-Host 'Another module (usually ExchangeOnlineManagement) already loaded an older MSAL in this session.' -ForegroundColor Yellow
        Write-Host 'Fix: open a NEW PowerShell 7 window and run the script there.' -ForegroundColor Yellow
        return
    }
    throw
}

# --- default policy --------------------------------------------------------

$default = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/crossTenantAccessPolicy/default'
$dTrust  = $default.inboundTrust

if ($dTrust.isMfaAccepted) {
    Add-Finding HIGH Default $null $null 'inboundTrust.isMfaAccepted' `
        'MFA performed in ANY external Entra tenant satisfies your Conditional Access MFA requirement. Trust MFA per partner, not by default.'
}
if ($dTrust.isCompliantDeviceAccepted) {
    Add-Finding HIGH Default $null $null 'inboundTrust.isCompliantDeviceAccepted' `
        "A device marked compliant by ANY external tenant's Intune counts as compliant for yours. You don't control their compliance bar."
}
if ($dTrust.isHybridAzureADJoinedDeviceAccepted) {
    Add-Finding HIGH Default $null $null 'inboundTrust.isHybridAzureADJoinedDeviceAccepted' `
        'Hybrid-joined devices from ANY external tenant satisfy your device-based Conditional Access.'
}
if (Test-OpenToAll $default.b2bCollaborationInbound) {
    Add-Finding MEDIUM Default $null $null 'b2bCollaborationInbound' `
        'Users from any Entra tenant can be invited as guests with access to all apps. This is the Microsoft default - fine for many orgs, but it should be a decision, not an accident.'
}
if ($default.b2bDirectConnectInbound.usersAndGroups.accessType -eq 'allowed') {
    Add-Finding MEDIUM Default $null $null 'b2bDirectConnectInbound' `
        "Users from any tenant can reach your Teams shared channels without existing in your directory. Microsoft's default is blocked - someone changed this."
}

# --- partners --------------------------------------------------------------

$partners = @(Get-GraphAll -Uri 'v1.0/policies/crossTenantAccessPolicy/partners')
Write-Host ("Found {0} partner entr{1}." -f $partners.Count, $(if ($partners.Count -eq 1) { 'y' } else { 'ies' })) -ForegroundColor Cyan

$overview = foreach ($p in $partners) {
    $id     = $p.tenantId
    $info   = Get-TenantInfo -TenantId $id
    $name   = if ($info.displayName) { "$($info.displayName)" } else { $id }
    $exists = Test-TenantExists -TenantId $id

    $sync = try {
        Invoke-MgGraphRequest -Method GET -Uri "v1.0/policies/crossTenantAccessPolicy/partners/$id/identitySynchronization"
    } catch { $null }   # 404 = no sync configured for this partner

    $syncIn     = [bool] $sync.userSyncInbound.isSyncAllowed
    $autoRedeem = [bool] $p.automaticUserConsentSettings.inboundAllowed
    $pTrust     = $p.inboundTrust
    $effTrust   = if ($pTrust) { $pTrust } else { $dTrust }

    if ($exists -eq $false) {
        Add-Finding HIGH Partner $id $name 'tenant' `
            'Tenant no longer exists. The partner entry is dead configuration - remove it.'
    }
    if ($syncIn) {
        Add-Finding MEDIUM Partner $id $name 'identitySynchronization.userSyncInbound' `
            'This tenant can create and update users in your directory. Confirm there is still a live multi-tenant or merger reason.'
    }
    if ($autoRedeem) {
        Add-Finding MEDIUM Partner $id $name 'automaticUserConsentSettings.inboundAllowed' `
            'Invitations from this tenant are redeemed automatically - users never see a consent prompt.'
    }
    if ($pTrust.isCompliantDeviceAccepted -or $pTrust.isHybridAzureADJoinedDeviceAccepted) {
        Add-Finding MEDIUM Partner $id $name 'inboundTrust (device)' `
            "Devices trusted by this tenant's Intune or AD count as trusted for your Conditional Access. Their bar may be lower than yours."
    }
    if ($pTrust.isMfaAccepted) {
        Add-Finding INFO Partner $id $name 'inboundTrust.isMfaAccepted' `
            'MFA from this tenant is trusted. Reasonable if you know their MFA policy - confirm it is still enforced.'
    }
    if (Test-OpenToAll $p.b2bDirectConnectInbound) {
        Add-Finding MEDIUM Partner $id $name 'b2bDirectConnectInbound' `
            'All users of this tenant can reach all your Teams shared channels.'
    }
    if ($p.isServiceProvider) {
        Add-Finding INFO Partner $id $name 'isServiceProvider' `
            'Marked as a service provider (e.g. GDAP / CSP). Confirm the relationship is current.'
    }

    $overrides = @('b2bCollaborationInbound', 'b2bCollaborationOutbound', 'b2bDirectConnectInbound',
                   'b2bDirectConnectOutbound', 'inboundTrust', 'tenantRestrictions') |
                 Where-Object { $null -ne $p.$_ }
    if (-not $overrides -and -not $syncIn -and -not $autoRedeem -and $exists -ne $false) {
        Add-Finding INFO Partner $id $name 'entry' `
            'Overrides nothing - every setting inherits the default. Either someone meant to configure it and did not, or it can go.'
    }

    [pscustomobject]@{
        TenantId              = $id
        TenantName            = $name
        DefaultDomain         = "$($info.defaultDomainName)"
        TenantExists          = $exists
        GuestAccessInbound    = Format-Access $p.b2bCollaborationInbound
        DirectConnectInbound  = Format-Access $p.b2bDirectConnectInbound
        MfaTrusted            = [bool] $effTrust.isMfaAccepted
        DeviceTrusted         = [bool] ($effTrust.isCompliantDeviceAccepted -or $effTrust.isHybridAzureADJoinedDeviceAccepted)
        SyncInbound           = $syncIn
        AutoRedeemInbound     = $autoRedeem
        ServiceProvider       = [bool] $p.isServiceProvider
        MultiTenantOrg        = [bool] $p.isInMultiTenantOrganization
    }
}

# --- report ----------------------------------------------------------------

Write-Host ''
Write-Host 'Default policy (applies to every tenant without a partner entry)' -ForegroundColor White
Write-Host ('  Guest access inbound    : {0}' -f (Format-Access $default.b2bCollaborationInbound))
Write-Host ('  Direct connect inbound  : {0}' -f (Format-Access $default.b2bDirectConnectInbound))
Write-Host ('  Trust external MFA      : {0}' -f [bool] $dTrust.isMfaAccepted)
Write-Host ('  Trust external devices  : {0}' -f [bool] ($dTrust.isCompliantDeviceAccepted -or $dTrust.isHybridAzureADJoinedDeviceAccepted))

if ($partners.Count) {
    Write-Host ''
    Write-Host 'Partners' -ForegroundColor White
    $overview | Format-Table TenantName, DefaultDomain, TenantExists, MfaTrusted, DeviceTrusted, SyncInbound, AutoRedeemInbound -AutoSize | Out-Host
}

$rank   = @{ HIGH = 0; MEDIUM = 1; INFO = 2 }
$sorted = @($findings | Sort-Object { $rank[$_.Severity] }, Scope, TenantName)

Write-Host ''
if ($sorted.Count) {
    $counts = $sorted | Group-Object Severity | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }
    Write-Host ('Findings: {0}' -f ($counts -join ', ')) -ForegroundColor Yellow
    $sorted | Format-Table Severity, Scope, TenantName, Setting, Finding -AutoSize -Wrap | Out-Host
}
else {
    Write-Host 'Nothing flagged.' -ForegroundColor Green
}

if ($OutputPath) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $stamp = '{0:yyyyMMdd-HHmm}' -f (Get-Date)
    $f1 = Join-Path $OutputPath "cross-tenant-access-findings-$stamp.csv"
    $f2 = Join-Path $OutputPath "cross-tenant-access-partners-$stamp.csv"
    $sorted   | Export-Csv -Path $f1 -NoTypeInformation -Encoding UTF8
    $overview | Export-Csv -Path $f2 -NoTypeInformation -Encoding UTF8
    Write-Host "Written: $f1" -ForegroundColor Cyan
    Write-Host "Written: $f2" -ForegroundColor Cyan
}

$sorted
