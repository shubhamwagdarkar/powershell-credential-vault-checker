<#
.SYNOPSIS
    BeyondTrust Password Safe audit functions via REST API.
.DESCRIPTION
    Authenticates to BeyondTrust Password Safe using an API Registration key,
    audits managed accounts for stale passwords, disabled auto-management,
    and fallback password failures.

    Required environment variables:
        BEYONDTRUST_URL      - e.g. https://passwordsafe.corp.com
        BEYONDTRUST_API_KEY  - API Registration key from PS Admin > API Registrations
        BEYONDTRUST_RUNAS    - Username to run API calls as (must have API access role)

    BeyondTrust API auth header format:
        Authorization: PS-Auth key=<api_key>; runas=<username>;
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Connect-BeyondTrustVault {
    <#
    .SYNOPSIS
        Signs into BeyondTrust Password Safe and returns a session cookie.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$RunAsUser
    )

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $authHeader = 'PS-Auth key=' + $ApiKey + '; runas=' + $RunAsUser + ';'
    $uri        = $BaseUrl.TrimEnd('/') + '/BeyondTrust/api/public/v3/Auth/SignAppIn'

    Write-Host ('[BeyondTrust] Authenticating as ' + $RunAsUser + '...') -ForegroundColor Cyan

    # Use a session to preserve cookies across requests
    $session  = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = $authHeader } `
        -SessionVariable 'btSession' -ContentType 'application/json' -Body '{}'

    # Sign in to get user token
    $signInUri = $BaseUrl.TrimEnd('/') + '/BeyondTrust/api/public/v3/Auth/SignIn'
    Invoke-RestMethod -Uri $signInUri -Method Post -WebSession $btSession `
        -ContentType 'application/json' -Body '{}' | Out-Null

    Write-Host '[BeyondTrust] Authenticated successfully.' -ForegroundColor Green
    return @{
        Session     = $btSession
        AuthHeader  = $authHeader
        BaseUrl     = $BaseUrl.TrimEnd('/')
    }
}

function Disconnect-BeyondTrustVault {
    <#
    .SYNOPSIS
        Signs out of BeyondTrust Password Safe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Connection
    )

    $uri = $Connection.BaseUrl + '/BeyondTrust/api/public/v3/Auth/SignOut'
    Invoke-RestMethod -Uri $uri -Method Post -WebSession $Connection.Session `
        -Headers @{ Authorization = $Connection.AuthHeader } -ErrorAction SilentlyContinue | Out-Null
    Write-Host '[BeyondTrust] Session closed.' -ForegroundColor Gray
}

function Get-BeyondTrustAccountAudit {
    <#
    .SYNOPSIS
        Audits BeyondTrust managed accounts for password staleness,
        auto-management gaps, and fallback password failures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Connection,

        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [string[]]$SystemFilter = @()
    )

    Write-Host '[BeyondTrust] Auditing managed accounts...' -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $now      = Get-Date

    # GET managed accounts (paginated via offset)
    $accounts = [System.Collections.Generic.List[PSObject]]::new()
    $offset   = 0
    $limit    = 100

    do {
        $uri      = $Connection.BaseUrl + '/BeyondTrust/api/public/v3/ManagedAccounts?offset=' + $offset + '&limit=' + $limit
        $page     = @(Invoke-RestMethod -Uri $uri -Method Get -WebSession $Connection.Session `
            -Headers @{ Authorization = $Connection.AuthHeader })

        foreach ($a in $page) { $accounts.Add($a) }
        $offset += $limit
    } while ($page.Count -eq $limit)

    Write-Host ('[BeyondTrust] Retrieved ' + $accounts.Count + ' managed accounts.') -ForegroundColor Cyan

    foreach ($account in $accounts) {
        # Apply system name filter
        if ($SystemFilter.Count -gt 0 -and $account.SystemName -notin $SystemFilter) { continue }

        $autoManaged      = $account.AutoManagementFlag -eq $true
        $fallbackActive   = $account.PasswordFallbackFlag -eq $true
        $lastChangeStr    = $account.LastChangeDate
        $nextChangeStr    = $account.NextChangeDate

        $lastChanged      = $null
        $daysSinceChange  = $null
        if ($lastChangeStr) {
            try {
                $lastChanged     = [datetime]::Parse($lastChangeStr)
                $daysSinceChange = [math]::Round(($now - $lastChanged).TotalDays, 1)
            }
            catch { }
        }

        $severity       = 'Info'
        $findingType    = 'OK'
        $recommendation = 'No action required.'
        $flags          = [System.Collections.Generic.List[string]]::new()

        # Fallback password active — means CyberArk/BT failed to change password
        # and fell back to a known backup. This is a HIGH risk state.
        if ($fallbackActive) {
            $severity       = 'High'
            $findingType    = 'FallbackPasswordActive'
            $recommendation = 'Password fallback is active. The last automated password change failed. Investigate the managed system connectivity and reset manually.'
            $flags.Add('FallbackActive')
        }

        # Auto-management disabled
        if (-not $autoManaged) {
            if ($severity -eq 'Info') {
                $severity       = 'Medium'
                $findingType    = 'NoAutoManagement'
                $recommendation = 'Auto-management is disabled. Passwords are not automatically rotated. Enable auto-management or document why manual management is approved.'
            }
            $flags.Add('AutoManagementDisabled')
        }

        # Stale password
        if ($daysSinceChange -and $daysSinceChange -gt $InactiveThresholdDays) {
            if ($severity -eq 'Info') {
                $severity       = 'Low'
                $findingType    = 'StalePassword'
                $recommendation = 'Password last changed ' + $daysSinceChange + ' days ago. Trigger a change or verify auto-management schedule.'
            }
            $flags.Add('Stale:' + $daysSinceChange + 'd')
        }

        $findings.Add([PSCustomObject]@{
            Source           = 'BeyondTrustPasswordSafe'
            VaultName        = $account.SystemName
            SecretName       = $account.AccountName
            Username         = $account.AccountName
            SystemName       = $account.SystemName
            AutoManagement   = $autoManaged
            FallbackActive   = $fallbackActive
            LastChanged      = if ($lastChanged) { $lastChanged.ToString('yyyy-MM-dd') } else { 'Unknown' }
            NextChangeDate   = if ($nextChangeStr) { $nextChangeStr } else { 'Unknown' }
            DaysSinceChange  = $daysSinceChange
            Flags            = ($flags -join ', ')
            FindingType      = $findingType
            Severity         = $severity
            Recommendation   = $recommendation
        })
    }

    $issueCount = @($findings | Where-Object { $_.FindingType -ne 'OK' }).Count
    Write-Host ('[BeyondTrust] Audited ' + $findings.Count + ' accounts. Issues: ' + $issueCount) -ForegroundColor Green
    return $findings
}

Export-ModuleMember -Function Connect-BeyondTrustVault, Disconnect-BeyondTrustVault, Get-BeyondTrustAccountAudit
