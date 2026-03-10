<#
.SYNOPSIS
    CyberArk PAM audit functions via PVWA REST API.
.DESCRIPTION
    Authenticates to CyberArk Privilege Cloud / on-prem PVWA,
    audits managed accounts for stale passwords and auto-management
    failures, and audits safe members for over-privileged access.

    Required environment variables:
        CYBERARK_PVWA_URL   - e.g. https://pvwa.corp.com
        CYBERARK_USER       - API/LDAP username (omit for Windows auth)
        CYBERARK_PASSWORD   - Password (omit for Windows auth)

    Supported auth types: CyberArk | LDAP | Windows | RADIUS
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ignore self-signed certs in lab/dev environments (toggle via config)
function Set-TlsPolicy {
    param([bool]$IgnoreSelfSigned)
    if ($IgnoreSelfSigned) {
        if (-not ([System.Management.Automation.PSTypeName]'TrustAll').Type) {
            Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
    }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

function Connect-CyberArkVault {
    <#
    .SYNOPSIS
        Authenticates to CyberArk PVWA and returns a session token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PvwaUrl,

        [Parameter(Mandatory = $false)]
        [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')]
        [string]$AuthType = 'CyberArk',

        [Parameter(Mandatory = $false)]
        [bool]$IgnoreSelfSigned = $false
    )

    Set-TlsPolicy -IgnoreSelfSigned $IgnoreSelfSigned

    $uri = $PvwaUrl.TrimEnd('/') + '/PasswordVault/api/auth/' + $AuthType + '/Logon'

    if ($AuthType -eq 'Windows') {
        Write-Host '[CyberArk] Authenticating with Windows credentials...' -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri $uri -Method Post `
            -ContentType 'application/json' -UseDefaultCredentials -Body '{}'
    }
    else {
        $user = $env:CYBERARK_USER
        $pass = $env:CYBERARK_PASSWORD

        if (-not $user -or -not $pass) {
            throw 'Set CYBERARK_USER and CYBERARK_PASSWORD environment variables before running.'
        }

        Write-Host ('[CyberArk] Authenticating as ' + $user + ' via ' + $AuthType + '...') -ForegroundColor Cyan
        $body     = '{"username":"' + $user + '","password":"' + $pass + '"}'
        $response = Invoke-RestMethod -Uri $uri -Method Post `
            -ContentType 'application/json' -Body $body
    }

    # PVWA returns the token as a plain quoted string
    $token = $response -replace '"', ''
    Write-Host '[CyberArk] Authenticated successfully.' -ForegroundColor Green
    return $token
}

function Disconnect-CyberArkVault {
    <#
    .SYNOPSIS
        Logs off the CyberArk session (invalidates the token).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PvwaUrl,

        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $uri     = $PvwaUrl.TrimEnd('/') + '/PasswordVault/api/auth/Logoff'
    $headers = @{ Authorization = $Token }
    Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -ErrorAction SilentlyContinue | Out-Null
    Write-Host '[CyberArk] Session closed.' -ForegroundColor Gray
}

function Get-CyberArkAccountAudit {
    <#
    .SYNOPSIS
        Audits all managed accounts in CyberArk for stale passwords
        and auto-management failures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PvwaUrl,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [string[]]$SafeFilter = @()
    )

    Write-Host '[CyberArk] Auditing managed accounts...' -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $headers  = @{ Authorization = $Token }
    $now      = Get-Date
    $baseUri  = $PvwaUrl.TrimEnd('/') + '/PasswordVault/api/Accounts'
    $limit    = 100
    $offset   = 0
    $accounts = [System.Collections.Generic.List[PSObject]]::new()

    # Paginate through all accounts
    do {
        $uri      = $baseUri + '?limit=' + $limit + '&offset=' + $offset
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $page     = @($response.value)
        foreach ($a in $page) { $accounts.Add($a) }
        $offset  += $limit
    } while ($page.Count -eq $limit)

    Write-Host ('[CyberArk] Retrieved ' + $accounts.Count + ' accounts.') -ForegroundColor Cyan

    foreach ($account in $accounts) {
        # Apply safe filter if specified
        if ($SafeFilter.Count -gt 0 -and $account.safeName -notin $SafeFilter) { continue }

        $mgmt             = $account.secretManagement
        $autoEnabled      = if ($null -ne $mgmt) { $mgmt.automaticManagementEnabled } else { $false }
        $status           = if ($null -ne $mgmt) { $mgmt.status } else { 'Unknown' }
        $lastModifiedUnix = if ($null -ne $mgmt) { $mgmt.lastModifiedTime } else { $null }

        $lastModified     = $null
        $daysSinceChange  = $null
        if ($lastModifiedUnix) {
            $lastModified    = [DateTimeOffset]::FromUnixTimeSeconds($lastModifiedUnix).LocalDateTime
            $daysSinceChange = [math]::Round(($now - $lastModified).TotalDays, 1)
        }

        $severity    = 'Info'
        $findingType = 'OK'
        $recommendation = 'No action required.'

        # Auto-management disabled
        if (-not $autoEnabled) {
            $severity       = 'Medium'
            $findingType    = 'NoAutoManagement'
            $recommendation = 'Enable automatic password management on this account to enforce rotation policy.'
        }

        # Management failure status
        if ($status -eq 'Failed' -or $status -eq 'UnrecoverableFailed') {
            $severity       = 'High'
            $findingType    = 'ManagementFailed'
            $recommendation = 'CyberArk reported management failure for this account. Check PVWA logs and verify connectivity to target system.'
        }

        # Stale password (last changed > threshold)
        if ($daysSinceChange -and $daysSinceChange -gt $InactiveThresholdDays) {
            if ($severity -eq 'Info') {
                $severity       = 'Low'
                $findingType    = 'StalePassword'
                $recommendation = 'Password not changed in ' + $daysSinceChange + ' days. Trigger a password change or verify auto-management is working.'
            }
        }

        $findings.Add([PSCustomObject]@{
            Source           = 'CyberArkPAM'
            VaultName        = $account.safeName
            SecretName       = $account.name
            Username         = $account.userName
            Address          = $account.address
            PlatformId       = $account.platformId
            AutoManagement   = $autoEnabled
            ManagementStatus = $status
            LastChanged      = if ($lastModified) { $lastModified.ToString('yyyy-MM-dd') } else { 'Unknown' }
            DaysSinceChange  = $daysSinceChange
            FindingType      = $findingType
            Severity         = $severity
            Recommendation   = $recommendation
        })
    }

    $issueCount = @($findings | Where-Object { $_.FindingType -ne 'OK' }).Count
    Write-Host ('[CyberArk] Audited ' + $findings.Count + ' accounts. Issues: ' + $issueCount) -ForegroundColor Green
    return $findings
}

function Get-CyberArkSafePermissionAudit {
    <#
    .SYNOPSIS
        Audits CyberArk safe members for over-privileged access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PvwaUrl,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $false)]
        [string[]]$SafesToAudit = @()
    )

    Write-Host '[CyberArk] Auditing safe permissions...' -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $headers  = @{ Authorization = $Token }

    # Get safes list
    if ($SafesToAudit.Count -gt 0) {
        $safes = $SafesToAudit | ForEach-Object { [PSCustomObject]@{ safeName = $_ } }
    }
    else {
        $uri   = $PvwaUrl.TrimEnd('/') + '/PasswordVault/api/Safes?limit=100'
        $resp  = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $safes = @($resp.value)
    }

    foreach ($safe in $safes) {
        $safeName = $safe.safeName
        try {
            $uri     = $PvwaUrl.TrimEnd('/') + '/PasswordVault/api/Safes/' + [Uri]::EscapeDataString($safeName) + '/Members'
            $resp    = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $members = @($resp.value)
        }
        catch {
            Write-Warning ('[CyberArk] Cannot read members of safe: ' + $safeName + ' - ' + $_)
            continue
        }

        foreach ($member in $members) {
            $perms = $member.permissions
            if ($null -eq $perms) { continue }

            # Flag: can retrieve passwords (direct read = high risk)
            $canRetrieve  = $perms.retrieveAccounts -eq $true
            # Flag: manage safe or members (admin-level)
            $isAdmin      = ($perms.manageSafe -eq $true) -or ($perms.manageSafeMembers -eq $true)
            # Flag: full control
            $fullControl  = $perms.initiateCPMAccountManagementOperations -eq $true

            $severity    = 'Info'
            $findingType = 'OK'
            $flags       = [System.Collections.Generic.List[string]]::new()
            $recommendation = 'No action required.'

            if ($canRetrieve) {
                $flags.Add('CanRetrievePasswords')
                $severity    = 'Medium'
                $findingType = 'ExcessivePermission'
                $recommendation = 'Member can retrieve account passwords directly. Verify this is intentional. Use JIT access or workflow approval if possible.'
            }
            if ($isAdmin) {
                $flags.Add('SafeAdmin')
                $severity    = 'High'
                $findingType = 'ExcessivePermission'
                $recommendation = 'Member has safe management rights. Restrict to minimum required permissions following least-privilege.'
            }
            if ($fullControl) {
                $flags.Add('CPMControl')
                if ($severity -eq 'Info') { $severity = 'Medium' }
            }

            if ($flags.Count -gt 0) {
                $findings.Add([PSCustomObject]@{
                    Source         = 'CyberArkPAM'
                    VaultName      = $safeName
                    SecretName     = 'Safe: ' + $safeName
                    Username       = $member.memberName
                    MemberType     = $member.memberType
                    Flags          = ($flags -join ', ')
                    FindingType    = $findingType
                    Severity       = $severity
                    Recommendation = $recommendation
                })
            }
        }
    }

    Write-Host ('[CyberArk] Safe permission audit complete. Findings: ' + $findings.Count) -ForegroundColor Green
    return $findings
}

Export-ModuleMember -Function Connect-CyberArkVault, Disconnect-CyberArkVault, Get-CyberArkAccountAudit, Get-CyberArkSafePermissionAudit
