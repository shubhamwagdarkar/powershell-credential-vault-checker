<#
.SYNOPSIS
    Azure Key Vault audit functions — secrets, permissions, expiry checks.
.DESCRIPTION
    Provides cmdlets to connect to Azure Key Vault and audit:
    - Secret expiry (expired, critical, warning, no-expiry)
    - RBAC and access policy over-permissions
    - Unused secrets (not accessed within threshold)
    - Vault-level diagnostics (soft-delete, purge protection)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Connect-AzureForAudit {
    <#
    .SYNOPSIS
        Verifies Azure connection; prompts login if needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "[Azure] No active session detected. Launching login..." -ForegroundColor Yellow
        Connect-AzAccount | Out-Null
        $context = Get-AzContext
    }

    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        Write-Host "[Azure] Using subscription: $SubscriptionId" -ForegroundColor Cyan
    }

    Write-Host "[Azure] Connected as: $($context.Account.Id)" -ForegroundColor Green
    return $context
}

function Get-KeyVaultSecretAudit {
    <#
    .SYNOPSIS
        Audits all secrets in a Key Vault for expiry and usage status.
    .OUTPUTS
        Array of PSCustomObject with audit findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $false)]
        [int]$ExpiryWarningDays = 30,

        [Parameter(Mandatory = $false)]
        [int]$CriticalExpiryDays = 7,

        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 90
    )

    Write-Host "[KeyVault] Auditing secrets in vault: $VaultName" -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $now = Get-Date

    try {
        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction Stop
    }
    catch {
        Write-Warning "[KeyVault] Cannot access vault '$VaultName': $_"
        return $findings
    }

    if ($secrets.Count -eq 0) {
        Write-Host "[KeyVault] No secrets found in '$VaultName'." -ForegroundColor Yellow
        return $findings
    }

    foreach ($secret in $secrets) {
        $secretDetail = Get-AzKeyVaultSecret -VaultName $VaultName -Name $secret.Name -ErrorAction SilentlyContinue

        $expiryDate  = $secretDetail.Expires
        $updatedDate = $secretDetail.Updated
        $enabled     = $secretDetail.Enabled
        $tags        = if ($secretDetail.Tags) { ($secretDetail.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' } else { 'None' }

        # --- Expiry classification ---
        $expiryStatus = 'OK'
        $severity     = 'Info'
        $daysToExpiry = $null

        if ($expiryDate) {
            $daysToExpiry = [math]::Round(($expiryDate - $now).TotalDays, 1)
            if ($daysToExpiry -lt 0) {
                $expiryStatus = 'Expired'
                $severity     = 'Critical'
            }
            elseif ($daysToExpiry -le $CriticalExpiryDays) {
                $expiryStatus = 'CriticalExpiry'
                $severity     = 'High'
            }
            elseif ($daysToExpiry -le $ExpiryWarningDays) {
                $expiryStatus = 'ExpiryWarning'
                $severity     = 'Medium'
            }
        }
        else {
            $expiryStatus = 'NoExpiry'
            $severity     = 'Medium'
        }

        # --- Inactivity check (last updated as proxy for last used) ---
        $isInactive = $false
        $daysSinceUpdate = $null
        if ($updatedDate) {
            $daysSinceUpdate = [math]::Round(($now - $updatedDate).TotalDays, 1)
            if ($daysSinceUpdate -gt $InactiveThresholdDays -and $expiryStatus -eq 'OK') {
                $isInactive = $true
                if ($severity -eq 'Info') { $severity = 'Low' }
            }
        }

        # --- Disabled secret ---
        if ($enabled -eq $false -and $expiryStatus -eq 'OK') {
            $expiryStatus = 'Disabled'
            $severity     = 'Low'
        }

        $findings.Add([PSCustomObject]@{
            Source           = 'AzureKeyVault'
            VaultName        = $VaultName
            SecretName       = $secret.Name
            Enabled          = $enabled
            ExpiryStatus     = $expiryStatus
            DaysToExpiry     = $daysToExpiry
            ExpiryDate       = if ($expiryDate) { $expiryDate.ToString('yyyy-MM-dd') } else { 'Not Set' }
            DaysSinceUpdate  = $daysSinceUpdate
            LastUpdated      = if ($updatedDate) { $updatedDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
            IsInactive       = $isInactive
            Tags             = $tags
            Severity         = $severity
            FindingType      = $expiryStatus
            Recommendation   = Get-ExpiryRecommendation -Status $expiryStatus -DaysToExpiry $daysToExpiry
        })
    }

    Write-Host "[KeyVault] Found $($findings.Count) secrets in '$VaultName'" -ForegroundColor Green
    return $findings
}

function Get-KeyVaultPermissionAudit {
    <#
    .SYNOPSIS
        Audits access policies on a Key Vault for over-permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName
    )

    Write-Host "[KeyVault] Auditing permissions for vault: $VaultName" -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
    }
    catch {
        Write-Warning "[KeyVault] Cannot retrieve vault details for '$VaultName': $_"
        return $findings
    }

    # RBAC-enabled vaults use role assignments instead of access policies
    if ($vault.EnableRbacAuthorization) {
        Write-Host ('[KeyVault] Vault ' + $VaultName + ' uses RBAC - checking role assignments.') -ForegroundColor Cyan

        $roles = Get-AzRoleAssignment -Scope $vault.ResourceId -ErrorAction SilentlyContinue
        foreach ($role in $roles) {
            $isOverPrivileged = $role.RoleDefinitionName -in @('Owner', 'Contributor', 'Key Vault Administrator')

            if ($isOverPrivileged) {
                $findings.Add([PSCustomObject]@{
                    Source         = 'AzureKeyVault'
                    VaultName      = $VaultName
                    FindingType    = 'WeakPermission'
                    Severity       = 'High'
                    Principal      = $role.DisplayName
                    PrincipalType  = $role.ObjectType
                    Role           = $role.RoleDefinitionName
                    Scope          = $role.Scope
                    Recommendation = "Replace '$($role.RoleDefinitionName)' with 'Key Vault Secrets User' or 'Key Vault Reader' following least-privilege."
                })
            }
        }
    }
    else {
        # Legacy access policy model
        foreach ($policy in $vault.AccessPolicies) {
            $secretPerms  = $policy.PermissionsToSecrets
            $dangerPerms  = $secretPerms | Where-Object { $_ -in @('All', 'Purge', 'Delete') }

            if ($dangerPerms) {
                $findings.Add([PSCustomObject]@{
                    Source         = 'AzureKeyVault'
                    VaultName      = $VaultName
                    FindingType    = 'WeakPermission'
                    Severity       = 'High'
                    Principal      = $policy.DisplayName
                    PrincipalType  = 'AccessPolicy'
                    Role           = ($secretPerms -join ', ')
                    Scope          = 'AccessPolicy'
                    Recommendation = "Remove overly-broad permissions ($($dangerPerms -join ', ')). Grant only 'Get' and 'List' unless deletion is explicitly required."
                })
            }
        }
    }

    # Soft-delete / purge protection checks
    if (-not $vault.EnableSoftDelete) {
        $findings.Add([PSCustomObject]@{
            Source         = 'AzureKeyVault'
            VaultName      = $VaultName
            FindingType    = 'WeakPermission'
            Severity       = 'Medium'
            Principal      = 'N/A'
            PrincipalType  = 'VaultConfiguration'
            Role           = 'N/A'
            Scope          = 'VaultLevel'
            Recommendation = "Enable soft-delete on vault '$VaultName' to protect against accidental/malicious deletion."
        })
    }

    if (-not $vault.EnablePurgeProtection) {
        $findings.Add([PSCustomObject]@{
            Source         = 'AzureKeyVault'
            VaultName      = $VaultName
            FindingType    = 'WeakPermission'
            Severity       = 'Low'
            Principal      = 'N/A'
            PrincipalType  = 'VaultConfiguration'
            Role           = 'N/A'
            Scope          = 'VaultLevel'
            Recommendation = "Enable purge protection on vault '$VaultName' to prevent permanent deletion during soft-delete retention period."
        })
    }

    Write-Host "[KeyVault] Found $($findings.Count) permission findings in '$VaultName'" -ForegroundColor Green
    return $findings
}

function Get-ExpiryRecommendation {
    param(
        [string]$Status,
        $DaysToExpiry
    )

    if ($Status -eq 'Expired') {
        return 'SECRET EXPIRED. Rotate immediately and update all consumers.'
    }
    elseif ($Status -eq 'CriticalExpiry') {
        return ('Expires in ' + $DaysToExpiry + ' days. Rotate NOW before service disruption.')
    }
    elseif ($Status -eq 'ExpiryWarning') {
        return ('Expires in ' + $DaysToExpiry + ' days. Plan rotation and update consumers.')
    }
    elseif ($Status -eq 'NoExpiry') {
        return 'No expiry set. Add an expiry date per your rotation policy, e.g. 365 days.'
    }
    elseif ($Status -eq 'Disabled') {
        return 'Secret is disabled. Remove if unused or re-enable with updated expiry.'
    }
    else {
        return 'No action required. Monitor per your rotation schedule.'
    }
}

Export-ModuleMember -Function Connect-AzureForAudit, Get-KeyVaultSecretAudit, Get-KeyVaultPermissionAudit, Get-ExpiryRecommendation
