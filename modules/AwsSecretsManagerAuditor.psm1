<#
.SYNOPSIS
    AWS Secrets Manager audit functions via AWS Tools for PowerShell.
.DESCRIPTION
    Lists all secrets in a region, checks rotation status, staleness,
    and upcoming deletions. Uses the standard AWS credential chain
    (environment variables, ~/.aws/credentials, IAM instance role).

    Required: AWS.Tools.SecretsManager or AWSPowerShell module.
    Install:  Install-Module -Name AWS.Tools.SecretsManager -Scope CurrentUser

    Credentials (any one of):
        Environment vars:  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
        Profile:           AWS_PROFILE or -ProfileName param
        IAM role:          Automatic when running on EC2/ECS/Lambda
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AwsModuleAvailable {
    $modNames = @('AWS.Tools.SecretsManager', 'AWSPowerShell.NetCore', 'AWSPowerShell')
    foreach ($mod in $modNames) {
        if (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue) {
            Import-Module $mod -ErrorAction SilentlyContinue
            return $mod
        }
    }
    throw 'No AWS PowerShell module found. Install with: Install-Module -Name AWS.Tools.SecretsManager -Scope CurrentUser'
}

function Get-AwsSecretsManagerAudit {
    <#
    .SYNOPSIS
        Audits all secrets in AWS Secrets Manager for a given region.
    .DESCRIPTION
        Checks:
          - Rotation not enabled (no automatic rotation policy)
          - Rotation enabled but last rotated beyond threshold
          - Secret never rotated since creation
          - Secret scheduled for deletion
          - Secret not accessed in InactiveThresholdDays
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Region,

        [Parameter(Mandatory = $false)]
        [string]$ProfileName,

        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 90,

        [Parameter(Mandatory = $false)]
        [int]$RotationWarningDays = 30,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeNamePatterns = @()
    )

    Write-Host '[AWS] Checking for AWS PowerShell module...' -ForegroundColor Cyan
    $moduleName = Assert-AwsModuleAvailable

    # Resolve region: param > env var > default
    if (-not $Region) {
        $Region = $env:AWS_DEFAULT_REGION
        if (-not $Region) { $Region = 'us-east-1' }
    }

    Write-Host ('[AWS] Auditing Secrets Manager in region: ' + $Region) -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $now      = Get-Date

    # Build splatted params for AWS cmdlet
    $awsParams = @{ Region = $Region }
    if ($ProfileName) { $awsParams['ProfileName'] = $ProfileName }

    # List all secrets (paginated)
    $secrets = [System.Collections.Generic.List[PSObject]]::new()
    $nextToken = $null

    do {
        if ($nextToken) { $awsParams['NextToken'] = $nextToken }
        $response  = Get-SECSecretList @awsParams -ErrorAction Stop
        $page      = @($response.SecretList)
        foreach ($s in $page) { $secrets.Add($s) }
        $nextToken = $response.NextToken
    } while ($nextToken)

    Write-Host ('[AWS] Retrieved ' + $secrets.Count + ' secrets.') -ForegroundColor Cyan

    foreach ($secret in $secrets) {
        # Apply name exclusion filter
        $excluded = $false
        foreach ($pattern in $ExcludeNamePatterns) {
            if ($secret.Name -ilike $pattern) { $excluded = $true; break }
        }
        if ($excluded) { continue }

        $rotationEnabled  = $secret.RotationEnabled
        $lastRotated      = $secret.LastRotatedDate
        $lastChanged      = $secret.LastChangedDate
        $lastAccessed     = $secret.LastAccessedDate
        $deletedDate      = $secret.DeletedDate

        $daysSinceRotated = $null
        $daysSinceChanged = $null
        $daysSinceAccess  = $null

        if ($lastRotated)  { $daysSinceRotated = [math]::Round(($now - $lastRotated).TotalDays, 1) }
        if ($lastChanged)  { $daysSinceChanged = [math]::Round(($now - $lastChanged).TotalDays, 1) }
        if ($lastAccessed) { $daysSinceAccess  = [math]::Round(($now - $lastAccessed).TotalDays, 1) }

        $severity       = 'Info'
        $findingType    = 'OK'
        $recommendation = 'No action required.'
        $flags          = [System.Collections.Generic.List[string]]::new()

        # Scheduled for deletion
        if ($deletedDate) {
            $daysUntilDelete = [math]::Round(($deletedDate - $now).TotalDays, 1)
            $severity        = 'High'
            $findingType     = 'ScheduledDeletion'
            $recommendation  = 'Secret is scheduled for deletion in ' + $daysUntilDelete + ' days. Restore via RestoreSecret if still needed.'
            $flags.Add('ScheduledDeletion')
        }

        # Rotation not enabled
        if (-not $rotationEnabled -and $findingType -eq 'OK') {
            $severity       = 'Medium'
            $findingType    = 'NoRotation'
            $recommendation = 'No automatic rotation configured. Enable rotation via a Lambda function or use Secrets Manager managed rotation.'
            $flags.Add('RotationDisabled')
        }

        # Rotation enabled but stale
        if ($rotationEnabled -and $daysSinceRotated -and $daysSinceRotated -gt $InactiveThresholdDays) {
            $severity       = 'Medium'
            $findingType    = 'StaleRotation'
            $recommendation = 'Rotation enabled but last rotated ' + $daysSinceRotated + ' days ago. Check rotation Lambda for errors.'
            $flags.Add('StaleRotation:' + $daysSinceRotated + 'd')
        }

        # Never rotated (rotation enabled but no LastRotatedDate)
        if ($rotationEnabled -and -not $lastRotated -and $findingType -eq 'NoRotation') {
            $severity       = 'Medium'
            $findingType    = 'NeverRotated'
            $recommendation = 'Rotation is configured but this secret has never been automatically rotated. Trigger a manual rotation to verify the Lambda works.'
            $flags.Add('NeverRotated')
        }

        # Inactive (not accessed in threshold)
        if ($daysSinceAccess -and $daysSinceAccess -gt $InactiveThresholdDays -and $severity -eq 'Info') {
            $severity       = 'Low'
            $findingType    = 'Unused'
            $recommendation = 'Secret not accessed in ' + $daysSinceAccess + ' days. Verify it is still needed or delete it.'
            $flags.Add('Inactive:' + $daysSinceAccess + 'd')
        }

        $findings.Add([PSCustomObject]@{
            Source           = 'AwsSecretsManager'
            VaultName        = 'AWS/' + $Region
            SecretName       = $secret.Name
            ARN              = $secret.ARN
            RotationEnabled  = $rotationEnabled
            LastRotated      = if ($lastRotated)  { $lastRotated.ToString('yyyy-MM-dd') }  else { 'Never' }
            LastChanged      = if ($lastChanged)  { $lastChanged.ToString('yyyy-MM-dd') }  else { 'Unknown' }
            LastAccessed     = if ($lastAccessed) { $lastAccessed.ToString('yyyy-MM-dd') } else { 'Unknown' }
            DaysSinceRotated = $daysSinceRotated
            DaysSinceAccess  = $daysSinceAccess
            ScheduledDelete  = if ($deletedDate)  { $deletedDate.ToString('yyyy-MM-dd') }  else { 'No' }
            Flags            = ($flags -join ', ')
            FindingType      = $findingType
            Severity         = $severity
            Recommendation   = $recommendation
        })
    }

    $issueCount = @($findings | Where-Object { $_.FindingType -ne 'OK' }).Count
    Write-Host ('[AWS] Audited ' + $findings.Count + ' secrets. Issues: ' + $issueCount) -ForegroundColor Green
    return $findings
}

Export-ModuleMember -Function Get-AwsSecretsManagerAudit
