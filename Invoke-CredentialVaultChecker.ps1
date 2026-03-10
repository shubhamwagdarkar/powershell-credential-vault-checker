<#
.SYNOPSIS
    Credential Vault Checker — multi-source credential audit tool.

.DESCRIPTION
    Audits credentials across six sources:
      - Azure Key Vault            (secrets expiry, permissions, vault config)
      - Windows Credential Manager (stale, suspicious, empty-username entries)
      - CyberArk PAM               (account management status, safe permissions)
      - AWS Secrets Manager        (rotation policy, staleness, scheduled deletion)
      - BeyondTrust Password Safe  (auto-management, fallback failures, staleness)

    Outputs severity-ranked findings to console and exports CSV / JSON reports.
    Exit codes: 0=clean, 1=High findings, 2=Critical findings (CI/CD compatible).

.PARAMETER VaultNames
    Azure Key Vault names to audit. Overrides settings.json.

.PARAMETER SubscriptionId
    Azure Subscription ID. Overrides settings.json.

.PARAMETER SkipAzure
    Skip Azure Key Vault audit.

.PARAMETER SkipWindows
    Skip Windows Credential Manager audit.

.PARAMETER SkipCyberArk
    Skip CyberArk PAM audit.

.PARAMETER SkipAws
    Skip AWS Secrets Manager audit.

.PARAMETER SkipBeyondTrust
    Skip BeyondTrust Password Safe audit.

.PARAMETER AwsRegion
    AWS region override. Defaults to AWS_DEFAULT_REGION env var or us-east-1.

.PARAMETER AwsProfile
    AWS credential profile name.

.PARAMETER ExpiryWarningDays
    Azure Key Vault: days before expiry to flag as warning (default: 30).

.PARAMETER CriticalExpiryDays
    Azure Key Vault: days before expiry to flag as critical (default: 7).

.PARAMETER InactiveThresholdDays
    Days since last update/rotation to flag as inactive (default: 90).

.PARAMETER OutputDirectory
    Directory to write reports into (default: 'reports').

.PARAMETER NoExport
    Skip exporting report files; display console summary only.

.PARAMETER OpenReport
    Open the CSV report after generation.

.EXAMPLE
    # Full audit of all configured sources
    .\Invoke-CredentialVaultChecker.ps1

.EXAMPLE
    # Azure + CyberArk only
    .\Invoke-CredentialVaultChecker.ps1 -SkipWindows -SkipAws -SkipBeyondTrust

.EXAMPLE
    # AWS only, specific region
    .\Invoke-CredentialVaultChecker.ps1 -SkipAzure -SkipWindows -SkipCyberArk -SkipBeyondTrust -AwsRegion eu-west-1

.EXAMPLE
    # Windows Credential Manager only, no file export
    .\Invoke-CredentialVaultChecker.ps1 -SkipAzure -SkipCyberArk -SkipAws -SkipBeyondTrust -NoExport
#>

[CmdletBinding()]
param(
    # Azure
    [string[]]$VaultNames,
    [string]$SubscriptionId,
    [switch]$SkipAzure,

    # Windows
    [switch]$SkipWindows,

    # CyberArk
    [switch]$SkipCyberArk,

    # AWS
    [switch]$SkipAws,
    [string]$AwsRegion,
    [string]$AwsProfile,

    # BeyondTrust
    [switch]$SkipBeyondTrust,

    # Shared thresholds
    [int]$ExpiryWarningDays,
    [int]$CriticalExpiryDays,
    [int]$InactiveThresholdDays,

    # Output
    [string]$OutputDirectory,
    [switch]$NoExport,
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Paths ────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = Join-Path $ScriptDir 'modules'

# ─── Config ───────────────────────────────────────────────────────────────────
$configPath = Join-Path $ScriptDir 'config\settings.json'
if (-not (Test-Path $configPath)) { Write-Error "Config not found: $configPath"; exit 1 }
$config = Get-Content $configPath -Raw | ConvertFrom-Json

# ─── Resolve effective values (param > config) ────────────────────────────────
$effVaults      = if ($VaultNames)            { $VaultNames }            else { $config.AzureKeyVault.VaultNames }
$effSubId       = if ($SubscriptionId)        { $SubscriptionId }        else { $config.AzureKeyVault.SubscriptionId }
$effExpWarn     = if ($ExpiryWarningDays)     { $ExpiryWarningDays }     else { $config.AzureKeyVault.ExpiryWarningDays }
$effCritical    = if ($CriticalExpiryDays)    { $CriticalExpiryDays }    else { $config.AzureKeyVault.CriticalExpiryDays }
$effInactive    = if ($InactiveThresholdDays) { $InactiveThresholdDays } else { $config.AzureKeyVault.InactiveThresholdDays }
$effOutputDir   = if ($OutputDirectory)       { $OutputDirectory }       else { Join-Path $ScriptDir $config.Report.OutputDirectory }
$effAwsRegion   = if ($AwsRegion)             { $AwsRegion }             else { $config.AwsSecretsManager.Region }
$effAwsProfile  = if ($AwsProfile)            { $AwsProfile }            else { $config.AwsSecretsManager.ProfileName }

# ─── Load modules ─────────────────────────────────────────────────────────────
Import-Module (Join-Path $ModulesPath 'AzureKeyVaultAuditor.psm1')      -Force
Import-Module (Join-Path $ModulesPath 'WindowsCredentialAuditor.psm1')  -Force
Import-Module (Join-Path $ModulesPath 'CyberArkAuditor.psm1')           -Force
Import-Module (Join-Path $ModulesPath 'AwsSecretsManagerAuditor.psm1')  -Force
Import-Module (Join-Path $ModulesPath 'BeyondTrustAuditor.psm1')        -Force
Import-Module (Join-Path $ModulesPath 'ReportGenerator.psm1')           -Force

# ─── Master findings list ─────────────────────────────────────────────────────
$allFindings = [System.Collections.Generic.List[PSObject]]::new()

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE 1 — Azure Key Vault
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipAzure) {
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault -ErrorAction SilentlyContinue)) {
        Write-Warning '[Azure] Az.KeyVault module not found. Install: Install-Module -Name Az -Scope CurrentUser'
        Write-Warning '[Azure] Skipping Azure Key Vault audit. Use -SkipAzure to suppress.'
    }
    elseif ($effVaults.Count -eq 0) {
        Write-Warning '[Azure] No vault names configured. Add to config/settings.json or pass -VaultNames.'
    }
    else {
        try {
            Connect-AzureForAudit -SubscriptionId $effSubId | Out-Null

            foreach ($vault in $effVaults) {
                $f = Get-KeyVaultSecretAudit -VaultName $vault `
                    -ExpiryWarningDays $effExpWarn -CriticalExpiryDays $effCritical `
                    -InactiveThresholdDays $effInactive
                foreach ($item in $f) { $allFindings.Add($item) }

                $f = Get-KeyVaultPermissionAudit -VaultName $vault
                foreach ($item in $f) { $allFindings.Add($item) }
            }
        }
        catch {
            Write-Warning ('[Azure] Audit failed: ' + $_)
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE 2 — Windows Credential Manager
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipWindows) {
    try {
        $winInactive = if ($config.WindowsCredentialManager.InactiveThresholdDays) {
            $config.WindowsCredentialManager.InactiveThresholdDays
        } else { $effInactive }

        $f = Get-WindowsCredentialAudit `
            -InactiveThresholdDays $winInactive `
            -ExcludeTypes          $config.WindowsCredentialManager.ExcludeTypes
        foreach ($item in $f) { $allFindings.Add($item) }
    }
    catch {
        Write-Warning ('[Windows] Audit failed: ' + $_)
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE 3 — CyberArk PAM
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipCyberArk) {
    $pvwaUrl = $config.CyberArk.PvwaUrl
    if (-not $pvwaUrl) {
        Write-Warning '[CyberArk] PvwaUrl not set in config/settings.json. Skipping.'
        Write-Warning '  Set CyberArk.PvwaUrl and env vars CYBERARK_USER / CYBERARK_PASSWORD.'
    }
    else {
        $caToken = $null
        try {
            $caToken = Connect-CyberArkVault -PvwaUrl $pvwaUrl `
                -AuthType $config.CyberArk.AuthType `
                -IgnoreSelfSigned $config.CyberArk.IgnoreSelfSigned

            if ($config.CyberArk.AuditAccounts) {
                $f = Get-CyberArkAccountAudit -PvwaUrl $pvwaUrl -Token $caToken `
                    -InactiveThresholdDays $config.CyberArk.InactiveThresholdDays `
                    -SafeFilter $config.CyberArk.SafesToAudit
                foreach ($item in $f) { $allFindings.Add($item) }
            }

            if ($config.CyberArk.AuditSafePermissions) {
                $f = Get-CyberArkSafePermissionAudit -PvwaUrl $pvwaUrl -Token $caToken `
                    -SafesToAudit $config.CyberArk.SafesToAudit
                foreach ($item in $f) { $allFindings.Add($item) }
            }
        }
        catch {
            Write-Warning ('[CyberArk] Audit failed: ' + $_)
        }
        finally {
            if ($caToken) {
                Disconnect-CyberArkVault -PvwaUrl $pvwaUrl -Token $caToken
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE 4 — AWS Secrets Manager
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipAws) {
    try {
        $awsParams = @{
            InactiveThresholdDays  = $config.AwsSecretsManager.InactiveThresholdDays
            RotationWarningDays    = $config.AwsSecretsManager.RotationWarningDays
            ExcludeNamePatterns    = $config.AwsSecretsManager.ExcludeNamePatterns
        }
        if ($effAwsRegion)  { $awsParams['Region']      = $effAwsRegion }
        if ($effAwsProfile) { $awsParams['ProfileName'] = $effAwsProfile }

        $f = Get-AwsSecretsManagerAudit @awsParams
        foreach ($item in $f) { $allFindings.Add($item) }
    }
    catch {
        Write-Warning ('[AWS] Audit failed: ' + $_)
        Write-Warning '  Ensure AWS.Tools.SecretsManager is installed and AWS credentials are configured.'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE 5 — BeyondTrust Password Safe
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipBeyondTrust) {
    $btUrl    = if ($config.BeyondTrust.BaseUrl) { $config.BeyondTrust.BaseUrl } else { $env:BEYONDTRUST_URL }
    $btKey    = $env:BEYONDTRUST_API_KEY
    $btRunAs  = $env:BEYONDTRUST_RUNAS

    if (-not $btUrl -or -not $btKey -or -not $btRunAs) {
        Write-Warning '[BeyondTrust] Missing configuration. Skipping.'
        Write-Warning '  Required: BeyondTrust.BaseUrl in settings.json + env vars BEYONDTRUST_API_KEY and BEYONDTRUST_RUNAS.'
    }
    else {
        $btConn = $null
        try {
            $btConn = Connect-BeyondTrustVault -BaseUrl $btUrl -ApiKey $btKey -RunAsUser $btRunAs

            $f = Get-BeyondTrustAccountAudit -Connection $btConn `
                -InactiveThresholdDays $config.BeyondTrust.InactiveThresholdDays `
                -SystemFilter          $config.BeyondTrust.SystemFilter
            foreach ($item in $f) { $allFindings.Add($item) }
        }
        catch {
            Write-Warning ('[BeyondTrust] Audit failed: ' + $_)
        }
        finally {
            if ($btConn) { Disconnect-BeyondTrustVault -Connection $btConn }
        }
    }
}

# ─── Guard: nothing collected ─────────────────────────────────────────────────
if ($allFindings.Count -eq 0) {
    Write-Host ''
    Write-Host '[Info] No findings collected. Check configuration and module availability.' -ForegroundColor Yellow
    exit 0
}

# ─── Export ───────────────────────────────────────────────────────────────────
$reportPaths = @{}
if (-not $NoExport) {
    $reportPaths = Export-AuditReport `
        -Findings        $allFindings `
        -OutputDirectory $effOutputDir `
        -ExportCsv       $config.Report.ExportCsv `
        -ExportJson      $config.Report.ExportJson
}

# ─── Console summary ──────────────────────────────────────────────────────────
$primaryReport = if ($reportPaths.ContainsKey('CSV')) { $reportPaths['CSV'] } else { $null }
Write-ConsoleSummary -Findings $allFindings -ReportPath $primaryReport

# ─── Open report ──────────────────────────────────────────────────────────────
if ($OpenReport -and $reportPaths.ContainsKey('CSV')) { Start-Process $reportPaths['CSV'] }

# ─── Exit code ────────────────────────────────────────────────────────────────
if (@($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { exit 2 }
if (@($allFindings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0)     { exit 1 }
exit 0
