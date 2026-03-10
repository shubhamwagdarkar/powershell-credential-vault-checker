<#
.SYNOPSIS
    Report generation functions — CSV, JSON, and console summary.
    Compatible with Windows PowerShell 5.x and PowerShell 7+.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SeverityOrder {
    param([string]$Severity)
    if ($Severity -eq 'Critical') { return 1 }
    elseif ($Severity -eq 'High')     { return 2 }
    elseif ($Severity -eq 'Medium')   { return 3 }
    elseif ($Severity -eq 'Low')      { return 4 }
    elseif ($Severity -eq 'Info')     { return 5 }
    else { return 99 }
}

function Get-SeverityColor {
    param([string]$Severity)
    if ($Severity -eq 'Critical') { return 'Red' }
    elseif ($Severity -eq 'High')     { return 'DarkRed' }
    elseif ($Severity -eq 'Medium')   { return 'Yellow' }
    elseif ($Severity -eq 'Low')      { return 'Cyan' }
    elseif ($Severity -eq 'Info')     { return 'Gray' }
    else { return 'White' }
}

function Write-ConsoleSummary {
    <#
    .SYNOPSIS
        Writes a human-readable summary of audit findings to the console.
    #>
    [CmdletBinding()]
    param(
        $Findings,

        [Parameter(Mandatory = $false)]
        [string]$ReportPath
    )

    # Wrap in array for PS5 compatibility
    $allFindings = @($Findings)

    $sorted = $allFindings | Sort-Object { Get-SeverityOrder -Severity $_.Severity }

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host '  CREDENTIAL VAULT AUDIT REPORT' -ForegroundColor White
    Write-Host ('  Generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor Gray
    Write-Host ('=' * 70) -ForegroundColor DarkGray

    # --- Severity summary ---
    $severities = @('Critical', 'High', 'Medium', 'Low', 'Info')
    Write-Host ''
    Write-Host 'SEVERITY SUMMARY' -ForegroundColor White
    Write-Host ('-' * 40) -ForegroundColor DarkGray

    foreach ($sev in $severities) {
        $count = @($allFindings | Where-Object { $_.Severity -eq $sev }).Count
        if ($count -gt 0) {
            $color = Get-SeverityColor -Severity $sev
            Write-Host ("  {0,-12} {1,4}" -f $sev, $count) -ForegroundColor $color
        }
    }
    Write-Host ("  {0,-12} {1,4}" -f 'TOTAL', $allFindings.Count) -ForegroundColor White

    if ($allFindings.Count -eq 0) {
        Write-Host ''
        Write-Host '  No findings to display.' -ForegroundColor Gray
        Write-Host ('=' * 70) -ForegroundColor DarkGray
        return
    }

    # --- Source breakdown ---
    Write-Host ''
    Write-Host 'SOURCE BREAKDOWN' -ForegroundColor White
    Write-Host ('-' * 40) -ForegroundColor DarkGray
    $allFindings | Group-Object Source | ForEach-Object {
        Write-Host ("  {0,-35} {1,4}" -f $_.Name, $_.Count) -ForegroundColor Gray
    }

    # --- Finding type breakdown ---
    Write-Host ''
    Write-Host 'FINDING TYPES' -ForegroundColor White
    Write-Host ('-' * 40) -ForegroundColor DarkGray
    $allFindings | Group-Object FindingType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  {0,-30} {1,4}" -f $_.Name, $_.Count) -ForegroundColor Gray
    }

    # --- Actionable findings ---
    $actionable = @($sorted | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' -or $_.Severity -eq 'Medium' })
    if ($actionable.Count -gt 0) {
        Write-Host ''
        Write-Host 'ACTIONABLE FINDINGS (Critical / High / Medium)' -ForegroundColor White
        Write-Host ('-' * 70) -ForegroundColor DarkGray

        foreach ($finding in $actionable) {
            $color = Get-SeverityColor -Severity $finding.Severity
            Write-Host ''
            Write-Host ('  [' + $finding.Severity + '] ' + $finding.FindingType) -ForegroundColor $color
            Write-Host ('  Source     : ' + $finding.Source) -ForegroundColor Gray
            $hasVaultName = $null -ne $finding.PSObject.Properties['VaultName']
            if ($hasVaultName -and $finding.VaultName) {
                Write-Host ('  Vault      : ' + $finding.VaultName) -ForegroundColor Gray
            }
            Write-Host ('  Secret     : ' + $finding.SecretName) -ForegroundColor Gray

            # DaysToExpiry — only present on Azure Key Vault findings
            $hasDaysToExpiry = $null -ne $finding.PSObject.Properties['DaysToExpiry']
            if ($hasDaysToExpiry -and $null -ne $finding.DaysToExpiry) {
                if ($finding.DaysToExpiry -lt 0) {
                    $expLabel = 'EXPIRED ' + [math]::Abs($finding.DaysToExpiry) + ' days ago'
                }
                else {
                    $expLabel = 'Expires in ' + $finding.DaysToExpiry + ' days'
                }
                Write-Host ('  Expiry     : ' + $expLabel) -ForegroundColor $color
            }
            $hasExpiryDate = $null -ne $finding.PSObject.Properties['ExpiryDate']
            if ($hasExpiryDate -and $finding.ExpiryDate -and $finding.ExpiryDate -ne 'Not Set') {
                Write-Host ('  Expiry Date: ' + $finding.ExpiryDate) -ForegroundColor Gray
            }

            # DaysSinceChange — CyberArk / BeyondTrust findings
            $hasDaysSince = $null -ne $finding.PSObject.Properties['DaysSinceChange']
            if ($hasDaysSince -and $finding.DaysSinceChange) {
                Write-Host ('  Days Since Change: ' + $finding.DaysSinceChange) -ForegroundColor Gray
            }
            Write-Host ('  Action     : ' + $finding.Recommendation) -ForegroundColor White
        }
    }

    if ($ReportPath) {
        Write-Host ''
        Write-Host ('=' * 70) -ForegroundColor DarkGray
        Write-Host ('  Full report saved to: ' + $ReportPath) -ForegroundColor Green
    }

    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host ''
}

function Export-AuditReport {
    <#
    .SYNOPSIS
        Exports audit findings to CSV and/or JSON files.
    .OUTPUTS
        Hashtable with paths of generated report files.
    #>
    [CmdletBinding()]
    param(
        $Findings,

        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = 'reports',

        [Parameter(Mandatory = $false)]
        [bool]$ExportCsv = $true,

        [Parameter(Mandatory = $false)]
        [bool]$ExportJson = $true
    )

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    # Wrap in array for PS5 .Count / pipeline compatibility
    $allFindings = @($Findings)

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportPaths = @{}

    $sorted = $allFindings | Sort-Object { Get-SeverityOrder -Severity $_.Severity }

    if ($ExportCsv) {
        $csvPath = Join-Path $OutputDirectory ('credential_audit_' + $timestamp + '.csv')
        $sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $reportPaths['CSV'] = $csvPath
        Write-Host ('[Report] CSV exported: ' + $csvPath) -ForegroundColor Green
    }

    if ($ExportJson) {
        $jsonPath = Join-Path $OutputDirectory ('credential_audit_' + $timestamp + '.json')

        $totalCount    = $allFindings.Count
        $criticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount     = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount   = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $lowCount      = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        $infoCount     = @($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count

        $sourceGroups  = $allFindings | Group-Object Source | ForEach-Object {
            [PSCustomObject]@{ Source = $_.Name; Count = $_.Count }
        }
        $typeGroups    = $allFindings | Group-Object FindingType | ForEach-Object {
            [PSCustomObject]@{ Type = $_.Name; Count = $_.Count }
        }

        $summary = [PSCustomObject]@{
            GeneratedAt    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
            TotalFindings  = $totalCount
            CriticalCount  = $criticalCount
            HighCount      = $highCount
            MediumCount    = $mediumCount
            LowCount       = $lowCount
            InfoCount      = $infoCount
            Sources        = @($sourceGroups)
            FindingTypes   = @($typeGroups)
            Findings       = $sorted
        }

        $summary | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
        $reportPaths['JSON'] = $jsonPath
        Write-Host ('[Report] JSON exported: ' + $jsonPath) -ForegroundColor Green
    }

    return $reportPaths
}

Export-ModuleMember -Function Write-ConsoleSummary, Export-AuditReport
