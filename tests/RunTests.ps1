$r = Invoke-Pester (Join-Path $PSScriptRoot 'CredentialVaultChecker.Tests.ps1') -PassThru
$r.TestResult | Where-Object { $_.Passed -eq $false } | ForEach-Object {
    Write-Host ('FAIL: ' + $_.Name)
    Write-Host ('  MSG: ' + $_.FailureMessage.Split("`n")[0])
    Write-Host ''
}
Write-Host ('Passed: ' + $r.PassedCount + '  Failed: ' + $r.FailedCount)
