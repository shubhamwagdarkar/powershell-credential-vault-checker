# powershell-credential-vault-checker

**Automation | PowerShell**

Enterprise credential audit tool covering five vault sources: Azure Key Vault, Windows Credential Manager, CyberArk PAM, AWS Secrets Manager, and BeyondTrust Password Safe. Identifies expiring secrets, rotation failures, weak permissions, and unused credentials — outputs severity-ranked findings to console and exports CSV/JSON reports with CI/CD-compatible exit codes.

---

## 🚀 Why This Project Exists

Most enterprises struggle with:
- Expired secrets causing outages
- Weak permissions creating security risks
- Lack of visibility across credential systems

This tool solves that by:

→ Providing a unified audit across 5 major vault systems  
→ Detecting security risks automatically  
→ Integrating into CI/CD pipelines for continuous monitoring

---

## What It Does

| Check | Source |
|-------|--------|
| Expired secrets | Azure Key Vault |
| Secrets expiring within warning/critical threshold | Azure Key Vault |
| Secrets with no expiry date set | Azure Key Vault |
| Inactive secrets (not rotated in N days) | Azure Key Vault |
| Over-privileged RBAC roles / access policies | Azure Key Vault |
| Soft-delete and purge protection disabled | Azure Key Vault |
| Stale / inactive credentials | Windows Credential Manager |
| Credentials with empty usernames | Windows Credential Manager |
| Suspicious credential targets | Windows Credential Manager |
| Generic type on domain targets | Windows Credential Manager |
| Account management failures | CyberArk PAM |
| Auto-management disabled on accounts | CyberArk PAM |
| Stale passwords (not rotated in N days) | CyberArk PAM |
| Safe members with retrieve / manage permissions | CyberArk PAM |
| Rotation not configured | AWS Secrets Manager |
| Rotation enabled but never triggered | AWS Secrets Manager |
| Stale rotation (last rotated > threshold) | AWS Secrets Manager |
| Secrets scheduled for deletion | AWS Secrets Manager |
| Inactive secrets (not accessed in N days) | AWS Secrets Manager |
| Fallback password active (last rotation failed) | BeyondTrust Password Safe |
| Auto-management disabled | BeyondTrust Password Safe |
| Stale passwords (not changed in N days) | BeyondTrust Password Safe |

---

## Stack

- **Language:** PowerShell 5+ (Windows PowerShell compatible)
- **Azure:** Az.KeyVault, Az.Resources modules
- **Windows:** Native Win32 CredEnumerate P/Invoke (no external module required)
- **CyberArk:** PVWA REST API (CyberArk / LDAP / Windows / RADIUS auth)
- **AWS:** AWS.Tools.SecretsManager or AWSPowerShell module
- **BeyondTrust:** Password Safe REST API (PS-Auth API Registration key)
- **Testing:** Pester 3.x / 5.x — 103 tests

---

## Project Structure

```
powershell-credential-vault-checker/
├── Invoke-CredentialVaultChecker.ps1      # Main orchestrator — runs all sources
├── modules/
│   ├── AzureKeyVaultAuditor.psm1          # Azure Key Vault secret + permission audit
│   ├── WindowsCredentialAuditor.psm1      # Windows Credential Manager audit (Win32 P/Invoke)
│   ├── CyberArkAuditor.psm1               # CyberArk PAM account + safe permission audit
│   ├── AwsSecretsManagerAuditor.psm1      # AWS Secrets Manager rotation + staleness audit
│   ├── BeyondTrustAuditor.psm1            # BeyondTrust Password Safe account audit
│   └── ReportGenerator.psm1              # Console summary + CSV/JSON export
├── tests/
│   ├── CredentialVaultChecker.Tests.ps1  # 103 Pester tests (edge cases + boundary conditions)
│   └── RunTests.ps1                      # Test runner helper
├── config/
│   └── settings.json                     # Thresholds, vault names, source toggles
├── reports/                              # Generated reports (gitignored)
└── README.md
```

---

## Setup

### Prerequisites

```powershell
# PowerShell 5+ (built into Windows) or PowerShell 7+
winget install Microsoft.PowerShell   # optional — PS7

# Azure Key Vault audit
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

# AWS Secrets Manager audit
Install-Module -Name AWS.Tools.SecretsManager -Scope CurrentUser -Force

# Pester (for running tests)
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

### Environment Variables

Set credentials via environment variables — never in config files.

```powershell
# CyberArk PAM
$env:CYBERARK_USER     = "audit-svc-account"
$env:CYBERARK_PASSWORD = "your-password"

# BeyondTrust Password Safe
$env:BEYONDTRUST_API_KEY = "your-api-registration-key"
$env:BEYONDTRUST_RUNAS   = "audit-username"

# AWS (standard credential chain — any of these)
$env:AWS_ACCESS_KEY_ID     = "AKIA..."
$env:AWS_SECRET_ACCESS_KEY = "..."
$env:AWS_DEFAULT_REGION    = "us-east-1"
# or use: $env:AWS_PROFILE = "your-profile"
```

### Configure

Edit `config/settings.json`:

```json
{
  "AzureKeyVault": {
    "SubscriptionId": "your-azure-subscription-id",
    "VaultNames": ["prod-vault", "dev-vault"],
    "ExpiryWarningDays": 30,
    "CriticalExpiryDays": 7,
    "InactiveThresholdDays": 90
  },
  "CyberArk": {
    "PvwaUrl": "https://pvwa.your-domain.com",
    "AuthType": "CyberArk",
    "SafesToAudit": [],
    "InactiveThresholdDays": 90,
    "AuditAccounts": true,
    "AuditSafePermissions": true
  },
  "AwsSecretsManager": {
    "Region": "us-east-1",
    "InactiveThresholdDays": 90,
    "RotationWarningDays": 30,
    "ExcludeNamePatterns": ["internal/temp/*"]
  },
  "BeyondTrust": {
    "BaseUrl": "https://passwordsafe.your-domain.com",
    "InactiveThresholdDays": 90,
    "SystemFilter": []
  }
}
```

---

## Usage

```powershell
# Full audit — all five sources
.\Invoke-CredentialVaultChecker.ps1

# Skip specific sources
.\Invoke-CredentialVaultChecker.ps1 -SkipAzure
.\Invoke-CredentialVaultChecker.ps1 -SkipWindows
.\Invoke-CredentialVaultChecker.ps1 -SkipCyberArk
.\Invoke-CredentialVaultChecker.ps1 -SkipAws
.\Invoke-CredentialVaultChecker.ps1 -SkipBeyondTrust

# Azure + CyberArk only
.\Invoke-CredentialVaultChecker.ps1 -SkipWindows -SkipAws -SkipBeyondTrust

# AWS — specific region and profile
.\Invoke-CredentialVaultChecker.ps1 -SkipAzure -SkipWindows -SkipCyberArk -SkipBeyondTrust `
    -AwsRegion eu-west-1 -AwsProfile prod

# Tighter expiry thresholds
.\Invoke-CredentialVaultChecker.ps1 -ExpiryWarningDays 60 -CriticalExpiryDays 14

# Console only, no file export
.\Invoke-CredentialVaultChecker.ps1 -NoExport

# Open CSV report after generation
.\Invoke-CredentialVaultChecker.ps1 -OpenReport
```

---

## Sample Output

```
======================================================================
  CREDENTIAL VAULT AUDIT REPORT
  Generated: 2026-03-09 14:22:05
======================================================================

SEVERITY SUMMARY
----------------------------------------
  Critical        2
  High            4
  Medium          6
  Low             8
  TOTAL          20

SOURCE BREAKDOWN
----------------------------------------
  AzureKeyVault                          6
  CyberArkPAM                            5
  AwsSecretsManager                      4
  BeyondTrustPasswordSafe                3
  WindowsCredentialManager               2

FINDING TYPES
----------------------------------------
  ExpiryWarning                          3
  NoAutoManagement                       3
  NoRotation                             2
  WeakPermission                         2
  FallbackPasswordActive                 1
  ...

ACTIONABLE FINDINGS (Critical / High / Medium)
----------------------------------------------------------------------

  [Critical] Expired
  Source     : AzureKeyVault
  Vault      : prod-vault
  Secret     : db-connection-string
  Expiry     : EXPIRED 12 days ago
  Expiry Date: 2026-02-25
  Action     : SECRET EXPIRED. Rotate immediately and update all consumers.

  [High] ManagementFailed
  Source     : CyberArkPAM
  Vault      : ProdSafe
  Secret     : svc-db-account
  Days Since Change: 142
  Action     : CyberArk reported management failure. Check PVWA logs.

  [High] FallbackPasswordActive
  Source     : BeyondTrustPasswordSafe
  Vault      : PROD-SQL-01
  Secret     : sa
  Action     : Password fallback is active. Last automated change failed.
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no Critical or High findings |
| `1` | High severity findings detected |
| `2` | Critical severity findings detected |

Use in CI/CD:

```yaml
- name: Credential Audit
  run: pwsh -File ./Invoke-CredentialVaultChecker.ps1 -SkipWindows
  env:
    CYBERARK_USER: ${{ secrets.CYBERARK_USER }}
    CYBERARK_PASSWORD: ${{ secrets.CYBERARK_PASSWORD }}
    BEYONDTRUST_API_KEY: ${{ secrets.BEYONDTRUST_API_KEY }}
    BEYONDTRUST_RUNAS: ${{ secrets.BEYONDTRUST_RUNAS }}
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

---

## Running Tests

```powershell
# Quick run
powershell -File .\tests\RunTests.ps1

# Full Pester output
Invoke-Pester .\tests\CredentialVaultChecker.Tests.ps1

# With code coverage
Invoke-Pester .\tests\CredentialVaultChecker.Tests.ps1 -CodeCoverage .\modules\*.psm1
```

103 tests covering: expiry boundary conditions, severity precedence, null date handling, special characters in data, missing optional properties, sort ordering, module exports, and all five source classifications.

---

## What I Learned

CyberArk and BeyondTrust are both mid-migration between legacy access policy models and modern RBAC — the audit logic needs to detect which model is active and branch accordingly. AWS Secrets Manager's rotation model (enabled vs. ever-triggered vs. stale) has three distinct failure states that each need separate classification logic. Implementing Win32 `CredEnumerate` directly via C# P/Invoke eliminated the CredentialManager module dependency while keeping the tool portable. Windows PowerShell 5 has subtle parser bugs that PS7 silently fixed — em dashes in double-quoted strings, nullable type annotations on parameters, and single-item `Where-Object` results without `.Count`.

---

## Author

Enterprise Automation Portfolio
