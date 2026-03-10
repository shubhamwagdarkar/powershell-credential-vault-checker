# powershell-credential-vault-checker

**Week 3/42 — Automation | PowerShell**

Enterprise credential audit tool for Azure Key Vault and Windows Credential Manager. Identifies expiring secrets, weak permissions, and unused credentials — outputs severity-ranked findings to console and exports CSV/JSON reports.

---

## What It Does

| Check | Source |
|-------|--------|
| Expired secrets | Azure Key Vault |
| Secrets expiring within warning/critical threshold | Azure Key Vault |
| Secrets with no expiry date set | Azure Key Vault |
| Inactive secrets (not rotated in N days) | Azure Key Vault |
| Over-privileged access policies / RBAC roles | Azure Key Vault |
| Soft-delete and purge protection disabled | Azure Key Vault |
| Stale/inactive credentials | Windows Credential Manager |
| Credentials with empty usernames | Windows Credential Manager |
| Suspicious credential targets | Windows Credential Manager |
| Generic type on domain targets | Windows Credential Manager |

---

## Stack

- **Language:** PowerShell 7+
- **Azure:** Az.KeyVault, Az.Resources modules
- **Windows:** Native Win32 CredEnumerate P/Invoke (no external module required)
- **Testing:** Pester 5+

---

## Project Structure

```
powershell-credential-vault-checker/
├── Invoke-CredentialVaultChecker.ps1   # Main entry point
├── modules/
│   ├── AzureKeyVaultAuditor.psm1       # Key Vault secret + permission audit
│   ├── WindowsCredentialAuditor.psm1   # Windows Credential Manager audit
│   └── ReportGenerator.psm1           # Console summary + CSV/JSON export
├── tests/
│   └── CredentialVaultChecker.Tests.ps1 # Pester test suite
├── config/
│   └── settings.json                   # Configuration (thresholds, vault names)
├── reports/                            # Generated reports (gitignored)
└── README.md
```

---

## Setup

### Prerequisites

```powershell
# PowerShell 7+
winget install Microsoft.PowerShell

# Az module (for Azure Key Vault audit)
Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

# Pester (for running tests)
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
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
  }
}
```

---

## Usage

```powershell
# Full audit (Azure Key Vault + Windows Credential Manager)
.\Invoke-CredentialVaultChecker.ps1

# Audit specific vaults
.\Invoke-CredentialVaultChecker.ps1 -VaultNames "prod-vault", "staging-vault"

# Windows Credential Manager only (no Azure)
.\Invoke-CredentialVaultChecker.ps1 -SkipAzure

# Azure only, skip Windows
.\Invoke-CredentialVaultChecker.ps1 -SkipWindows

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
  High            3
  Medium          5
  Low             8
  TOTAL          18

SOURCE BREAKDOWN
----------------------------------------
  AzureKeyVault                        12
  WindowsCredentialManager              6

FINDING TYPES
----------------------------------------
  OK                                    4
  ExpiryWarning                         3
  NoExpiry                              2
  WeakPermission                        3
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
  run: pwsh -File ./Invoke-CredentialVaultChecker.ps1
  # Pipeline fails if Critical or High findings exist (exit code 1 or 2)
```

---

## Running Tests

```powershell
# Run full test suite
Invoke-Pester .\tests\CredentialVaultChecker.Tests.ps1 -Output Detailed

# Run with coverage
Invoke-Pester .\tests\CredentialVaultChecker.Tests.ps1 -CodeCoverage .\modules\*.psm1
```

---

## What I Learned

Implementing Win32 `CredEnumerate` directly via C# P/Invoke in PowerShell eliminated the dependency on the CredentialManager module while handling the pointer arithmetic for marshaling the credential array — a good example of reaching into native Win32 when PowerShell abstractions fall short. The Az module's RBAC vs. legacy access policy bifurcation for Key Vaults required separate audit paths, reflecting how Azure's security model is mid-migration to RBAC-first.

---

## Author

Week 3 of 42 — Enterprise Automation Portfolio
