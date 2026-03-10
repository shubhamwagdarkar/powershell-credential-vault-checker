<#
.SYNOPSIS
    Windows Credential Manager audit functions.
.DESCRIPTION
    Reads credentials stored in Windows Credential Manager using the
    native CredEnumerate Win32 API via P/Invoke (no external module required).
    Audits for: generic/legacy credential types, suspicious target patterns,
    credentials with empty usernames, and very old entries.

    Optional: If the CredentialManager module is installed, falls back to it.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Win32 P/Invoke for CredEnumerate (no dependency on CredentialManager module) ---
$Win32CredType = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32Credential {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr credentials);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void CredFree(IntPtr cred);

    public static CREDENTIAL[] GetAllCredentials() {
        uint count;
        IntPtr credPtr;
        if (!CredEnumerate(null, 0, out count, out credPtr)) {
            int err = Marshal.GetLastWin32Error();
            if (err == 1168) return Array.Empty<CREDENTIAL>(); // Not found — no creds
            throw new System.ComponentModel.Win32Exception(err);
        }

        var creds = new CREDENTIAL[count];
        for (uint i = 0; i < count; i++) {
            IntPtr credItemPtr = Marshal.ReadIntPtr(credPtr, (int)(i * IntPtr.Size));
            creds[i] = Marshal.PtrToStructure<CREDENTIAL>(credItemPtr);
        }
        CredFree(credPtr);
        return creds;
    }
}
"@

function Initialize-Win32CredType {
    if (-not ([System.Management.Automation.PSTypeName]'Win32Credential').Type) {
        Add-Type -TypeDefinition $Win32CredType -ErrorAction SilentlyContinue
    }
}

function ConvertFrom-FileTime {
    param([System.Runtime.InteropServices.ComTypes.FILETIME]$FileTime)
    $high = [long]$FileTime.dwHighDateTime
    $low  = [long]$FileTime.dwLowDateTime
    if ($low -lt 0) { $low += [long]::MaxValue + [long]::MaxValue + 2 }
    $combined = ($high -shl 32) -bor $low
    if ($combined -eq 0) { return $null }
    return [DateTime]::FromFileTimeUtc($combined).ToLocalTime()
}

function Get-CredentialTypeLabel {
    param([uint32]$Type)
    switch ($Type) {
        1  { return 'Generic' }
        2  { return 'DomainPassword' }
        3  { return 'DomainCertificate' }
        4  { return 'DomainVisiblePassword' }
        5  { return 'GenericCertificate' }
        6  { return 'DomainExtended' }
        7  { return 'Maximum' }
        default { return "Unknown($Type)" }
    }
}

function Get-WindowsCredentialAudit {
    <#
    .SYNOPSIS
        Enumerates and audits Windows Credential Manager entries.
    .OUTPUTS
        Array of PSCustomObject with audit findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$InactiveThresholdDays = 365,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeTypes = @()
    )

    Write-Host "[WinCred] Auditing Windows Credential Manager..." -ForegroundColor Cyan
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $now = Get-Date

    # Try native P/Invoke first; fall back to CredentialManager module if available
    $rawCreds = @()
    $useNative = $true

    try {
        Initialize-Win32CredType
        $rawCreds = [Win32Credential]::GetAllCredentials()
    }
    catch {
        Write-Warning "[WinCred] Native P/Invoke failed: $_"
        $useNative = $false
    }

    if (-not $useNative) {
        if (Get-Module -ListAvailable -Name 'CredentialManager' -ErrorAction SilentlyContinue) {
            Write-Host "[WinCred] Falling back to CredentialManager module..." -ForegroundColor Yellow
            Import-Module CredentialManager -ErrorAction Stop
            $rawCreds = Get-StoredCredential -ErrorAction SilentlyContinue
        }
        else {
            Write-Warning "[WinCred] CredentialManager module not found. Skipping Windows Credential audit."
            Write-Warning "  Install with: Install-Module -Name CredentialManager -Scope CurrentUser"
            return $findings
        }
    }

    if ($rawCreds.Count -eq 0) {
        Write-Host "[WinCred] No credentials found in Windows Credential Manager." -ForegroundColor Yellow
        return $findings
    }

    foreach ($cred in $rawCreds) {
        # Handle both native struct and module output shapes
        if ($useNative) {
            $target      = $cred.TargetName
            $username    = $cred.UserName
            $typeLabel   = Get-CredentialTypeLabel -Type $cred.Type
            $lastWritten = ConvertFrom-FileTime -FileTime $cred.LastWritten
            $comment     = $cred.Comment
        }
        else {
            $target      = $cred.TargetName
            $username    = $cred.UserName
            $typeLabel   = if ($cred.Type) { $cred.Type.ToString() } else { 'Unknown' }
            $lastWritten = $cred.LastWriteTime
            $comment     = $cred.Comment
        }

        if ($typeLabel -in $ExcludeTypes) { continue }

        $severity      = 'Info'
        $findingType   = 'OK'
        $recommendation = 'No action required. Credential appears healthy.'
        $flags         = [System.Collections.Generic.List[string]]::new()

        # Check: empty username
        if ([string]::IsNullOrWhiteSpace($username)) {
            $flags.Add('NoUsername')
            $severity    = 'Medium'
            $findingType = 'WeakCredential'
            $recommendation = 'Credential has no username. Verify it is still needed; remove if orphaned.'
        }

        # Check: suspiciously broad or generic targets
        $suspiciousPatterns = @('*', 'localhost', '127.0.0.1', 'test', 'demo', 'temp', 'password')
        foreach ($pattern in $suspiciousPatterns) {
            if ($target -ilike "*$pattern*") {
                $flags.Add("SuspiciousTarget:$pattern")
                if ($severity -eq 'Info') { $severity = 'Low' }
                if ($findingType -eq 'OK') { $findingType = 'SuspiciousTarget' }
            }
        }

        # Check: Legacy/Generic type in domain context (potential misuse)
        if ($typeLabel -eq 'Generic' -and $target -imatch '(domain|ad|ldap|corp|\.local)') {
            $flags.Add('GenericTypeForDomainTarget')
            if ($severity -in @('Info', 'Low')) { $severity = 'Medium' }
            $findingType    = 'WeakCredential'
            $recommendation = "Generic credential type used for what appears to be a domain target ($target). Use DomainPassword type instead."
        }

        # Check: inactivity
        $daysSinceWrite = $null
        if ($lastWritten) {
            $daysSinceWrite = [math]::Round(($now - $lastWritten).TotalDays, 1)
            if ($daysSinceWrite -gt $InactiveThresholdDays) {
                $flags.Add("Inactive:${daysSinceWrite}days")
                if ($severity -eq 'Info') { $severity = 'Low' }
                if ($findingType -eq 'OK') {
                    $findingType    = 'UnusedCredential'
                    $recommendation = "Not updated in $daysSinceWrite days. Verify if still needed and rotate or remove."
                }
            }
        }

        $findings.Add([PSCustomObject]@{
            Source          = 'WindowsCredentialManager'
            VaultName       = 'WindowsCredentialManager'
            SecretName      = $target
            Username        = $username
            CredentialType  = $typeLabel
            LastWritten     = if ($lastWritten) { $lastWritten.ToString('yyyy-MM-dd') } else { 'Unknown' }
            DaysSinceWrite  = $daysSinceWrite
            Comment         = $comment
            Flags           = ($flags -join ', ')
            FindingType     = $findingType
            Severity        = $severity
            Recommendation  = $recommendation
        })
    }

    $issueCount = ($findings | Where-Object { $_.FindingType -ne 'OK' }).Count
    Write-Host "[WinCred] Audited $($findings.Count) credentials. Issues found: $issueCount" -ForegroundColor Green
    return $findings
}

Export-ModuleMember -Function Get-WindowsCredentialAudit
