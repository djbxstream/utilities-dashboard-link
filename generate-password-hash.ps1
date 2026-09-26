<#
.SYNOPSIS
    Generates the SHA-256 hash for the Utilities Dashboard launcher password.

.DESCRIPTION
    Prompts for a password with no echo, hashes it with SHA-256, and prints
    ONLY the 64-character lowercase hex digest.

    The plain-text password is never written to disk, never logged, and never
    passed on the command line - which matters, because on Windows a command
    line argument is visible to every process on the machine via the process
    list. It is held in a SecureString and converted only in memory at the
    moment of hashing, then discarded.

    Paste the printed hash into PASSWORD_SHA256 in launcher-config.js and set
    CONFIGURED to true.

.EXAMPLE
    .\generate-password-hash.ps1
    Prompts for the password and prints the SHA-256 hash.

.EXAMPLE
    .\generate-password-hash.ps1 -ShowSample
    Prints a known test vector so you can confirm the script works before
    trusting its output. Never use the sample value as a real password.

.NOTES
    This is a POC convenience tool for the launcher gate. It does not write to
    the configuration file automatically, so nothing sensitive can be
    committed by accident. Do not commit the plain-text password.
#>
[CmdletBinding()]
param(
    # Prints a known-answer test vector instead of prompting. Use to verify the
    # script produces a correct SHA-256 digest.
    [switch] $ShowSample
)

$ErrorActionPreference = "Stop"

# Known-answer test: the SHA-256 of the ASCII string "abc".
$sampleInput  = "abc"
$sampleDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

function Get-HexHash {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }

    $builder = [System.Text.StringBuilder]::new($hashBytes.Length * 2)
    foreach ($b in $hashBytes) {
        [void] $builder.Append($b.ToString("x2"))
    }
    return $builder.ToString()
}

Write-Host ""
Write-Host "Utilities Dashboard - launcher password hash generator" -ForegroundColor Cyan
Write-Host ""

if ($ShowSample) {
    $digest = Get-HexHash -Text $sampleInput
    if ($digest -ne $sampleDigest) {
        throw "Self-test failed. Expected $sampleDigest but computed $digest."
    }
    Write-Host "Self-test passed: SHA-256 of 'abc' is correct." -ForegroundColor Green
    Write-Host ""
    Write-Host "Sample hash (do NOT use as a password):" -ForegroundColor Yellow
    Write-Host $digest
    Write-Host ""
    return
}

# Prompt with no echo. Read-Host -AsSecureString keeps the value off screen.
$secure = Read-Host -Prompt "Enter the launcher password (input is hidden)" -AsSecureString

if ($null -eq $secure) {
    throw "No password was entered."
}

# Convert to plain text only in memory, for hashing. $plain is cleared below.
$plainPtr = [System.IntPtr]::Zero
try {
    $plainPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($plainPtr)
    $digest = Get-HexHash -Text $plain
}
finally {
    if ($plainPtr -ne [System.IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($plainPtr)
    }
    # Drop every reference we can, so the value does not linger in the session.
    $plain = $null
    $secure = $null
    [System.GC]::Collect()
}

Write-Host ""
Write-Host "SHA-256 hash (lowercase hex):" -ForegroundColor Green
Write-Host $digest
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy the hash above."
Write-Host "  2. Paste it over PASSWORD_SHA256 in launcher-config.js."
Write-Host "  3. Set CONFIGURED to true."
Write-Host "  4. Commit and push. Never commit the plain-text password."
Write-Host ""
Write-Host "Reminder: the hash is public once published, because GitHub Pages" -ForegroundColor Yellow
Write-Host "serves this repository as public static files. This is a casual-" -ForegroundColor Yellow
Write-Host "access deterrent only, not authentication." -ForegroundColor Yellow
Write-Host ""
