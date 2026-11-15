#Requires -Version 5.1
<#
.SYNOPSIS
    SECURE-WEB-1 (3.1.26, owner: "the internet-facing identity has NO Key Vault edge") -- the emergency override
    (break-glass) passphrase VERIFIER, kept in the PIM database (pim.Settings 'EmergencyPassphraseVerifier').

.DESCRIPTION
    Before 3.1.26 the Manager (the internet-facing web app) read the SHA-256 hex of the passphrase from the Key Vault
    secret PIM-EmergencyPasscode, so its identity held Key Vault Secrets User on that secret. From 3.1.26 the Manager reads
    a VERIFIER from the store it already reads, and its identity holds no Key Vault role at all.

    THE VERIFIER (never the passphrase, never its plain hash):
        pre   = lower-case SHA-256 hex of the UTF-8 passphrase          (what Set-PimEmergencyPassphrase.ps1 always computed,
                                                                         and what the old Key Vault secret holds)
        dk    = PBKDF2-HMAC-SHA256(UTF-8 bytes of pre, salt, iterations, 32 bytes)
        salt  = 16 random bytes, new on every write (per install, per passphrase)
        iter  = 600000 when written (OWASP 2023 figure for PBKDF2-SHA256); a verifier below 100000 is refused when read
    Stored as JSON: { v = 1; alg = 'pbkdf2-sha256'; pre = 'sha256-hex'; iter; salt (base64); dk (base64); setUtc; source }.
    The pre-hash step is what lets the updater move an EXISTING installation once without the passphrase: it reads the
    old secret (the same SHA-256 hex) and derives the verifier from it. A guess still costs one full PBKDF2 run.
    The compare is constant time (an XOR fold over all 32 bytes).

    The setting name contains "Passphrase", so the configuration backup never copies it (PIM-ConfigBackup.ps1
    Test-PimConfigBackupSecretName) and a restore can never put an old one back.

    PURE (no I/O). PS 5.1 + 7. ASCII only. No modules.
#>
Set-StrictMode -Off

function Get-PimEmergencyVerifierSettingName { 'EmergencyPassphraseVerifier' }
function Get-PimEmergencyVerifierIterations { 600000 }
function Get-PimEmergencyVerifierMinIterations { 100000 }

function Get-PimEmergencyPreHash {
    <# PURE. The lower-case SHA-256 hex of the UTF-8 text (the pre-hash the verifier is derived from). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PimEmergencyPbkdf2 {
    <# PURE. PBKDF2-HMAC-SHA256 of -PreHashHex (its UTF-8 bytes) -> 32 bytes. #>
    param([Parameter(Mandatory)][string]$PreHashHex, [Parameter(Mandatory)][byte[]]$Salt, [Parameter(Mandatory)][int]$Iterations)
    $pw = [System.Text.Encoding]::UTF8.GetBytes("$PreHashHex".ToLowerInvariant())
    $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($pw, $Salt, $Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return [byte[]]$kdf.GetBytes(32) } finally { $kdf.Dispose() }
}

function Test-PimEmergencyBytesEqual {
    <# PURE. Constant-time compare of two byte arrays (length-safe). #>
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    # an XOR fold over every byte (PowerShell cannot pass the Span arguments CryptographicOperations.FixedTimeEquals takes)
    $diff = $A.Length -bxor $B.Length
    $n = [math]::Min($A.Length, $B.Length)
    for ($i = 0; $i -lt $n; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
    return ($diff -eq 0)
}

function New-PimEmergencyVerifier {
    <#
      PURE (random salt). The verifier record for a pre-hash (-PreHashHex, 64 lower-case hex). -Iterations / -Salt are for
      the tests; the default is 600000 iterations and 16 fresh random bytes. Throws on a pre-hash that is not 64 hex.
    #>
    param([Parameter(Mandatory)][string]$PreHashHex, [int]$Iterations = 0, [byte[]]$Salt, [string]$Source = 'Set-PimEmergencyPassphrase', [datetime]$NowUtc = [datetime]::UtcNow)
    $pre = "$PreHashHex".Trim().ToLowerInvariant()
    if ($pre -notmatch '^[0-9a-f]{64}$') { throw 'New-PimEmergencyVerifier: the pre-hash is not a SHA-256 hex' }
    if ($Iterations -le 0) { $Iterations = Get-PimEmergencyVerifierIterations }
    if ($Iterations -lt (Get-PimEmergencyVerifierMinIterations)) { throw "New-PimEmergencyVerifier: $Iterations iterations is below the floor $(Get-PimEmergencyVerifierMinIterations)" }
    if (-not $Salt -or $Salt.Length -lt 16) {
        $Salt = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($Salt) } finally { $rng.Dispose() }
    }
    $dk = Get-PimEmergencyPbkdf2 -PreHashHex $pre -Salt $Salt -Iterations $Iterations
    return [ordered]@{
        v = 1; alg = 'pbkdf2-sha256'; pre = 'sha256-hex'; iter = [int]$Iterations
        salt = [Convert]::ToBase64String($Salt); dk = [Convert]::ToBase64String($dk)
        setUtc = $NowUtc.ToUniversalTime().ToString('o'); source = "$Source"
    }
}

function ConvertFrom-PimEmergencyVerifier {
    <#
      PURE. The stored value (JSON text, a parsed object or a dictionary) -> @{ ok; reason; iter; salt (bytes); dk (bytes);
      setUtc; source }. ok = $false (with the reason) for anything that is not a usable verifier -- never throws.
    #>
    param([AllowNull()][object]$Value, [int]$MinIterations = 0)
    if ($MinIterations -le 0) { $MinIterations = Get-PimEmergencyVerifierMinIterations }
    $bad = { param($why) [pscustomobject]@{ ok = $false; reason = $why; iter = 0; salt = $null; dk = $null; setUtc = ''; source = '' } }
    if ($null -eq $Value) { return (& $bad 'no verifier is stored') }
    $o = $Value
    if ($o -is [string]) {
        if (-not "$o".Trim()) { return (& $bad 'no verifier is stored') }
        try { $o = "$o" | ConvertFrom-Json } catch { return (& $bad 'the stored verifier is not valid JSON') }
    }
    $get = { param($n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if ("$(& $get 'alg')" -ne 'pbkdf2-sha256' -or "$(& $get 'pre')" -ne 'sha256-hex') { return (& $bad 'the stored verifier is not pbkdf2-sha256 over the sha256-hex pre-hash') }
    $it = 0; try { $it = [int](& $get 'iter') } catch { $it = 0 }
    if ($it -lt $MinIterations) { return (& $bad "the stored verifier uses $it iterations (at least $MinIterations are required)") }
    $salt = $null; $dk = $null
    try { $salt = [Convert]::FromBase64String("$(& $get 'salt')"); $dk = [Convert]::FromBase64String("$(& $get 'dk')") } catch { return (& $bad 'the stored verifier has an unreadable salt or key') }
    if ($salt.Length -lt 16 -or $dk.Length -ne 32) { return (& $bad 'the stored verifier has a salt shorter than 16 bytes or a key that is not 32 bytes') }
    return [pscustomobject]@{ ok = $true; reason = ''; iter = $it; salt = $salt; dk = $dk; setUtc = "$(& $get 'setUtc')"; source = "$(& $get 'source')" }
}

function Test-PimEmergencyVerifier {
    <#
      PURE. Does -Passphrase (the typed text) match the stored -Verifier? -PreHashHex instead of -Passphrase checks a
      pre-hash (the read-back self-check of a write). Returns $true / $false; an unusable verifier is $false.
    #>
    param([AllowNull()][object]$Verifier, [AllowEmptyString()][string]$Passphrase, [string]$PreHashHex = '', [int]$MinIterations = 0)
    $p = ConvertFrom-PimEmergencyVerifier -Value $Verifier -MinIterations $MinIterations
    if (-not $p.ok) { return $false }
    $pre = if ("$PreHashHex".Trim()) { "$PreHashHex".Trim().ToLowerInvariant() } else { Get-PimEmergencyPreHash -Text "$Passphrase" }
    $dk = Get-PimEmergencyPbkdf2 -PreHashHex $pre -Salt $p.salt -Iterations $p.iter
    return (Test-PimEmergencyBytesEqual -A $dk -B $p.dk)
}

function ConvertTo-PimEmergencyPreHashFromSecret {
    <#
      PURE. The value of the OLD Key Vault secret PIM-EmergencyPasscode -> the pre-hash: a 64-char hex is used as it is (the
      setup script stored that), anything else is a passphrase stored in clear (hand-made) and is hashed. '' -> ''.
    #>
    param([AllowNull()][object]$SecretValue)
    $v = "$SecretValue".Trim()
    if (-not $v) { return '' }
    if ($v -match '^[0-9a-fA-F]{64}$') { return $v.ToLowerInvariant() }
    return (Get-PimEmergencyPreHash -Text $v)
}
