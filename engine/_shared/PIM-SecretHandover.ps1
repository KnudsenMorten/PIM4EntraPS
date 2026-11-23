<#
.SYNOPSIS
  SECRETS-WRITE (framework 12.25 / SEC-10, decision Q2 option a): the SEALED hand-over of a secret value from a person to
  the install's UPDATER -- the person never writes Key Vault; the updater (the only writer of secrets) does.

.DESCRIPTION
  THE FLOW
    1. The UPDATER (id-pim-updater, Key Vault Secrets Officer on the install's own vault -- the SEC-10 writer right, granted
       once by the Support app) keeps ONE RSA-3072 key pair for the install. The private key is a secret IN the install's
       vault (Get-PimShoKeySecretName); only its PUBLIC part leaves the vault, published in pim.Settings
       'SecretHandoverPublicKey' = { v; alg; keyId; publicKey (SubjectPublicKeyInfo, base64); vault; publishedUtc }.
    2. The PERSON's script (Set-PimSmtpRelayPassword.ps1 -SqlServerFqdn ...) reads that public key, SEALS the value to it
       (Protect-PimShoValue: a random AES-256-GCM key wrapped with RSA-OAEP-SHA256; the kind, vault, secret name and key id
       are the GCM associated data, so none of them can be changed without the seal failing) and writes ONLY the sealed
       blob to pim.Settings 'SecretHandoverPending'. No Key Vault call, no Key Vault role.
    3. The updater's step (Invoke-PimShoUpdaterStep) unseals it in memory, refuses anything that does not open with ITS key
       (a tampered, foreign or replayed-to-another-vault blob), writes the secret, READS IT BACK (SHA-256 compare), puts the
       previous value back on a failed read-back (a failed write keeps the old secret), then DELETES the blob (compare-and-
       delete: a newer blob written meanwhile is kept) and records pim.Settings 'SecretHandoverResult' (names only).
       It never assigns a role (P9): whether the engine identity may read the secret is REPORTED (engineCanRead).

  WHAT THE VALUE NEVER DOES: it is never printed, logged, recorded or put in an error text (Protect-PimShoText), never
  stored in SQL in the clear, and the sealed blob is checked not to carry it (Test-PimShoBlobNotPlain).

  PURE except Invoke-PimShoUpdaterStep / Invoke-PimShoSubmit, whose I/O goes through seams:
    -Kv { param($Method, $Url, $Body) }       Key Vault data plane (GET / PUT of https://<vault>/secrets/<name>?api-version=7.4)
    -GetSetting { param($Name) }               the RAW pim.Settings ValueJson ($null when absent)
    -SetSetting { param($Name, $Json) }        writes a pim.Settings value (already serialised)
    -RemoveSettingIf { param($Name, $Raw) }    deletes the row ONLY if it still holds exactly $Raw; returns the rows deleted
  PowerShell 7 only (.NET RSA SubjectPublicKeyInfo / PKCS#8 import + AesGcm). ASCII; no modules.
#>
Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------------- constants (literals)
function Get-PimShoVersion { <# PURE. LITERAL. The blob / key-record format version. #> return 1 }
function Get-PimShoAlg { <# PURE. LITERAL. #> return 'RSA-OAEP-256+A256GCM' }
function Get-PimShoKeySecretName { <# PURE. LITERAL. The vault secret holding the hand-over PRIVATE key. #> return 'pim-secret-handover-key' }
function Get-PimShoPublicKeySetting { <# PURE. LITERAL. pim.Settings: the published PUBLIC key. #> return 'SecretHandoverPublicKey' }
function Get-PimShoPendingSetting { <# PURE. LITERAL. pim.Settings: the ONE sealed blob waiting for the updater. #> return 'SecretHandoverPending' }
function Get-PimShoResultSetting { <# PURE. LITERAL. pim.Settings: the last hand-over's result (names only). #> return 'SecretHandoverResult' }
function Get-PimShoKvApi { <# PURE. LITERAL. #> return '7.4' }
function Get-PimShoMinUpdaterVersion { <# PURE. LITERAL. The first PIM Manager version whose updater takes the hand-over. #> return '3.1.56' }
function Get-PimShoKinds {
    <#
      PURE. LITERAL. THE ONLY kinds of value the hand-over carries, and the content type the updater writes the secret with.
      A blob of any other kind is REFUSED (a new kind is a rights decision, never silent).
    #>
    return [ordered]@{ 'smtp-relay-password' = 'PIM Manager SMTP relay password' }
}
function Get-PimShoKeyContentType { <# PURE. LITERAL. #> return 'PIM Manager secret hand-over key (RSA-3072, PKCS#8, private)' }

# ---------------------------------------------------------------------------------------------------------- small pure
function Get-PimShoField {
    <# PURE. A field of a hashtable or an object ($null when absent). #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimShoSha256 {
    <# PURE. Lower-case SHA-256 hex of UTF-8 text (for COMPARING a value; never printed, never recorded). #>
    param([AllowNull()][string]$Text)
    return (Get-PimShoHex -Bytes ([System.Text.Encoding]::UTF8.GetBytes("$Text")))
}

function Get-PimShoHex {
    <# PURE. Lower-case SHA-256 hex of bytes (.NET Core 3.1 and later: no SHA256.HashData / Convert.ToHexString). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([System.BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant()) } finally { $sha.Dispose() }
}

function Get-PimShoRandom {
    <# PURE (random). -Count cryptographically random bytes. #>
    param([Parameter(Mandatory)][int]$Count)
    $b = [byte[]]::new($Count); $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return , $b
}

function Get-PimShoKeyId {
    <# PURE. The key id of a public key: the first 16 hex characters of SHA-256 over its SubjectPublicKeyInfo bytes. #>
    param([Parameter(Mandatory)][string]$PublicKey)
    return (Get-PimShoHex -Bytes ([Convert]::FromBase64String("$PublicKey".Trim()))).Substring(0, 16)
}

function Get-PimShoAad {
    <# PURE. The GCM associated data: binds the kind, the vault (lower case), the secret name and the key id to the seal. #>
    param([string]$Kind, [string]$VaultName, [string]$SecretName, [string]$KeyId)
    return [System.Text.Encoding]::UTF8.GetBytes("pim-sho/$(Get-PimShoVersion)|$Kind|$("$VaultName".Trim().ToLowerInvariant())|$("$SecretName".Trim())|$("$KeyId".Trim().ToLowerInvariant())")
}

function Protect-PimShoText {
    <# PURE. A text with every one of -Values (the values this run holds) replaced by <withheld>; one line. #>
    param([AllowNull()][string]$Text, [AllowEmptyCollection()][string[]]$Values = @())
    $t = "$Text"
    foreach ($v in @($Values | Where-Object { "$_".Length -ge 1 } | Sort-Object { $_.Length } -Descending)) { $t = $t.Replace("$v", '<withheld>') }
    return (($t -replace '[\r\n\t]+', ' ').Trim())
}

function Test-PimShoSecretName { <# PURE. A Key Vault secret name. #> param([AllowEmptyString()][string]$Name) return ("$Name" -cmatch '^[0-9A-Za-z-]{1,127}$') }
function Test-PimShoVaultName { <# PURE. A Key Vault name. #> param([AllowEmptyString()][string]$Name) return ("$Name" -match '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') }

# ------------------------------------------------------------------------------------------------------------ the key
function New-PimShoKeyPair {
    <# PURE (random). A new RSA-3072 pair: @{ privateKey (PKCS#8 base64); publicKey (SubjectPublicKeyInfo base64); keyId }. #>
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    try {
        $pub = [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo())
        return @{ privateKey = [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey()); publicKey = $pub; keyId = (Get-PimShoKeyId -PublicKey $pub) }
    } finally { $rsa.Dispose() }
}

function Get-PimShoPublicFromPrivate {
    <# PURE. The public key (SubjectPublicKeyInfo base64) of a PKCS#8 private key (base64); THROWS when it is not one. #>
    param([Parameter(Mandatory)][string]$PrivateKey)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try { $rsa.ImportPkcs8PrivateKey([Convert]::FromBase64String("$PrivateKey".Trim()), [ref]$null); return [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo()) }
    finally { $rsa.Dispose() }
}

function New-PimShoPublicRecord {
    <# PURE. The pim.Settings 'SecretHandoverPublicKey' value for a public key of the install's vault. #>
    param([Parameter(Mandatory)][string]$PublicKey, [Parameter(Mandatory)][string]$VaultName, [string]$NowUtc = ([datetime]::UtcNow.ToString('o')))
    return [ordered]@{ v = (Get-PimShoVersion); alg = (Get-PimShoAlg); keyId = (Get-PimShoKeyId -PublicKey $PublicKey); publicKey = "$PublicKey".Trim()
                       vault = "$VaultName".Trim(); publishedUtc = $NowUtc; writer = 'updater' }
}

function Test-PimShoPublicRecord {
    <#
      PURE. Is a published key record usable for -VaultName? @{ ok; reason }. NEGATIVE: an absent record, another vault, a key
      id that does not match the key itself (a record edited by hand), an unknown version / algorithm.
    #>
    param([AllowNull()]$Record, [Parameter(Mandatory)][string]$VaultName)
    $minV = Get-PimShoMinUpdaterVersion
    if ($null -eq $Record -or -not "$(Get-PimShoField $Record 'publicKey')".Trim()) {
        return @{ ok = $false; reason = "this installation has published no hand-over key yet: its updater is older than $minV, or it has not run since it was updated (Update now in PIM Manager starts it)" }
    }
    if ("$(Get-PimShoField $Record 'v')" -ne "$(Get-PimShoVersion)" -or "$(Get-PimShoField $Record 'alg')" -ne (Get-PimShoAlg)) { return @{ ok = $false; reason = 'the published hand-over key has an unknown format' } }
    $kid = ''; try { $kid = Get-PimShoKeyId -PublicKey "$(Get-PimShoField $Record 'publicKey')" } catch { $kid = '' }
    if (-not $kid -or $kid -ne "$(Get-PimShoField $Record 'keyId')".Trim().ToLowerInvariant()) { return @{ ok = $false; reason = 'the published hand-over key does not match its key id -- refusing to seal to it' } }
    $rv = "$(Get-PimShoField $Record 'vault')".Trim()
    if ($rv -ine "$VaultName".Trim()) { return @{ ok = $false; reason = "the sealed hand-over writes only into this installation's own vault ($rv), not $VaultName" } }
    return @{ ok = $true; reason = '' }
}

# ---------------------------------------------------------------------------------------------------- seal / unseal
function Protect-PimShoValue {
    <#
      PURE (random). SEAL -Value for the install whose published key is -PublicKey. Returns the blob (an ordered hashtable;
      every byte field base64): v, alg, kind, vault, secret, keyId, reader, by, createdUtc, ek (the AES key wrapped with
      RSA-OAEP-SHA256), iv (12), ct, tag (16). The value is in it ONLY as AES-256-GCM cipher text.
    #>
    param([Parameter(Mandatory)][string]$PublicKey, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$VaultName,
          [Parameter(Mandatory)][string]$SecretName, [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
          [string]$Reader = '', [string]$By = '', [string]$NowUtc = ([datetime]::UtcNow.ToString('o')))
    if (-not (Get-PimShoKinds).Contains($Kind)) { throw "not a hand-over kind: $Kind" }
    if (-not (Test-PimShoVaultName $VaultName)) { throw "not a Key Vault name: $VaultName" }
    if (-not (Test-PimShoSecretName $SecretName)) { throw "not a Key Vault secret name: $SecretName" }
    if ($Value.Length -lt 1) { throw 'the value is empty' }
    $keyId = Get-PimShoKeyId -PublicKey $PublicKey
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $cek = Get-PimShoRandom -Count 32
    $iv = Get-PimShoRandom -Count 12
    $pt = [System.Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $rsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String("$PublicKey".Trim()), [ref]$null)
        $ek = $rsa.Encrypt($cek, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        $ct = [byte[]]::new($pt.Length); $tag = [byte[]]::new(16)
        $gcm = [System.Security.Cryptography.AesGcm]::new($cek)
        try { $gcm.Encrypt($iv, $pt, $ct, $tag, (Get-PimShoAad -Kind $Kind -VaultName $VaultName -SecretName $SecretName -KeyId $keyId)) } finally { $gcm.Dispose() }
    } finally { [Array]::Clear($pt, 0, $pt.Length); [Array]::Clear($cek, 0, $cek.Length); $rsa.Dispose() }
    return [ordered]@{ v = (Get-PimShoVersion); alg = (Get-PimShoAlg); kind = $Kind; vault = "$VaultName".Trim(); secret = "$SecretName".Trim(); keyId = $keyId
                       reader = "$Reader".Trim(); by = "$By".Trim(); createdUtc = $NowUtc
                       ek = [Convert]::ToBase64String($ek); iv = [Convert]::ToBase64String($iv); ct = [Convert]::ToBase64String($ct); tag = [Convert]::ToBase64String($tag) }
}

function Test-PimShoBlobNotPlain {
    <# PURE. NEGATIVE guard: the serialised blob carries the value neither as text nor as its base64 / UTF-8 base64. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json, [Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if (-not $Value) { return $true }
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value))
    return (-not $Json.Contains($Value) -and -not $Json.Contains($b64) -and -not $Json.Contains(($Value | ConvertTo-Json -Compress).Trim('"')))
}

function Test-PimShoBlobShape {
    <# PURE. The blob's form, before any key is touched: @{ ok; reason }. #>
    param([AllowNull()]$Blob)
    if ($null -eq $Blob) { return @{ ok = $false; reason = 'not a hand-over (empty)' } }
    if ("$(Get-PimShoField $Blob 'v')" -ne "$(Get-PimShoVersion)" -or "$(Get-PimShoField $Blob 'alg')" -ne (Get-PimShoAlg)) { return @{ ok = $false; reason = 'not a hand-over of a known format' } }
    $k = "$(Get-PimShoField $Blob 'kind')"
    if (-not (Get-PimShoKinds).Contains($k)) { return @{ ok = $false; reason = "the kind '$k' is not one the updater writes" } }
    if (-not (Test-PimShoVaultName "$(Get-PimShoField $Blob 'vault')")) { return @{ ok = $false; reason = 'not a Key Vault name in the hand-over' } }
    if (-not (Test-PimShoSecretName "$(Get-PimShoField $Blob 'secret')")) { return @{ ok = $false; reason = 'not a Key Vault secret name in the hand-over' } }
    if ("$(Get-PimShoField $Blob 'keyId')" -notmatch '^[0-9a-f]{16}$') { return @{ ok = $false; reason = 'no key id in the hand-over' } }
    $len = @{ ek = 384; iv = 12; tag = 16 }
    foreach ($f in 'ek', 'iv', 'ct', 'tag') {
        $b = $null; try { $b = [Convert]::FromBase64String("$(Get-PimShoField $Blob $f)") } catch { $b = $null }
        if ($null -eq $b -or $b.Length -lt 1) { return @{ ok = $false; reason = "the hand-over field '$f' is not base64" } }
        if ($len.Contains($f) -and $b.Length -ne $len[$f]) { return @{ ok = $false; reason = "the hand-over field '$f' has the wrong length" } }
    }
    return @{ ok = $true; reason = '' }
}

function Unprotect-PimShoValue {
    <#
      PURE. UNSEAL a blob with the install's PKCS#8 private key (base64). @{ ok; value; reason }. NEGATIVE: a wrong shape, a
      key id that is not this key's, an AES key that does not unwrap (sealed to another key), a tag that does not verify (ANY
      changed byte of ek / iv / ct / tag, or a changed kind / vault / secret / key id) -- all refused, no value returned.
    #>
    param([Parameter(Mandatory)][string]$PrivateKey, [AllowNull()]$Blob)
    $out = @{ ok = $false; value = $null; reason = '' }
    $sh = Test-PimShoBlobShape -Blob $Blob
    if (-not $sh.ok) { $out.reason = $sh.reason; return $out }
    $pub = ''; try { $pub = Get-PimShoPublicFromPrivate -PrivateKey $PrivateKey } catch { $out.reason = 'the installation''s hand-over key could not be read'; return $out }
    $kid = Get-PimShoKeyId -PublicKey $pub
    if ("$(Get-PimShoField $Blob 'keyId')" -ne $kid) { $out.reason = 'sealed to another key (not this installation''s current hand-over key) -- seal it again'; return $out }
    $rsa = [System.Security.Cryptography.RSA]::Create(); $cek = $null; $pt = $null
    try {
        $rsa.ImportPkcs8PrivateKey([Convert]::FromBase64String("$PrivateKey".Trim()), [ref]$null)
        try { $cek = $rsa.Decrypt([Convert]::FromBase64String("$(Get-PimShoField $Blob 'ek')"), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256) }
        catch { $out.reason = 'refused: the hand-over does not open with this installation''s key (tampered, or sealed elsewhere)'; return $out }
        $ct = [Convert]::FromBase64String("$(Get-PimShoField $Blob 'ct')")
        $pt = [byte[]]::new($ct.Length)
        $gcm = [System.Security.Cryptography.AesGcm]::new($cek)
        try {
            $gcm.Decrypt([Convert]::FromBase64String("$(Get-PimShoField $Blob 'iv')"), $ct, [Convert]::FromBase64String("$(Get-PimShoField $Blob 'tag')"), $pt,
                         (Get-PimShoAad -Kind "$(Get-PimShoField $Blob 'kind')" -VaultName "$(Get-PimShoField $Blob 'vault')" -SecretName "$(Get-PimShoField $Blob 'secret')" -KeyId $kid))
        } catch { $out.reason = 'refused: the hand-over was changed after it was sealed (its authentication tag does not match)'; return $out }
        finally { $gcm.Dispose() }
        $out.value = [System.Text.Encoding]::UTF8.GetString($pt)
        if ($out.value.Length -lt 1) { $out.value = $null; $out.reason = 'refused: the hand-over holds an empty value'; return $out }
        $out.ok = $true
        return $out
    } finally {
        if ($cek) { [Array]::Clear($cek, 0, $cek.Length) }
        if ($pt) { [Array]::Clear($pt, 0, $pt.Length) }
        $rsa.Dispose()
    }
}

function Test-PimShoTarget {
    <#
      PURE. May the updater write the hand-over into -SecretName? @{ ok; reason }. NEGATIVE: the hand-over key itself; a
      secret the Container Apps move owns (tag pim-moved-from); an existing secret of another content type (a different
      secret already has that name). An absent secret, or one of the kind's own content type (or none), is allowed.
    #>
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$SecretName, [AllowNull()]$Existing)
    if ("$SecretName" -ieq (Get-PimShoKeySecretName)) { return @{ ok = $false; reason = 'refused: the hand-over may never overwrite the hand-over key' } }
    if ($null -eq $Existing) { return @{ ok = $true; reason = '' } }
    $tags = Get-PimShoField $Existing 'tags'
    if ("$(Get-PimShoField $tags 'pim-moved-from')".Trim()) { return @{ ok = $false; reason = "refused: $SecretName holds a PIM app / job secret (moved from the Container Apps definition) -- the hand-over never overwrites it" } }
    $ctNow = "$(Get-PimShoField $Existing 'contentType')".Trim()
    $want = "$((Get-PimShoKinds)[$Kind])"
    if ($ctNow -and $ctNow -ne $want) { return @{ ok = $false; reason = "refused: a different secret already has the name $SecretName (content type '$ctNow')" } }
    return @{ ok = $true; reason = '' }
}

function Test-PimShoReaderHolds {
    <#
      PURE. Does -PrincipalId hold Key Vault Secrets User (or Officer) on the secret or ABOVE it at the vault (ARM role
      assignments read atScope() at <vault>/secrets/<name>)? $true / $false.
    #>
    param([AllowEmptyCollection()][object[]]$Assignments = @(), [Parameter(Mandatory)][string]$PrincipalId)
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $p = Get-PimShoField $a 'properties'
        if ("$(Get-PimShoField $p 'principalId')" -ine "$PrincipalId".Trim()) { continue }
        $rd = "$(Get-PimShoField $p 'roleDefinitionId')".ToLowerInvariant()
        if ($rd.EndsWith('/4633458b-17de-408a-b874-0445c86b69e6') -or $rd.EndsWith('/b86a8fe4-44ce-4948-aee5-eccb2c155cd7')) { return $true }
    }
    return $false
}

# ------------------------------------------------------------------------------------------------- the person's side
function Invoke-PimShoSubmit {
    <#
      THE PERSON'S STEP (Set-PimSmtpRelayPassword.ps1 -SqlServerFqdn). Reads the published key, seals -Value, writes ONLY the
      sealed blob to pim.Settings 'SecretHandoverPending' and reads it back. It has NO Key Vault seam: it cannot write a
      secret or ask for a Key Vault role. -PlanOnly (the script's -WhatIf): reads the key and returns the plan, writes nothing.
      Returns @{ ok; reason; keyId; written; replaced; setting }. The value is never returned.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SecretName,
          [AllowEmptyString()][string]$Value = '', [string]$Reader = '', [string]$By = '', [switch]$PlanOnly)
    $out = @{ ok = $false; reason = ''; keyId = ''; written = $false; replaced = $false; setting = (Get-PimShoPendingSetting) }
    $pubRaw = & $GetSetting (Get-PimShoPublicKeySetting)
    $pub = $null; if ("$pubRaw".Trim()) { try { $pub = "$pubRaw" | ConvertFrom-Json } catch { $pub = $null } }
    $chk = Test-PimShoPublicRecord -Record $pub -VaultName $VaultName
    if (-not $chk.ok) { $out.reason = $chk.reason; return $out }
    $out.keyId = "$($pub.keyId)"
    $prev = & $GetSetting (Get-PimShoPendingSetting)
    $out.replaced = [bool]"$prev".Trim()
    if ($PlanOnly) { $out.ok = $true; return $out }
    if (-not $Value) { $out.reason = 'the value is empty -- nothing was written'; return $out }
    $json = ''
    try { $json = ConvertTo-Json -Compress -Depth 4 -InputObject (Protect-PimShoValue -PublicKey "$($pub.publicKey)" -Kind $Kind -VaultName $VaultName -SecretName $SecretName -Value $Value -Reader $Reader -By $By) }
    catch { $out.reason = "could not seal the value: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($Value))"; return $out }
    if (-not (Test-PimShoBlobNotPlain -Json $json -Value $Value)) { $out.reason = 'REFUSED: the sealed hand-over would carry the value -- nothing was written'; return $out }
    try { & $SetSetting (Get-PimShoPendingSetting) $json } catch { $out.reason = "could not store the sealed hand-over: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($Value))"; return $out }
    $back = & $GetSetting (Get-PimShoPendingSetting)
    if ("$back" -cne $json) { $out.reason = 'the sealed hand-over was stored but did not read back the same -- run the command again'; return $out }
    $out.written = $true; $out.ok = $true
    return $out
}

# ------------------------------------------------------------------------------------------------- the updater's side
function Invoke-PimShoKvGet {
    <# A Key Vault GET through the seam; 404 / NotFound -> $null. Any other error throws. #>
    param([Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)][string]$Url)
    $res = $null; $err = $null
    try { $res = & $Kv 'GET' $Url $null } catch { $err = $_ }
    if ($err) { if ("$($err.Exception.Message)" -match '(?i)\b404\b|NotFound|SecretNotFound') { $res = $null } else { throw $err } }
    return $res
}

function Invoke-PimShoUpdaterStep {
    <#
      THE UPDATER'S STEP (update-job-entry.ps1 step 2f-ter-bis). (1) the install's hand-over key: read from the vault, or
      created + written + read back once; its public part published to pim.Settings. (2) the ONE pending blob, if any:
      unsealed, the target checked, written, read back (SHA-256), the previous value put back on a failed read-back, the blob
      compare-and-deleted, the result recorded (names only). Never assigns a role, never throws.
      Returns @{ state = ok | written | refused | failed | missing | unknown; how = updater | support-app; detail; lines[] (@{
      level = info|changed|warn; text }); result (the recorded SecretHandoverResult or $null) }.
        ok       the key is published, nothing was waiting
        written  a hand-over was written into the vault and read back; the blob was removed
        refused  a blob was refused (tampered, foreign key, other vault, wrong kind / target) and removed; the old secret kept
        failed   the write or its read-back failed; the old secret kept (put back), the blob KEPT for the next run
        missing  the updater may not use the vault's secrets (no Key Vault Secrets Officer): the Support app grants it once
        unknown  not read
    #>
    param([Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [Parameter(Mandatory)][scriptblock]$RemoveSettingIf, [Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$VaultUri,
          [scriptblock]$ReaderCheck = $null, [string]$GrantCommand = '', [string]$NowUtc = ([datetime]::UtcNow.ToString('o')))
    $out = [ordered]@{ state = 'unknown'; how = 'updater'; detail = ''; lines = ([System.Collections.Generic.List[object]]::new()); result = $null }
    $say = { param($lvl, $txt) $out.lines.Add([pscustomobject]@{ level = $lvl; text = $txt }) }
    $api = Get-PimShoKvApi; $base = "$VaultUri".TrimEnd('/')
    $keyUrl = "$base/secrets/$(Get-PimShoKeySecretName)?api-version=$api"
    $priv = $null; $plain = $null; $oldVal = $null
    try {
        # ---- (1) the key ---------------------------------------------------------------------------------------------
        $cur = $null
        try { $cur = Invoke-PimShoKvGet -Kv $Kv -Url $keyUrl }
        catch {
            $m = "$($_.Exception.Message)"
            if ($m -match '(?i)\b403\b|Forbidden') {
                $out.state = 'missing'; $out.how = 'support-app'
                $out.detail = "the updater may not use the secrets of $VaultName (Key Vault Secrets Officer is missing) -- the Support app grants it once$(if ($GrantCommand) { ": $GrantCommand" }); a waiting hand-over stays sealed until then"
                & $say 'warn' $out.detail; return $out
            }
            $out.detail = "the hand-over key was not read: $(Protect-PimShoText -Text $m)"; & $say 'warn' $out.detail; return $out
        }
        # A secret the Invardia Support app PRE-CREATED (tag pim-handover = placeholder, decision 15867370 option (a): the
        # updater's Secrets Officer is scoped to this one secret, so it cannot create it) is not a key yet: make one into it.
        $isPlaceholder = $cur -and ("$(Get-PimShoField (Get-PimShoField $cur 'tags') 'pim-handover')" -ieq 'placeholder')
        if ($cur -and -not $isPlaceholder -and "$(Get-PimShoField $cur 'value')".Trim()) {
            $priv = "$(Get-PimShoField $cur 'value')"
        } else {
            $kp = New-PimShoKeyPair
            [void](& $Kv 'PUT' $keyUrl @{ value = $kp.privateKey; contentType = (Get-PimShoKeyContentType); tags = @{ purpose = 'PIM Manager'; 'pim-handover' = 'key' } })
            $kb = & $Kv 'GET' $keyUrl $null
            if ((Get-PimShoSha256 "$(Get-PimShoField $kb 'value')") -ne (Get-PimShoSha256 $kp.privateKey)) { $out.detail = 'the new hand-over key did not read back -- nothing published'; & $say 'warn' $out.detail; return $out }
            $priv = $kp.privateKey; $kp = $null; $kb = $null
            & $say 'changed' "hand-over key created in $VaultName (secret $(Get-PimShoKeySecretName); only its public part leaves the vault)"
        }
        $pubKey = ''
        try { $pubKey = Get-PimShoPublicFromPrivate -PrivateKey $priv } catch { $out.detail = "the vault secret $(Get-PimShoKeySecretName) is not a hand-over key -- nothing published"; & $say 'warn' $out.detail; return $out }
        $rec = New-PimShoPublicRecord -PublicKey $pubKey -VaultName $VaultName -NowUtc $NowUtc
        $pubRaw = & $GetSetting (Get-PimShoPublicKeySetting)
        $pubNow = $null; if ("$pubRaw".Trim()) { try { $pubNow = "$pubRaw" | ConvertFrom-Json } catch { $pubNow = $null } }
        if (-not $pubNow -or "$($pubNow.keyId)" -ne $rec.keyId -or "$($pubNow.publicKey)" -ne $rec.publicKey -or "$($pubNow.vault)" -ine $VaultName) {
            & $SetSetting (Get-PimShoPublicKeySetting) (ConvertTo-Json -Compress -InputObject $rec)
            & $say 'changed' "hand-over key $($rec.keyId) published (pim.Settings $(Get-PimShoPublicKeySetting))"
        }
        # ---- (2) the pending blob --------------------------------------------------------------------------------------
        $raw = & $GetSetting (Get-PimShoPendingSetting)
        if (-not "$raw".Trim()) { $out.state = 'ok'; $out.detail = "hand-over key $($rec.keyId) published; no sealed hand-over waiting"; & $say 'info' $out.detail; return $out }
        $blob = $null; try { $blob = "$raw" | ConvertFrom-Json } catch { $blob = $null }
        $kind = "$(Get-PimShoField $blob 'kind')"; $sec = "$(Get-PimShoField $blob 'secret')"; $reader = "$(Get-PimShoField $blob 'reader')".Trim()
        $record = { param($state, $detail, $canRead)
            $r = [ordered]@{ state = $state; kind = $kind; vault = $VaultName; secret = $sec; keyId = $rec.keyId; utc = $NowUtc; detail = (Protect-PimShoText -Text $detail -Values @($plain, $oldVal)); engineCanRead = $canRead }
            try { & $SetSetting (Get-PimShoResultSetting) (ConvertTo-Json -Compress -InputObject $r) } catch { & $say 'warn' "the hand-over result could not be recorded: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($plain, $oldVal))" }
            $out.result = $r }
        $refuse = { param($why)
            $gone = 0; try { $gone = [int](& $RemoveSettingIf (Get-PimShoPendingSetting) "$raw") } catch { $gone = 0 }
            $out.state = 'refused'; $out.detail = "sealed hand-over REFUSED and $(if ($gone) { 'removed' } else { 'NOT removed (it changed meanwhile)' }): $why -- nothing was written, the old secret is kept"
            & $say 'warn' $out.detail; & $record 'refused' $why $null }
        if ($null -eq $blob) { & $refuse 'not a hand-over (not JSON)'; return $out }
        if ("$(Get-PimShoField $blob 'vault')" -ine $VaultName) { & $refuse "sealed for the vault '$(Get-PimShoField $blob 'vault')'; this installation's updater writes only into its own vault $VaultName"; return $out }
        $un = Unprotect-PimShoValue -PrivateKey $priv -Blob $blob
        if (-not $un.ok) { & $refuse $un.reason; return $out }
        $plain = "$($un.value)"; $un.value = $null
        $secUrl = "$base/secrets/$sec`?api-version=$api"
        $existing = $null
        try { $existing = Invoke-PimShoKvGet -Kv $Kv -Url $secUrl }
        catch { $why = "the secret $sec was not read: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($plain))"; $out.state = 'failed'; $out.detail = "$why -- the hand-over is kept for the next run"; & $say 'warn' $out.detail; & $record 'failed' $why $null; return $out }
        $tg = Test-PimShoTarget -Kind $kind -SecretName $sec -Existing $existing
        if (-not $tg.ok) { & $refuse $tg.reason; return $out }
        if ($existing) { $oldVal = "$(Get-PimShoField $existing 'value')" }
        $want = Get-PimShoSha256 $plain
        $action = 'written'
        if ($null -ne $oldVal -and (Get-PimShoSha256 $oldVal) -eq $want) { $action = 'unchanged' }
        else {
            try { [void](& $Kv 'PUT' $secUrl @{ value = $plain; contentType = "$((Get-PimShoKinds)[$kind])"; tags = @{ purpose = 'PIM Manager'; 'pim-handover' = 'updater' } }) }
            catch {
                $why = "Key Vault refused the write of $sec`: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($plain, $oldVal))"
                $out.state = 'failed'; $out.detail = "$why -- the old secret is unchanged; the hand-over is kept for the next run"; & $say 'warn' $out.detail; & $record 'failed' $why $null; return $out
            }
        }
        $back = $null; try { $back = & $Kv 'GET' $secUrl $null } catch { $back = $null }
        if ((Get-PimShoSha256 "$(Get-PimShoField $back 'value')") -ne $want) {
            $undo = 'there was no previous value'
            if ($null -ne $oldVal) {
                try { [void](& $Kv 'PUT' $secUrl @{ value = $oldVal; contentType = "$((Get-PimShoKinds)[$kind])"; tags = @{ purpose = 'PIM Manager'; 'pim-handover' = 'put-back' } }); $undo = 'the previous value was put back' }
                catch { $undo = 'the previous value could NOT be put back -- set the previous version current in Key Vault' }
            }
            $why = "the secret $sec did not read back the handed-over value (compared by SHA-256); $undo"
            $out.state = 'failed'; $out.detail = "$why -- the hand-over is kept for the next run"; & $say 'warn' $out.detail; & $record 'failed' $why $null; return $out
        }
        $back = $null
        $gone = 0; try { $gone = [int](& $RemoveSettingIf (Get-PimShoPendingSetting) "$raw") } catch { $gone = 0 }
        $canRead = $null
        if ($reader -and $ReaderCheck) { try { $canRead = & $ReaderCheck $reader $sec } catch { $canRead = $null } }
        $readTxt = switch ($canRead) { $true { "the engine identity $reader may read it" } $false { "the engine identity $reader may NOT read it yet: give it 'Key Vault Secrets User' on that secret (an Owner, or the Invardia Support app) -- the updater never assigns a role" } default { 'whether the engine identity may read it was not checked' } }
        $out.state = 'written'
        $out.detail = "sealed hand-over $(if ($action -eq 'unchanged') { 'matched the value already in' } else { 'written into' }) $VaultName/$sec and read back (the value was not printed); the sealed copy $(if ($gone) { 'was deleted' } else { 'was NOT deleted (a newer one arrived; the next run takes it)' }); $readTxt"
        & $say $(if ($canRead -eq $false) { 'warn' } else { 'changed' }) $out.detail
        & $record 'written' "$action; sealed copy $(if ($gone) { 'deleted' } else { 'kept (a newer one arrived)' })" $canRead
        return $out
    } catch {
        $out.state = 'unknown'; $out.detail = "the hand-over step stopped: $(Protect-PimShoText -Text "$($_.Exception.Message)" -Values @($plain, $oldVal, $priv))"
        & $say 'warn' $out.detail; return $out
    } finally { $priv = $null; $plain = $null; $oldVal = $null }
}
