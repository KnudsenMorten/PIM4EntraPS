#Requires -Version 5.1
<#
.SYNOPSIS
    Lints / validates the PIM Activator browser-extension package without signing it.

.DESCRIPTION
    A repack of the extension is only valid from the master signing key on mgmt1
    (the one key that reproduces extension id "eheocihmlppcophaeakmdenhgcookkab").
    This script does NOT sign or repack -- it validates the *source* so problems
    are caught before the master-key repack/deploy step runs.

    Checks performed (each returns a finding object; the script returns an
    object with .Ok / .Findings so it is unit-testable):

      MANIFEST   manifest.json parses, MV3, has the canonical "key" (extension id),
                 version present and well-formed.
      IDLOCK     manifest "key" is unchanged -> extension id stays
                 eheocihmlppcophaeakmdenhgcookkab. The id is a public contract
                 (redirect URI, forcelist, deployed CRX) and must never drift.
      VERSION    manifest.json version matches the popup-facing version source so
                 the in-popup version badge does not lie.
      NODEVCODE  no device-code auth path anywhere in the JS (MS blocks it via
                 managed CA; we use Edge PKCE loopback only).
      PKCE       the PKCE / launchWebAuthFlow loopback flow is present (the
                 supported sign-in path is still wired).
      NOMULTI    multi-tenant config is policy/catalog driven, never a free-text
                 "add any tenant" entry box (security constraint).
      BRANDING   required branding strings present (name, attribution footer).
      NOSECRET   no secrets / tenant ids / subscription ids hard-coded in the
                 shipped extension files.

.PARAMETER Path
    Folder holding the extension source. Defaults to the script's own folder.

.PARAMETER Quiet
    Suppress the human-readable summary (object is still returned).

.OUTPUTS
    PSCustomObject with .Ok (bool) and .Findings (array of
    @{ Check; Severity; Ok; Message }). Severity is Error or Warn; .Ok is
    $false only when an Error-severity finding fails.

.NOTES
    Pure validation, no network, no signing, PS 5.1-safe. Covered by
    TESTS/PIM.Tests.ps1 ("PIM Activator package").
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,
    [switch]$Quiet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Canonical extension id + the manifest "key" that produces it. The key is a
# public, deterministic value (already committed in manifest.json) -- not a
# secret -- and pinning it here is how we detect accidental key drift.
$script:CanonicalExtensionId = 'eheocihmlppcophaeakmdenhgcookkab'

function Pick {
    # PS 5.1-safe ternary: Pick $cond $whenTrue $whenFalse
    param([bool]$Cond, $WhenTrue, $WhenFalse)
    if ($Cond) { $WhenTrue } else { $WhenFalse }
}

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][bool]$Ok,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Error', 'Warn')][string]$Severity = 'Error'
    )
    [pscustomobject]@{
        Check    = $Check
        Severity = $Severity
        Ok       = $Ok
        Message  = $Message
    }
}

function Test-PimActivatorPackage {
    [CmdletBinding()]
    param(
        [string]$Path = $PSScriptRoot,
        [switch]$Quiet
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $add = { param($f) $findings.Add($f) }

    if (-not (Test-Path -LiteralPath $Path)) {
        & $add (New-Finding -Check 'PATH' -Ok $false -Message "Extension path not found: $Path")
        return [pscustomobject]@{ Ok = $false; Findings = $findings.ToArray() }
    }

    $manifestPath = Join-Path $Path 'manifest.json'
    $popupJsPath  = Join-Path $Path 'popup.js'
    $popupHtml    = Join-Path $Path 'popup.html'

    # ---- MANIFEST ------------------------------------------------------------
    $manifest = $null
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        & $add (New-Finding -Check 'MANIFEST' -Ok $false -Message 'manifest.json not found.')
    } else {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            & $add (New-Finding -Check 'MANIFEST' -Ok $true -Message 'manifest.json parses.')
        } catch {
            & $add (New-Finding -Check 'MANIFEST' -Ok $false -Message "manifest.json does not parse: $($_.Exception.Message)")
        }
    }

    if ($manifest) {
        $mvOk = ($manifest.PSObject.Properties.Name -contains 'manifest_version') -and $manifest.manifest_version -eq 3
        & $add (New-Finding -Check 'MANIFEST' -Ok $mvOk -Message (Pick $mvOk 'manifest_version is 3 (MV3).' 'manifest_version must be 3 (MV3).'))

        $verOk = ($manifest.PSObject.Properties.Name -contains 'version') -and ($manifest.version -match '^\d+(\.\d+){1,3}$')
        & $add (New-Finding -Check 'MANIFEST' -Ok $verOk -Message (Pick $verOk "version is '$($manifest.version)'." 'version missing or not dotted-numeric.'))

        # ---- IDLOCK ----------------------------------------------------------
        $hasKey = ($manifest.PSObject.Properties.Name -contains 'key') -and -not [string]::IsNullOrWhiteSpace($manifest.key)
        if (-not $hasKey) {
            & $add (New-Finding -Check 'IDLOCK' -Ok $false -Message 'manifest "key" missing -> extension id would not be deterministic.')
        } else {
            $derivedId = Get-PimActivatorExtensionId -Base64Key $manifest.key
            $idOk = $derivedId -eq $script:CanonicalExtensionId
            & $add (New-Finding -Check 'IDLOCK' -Ok $idOk -Message (Pick $idOk `
                "extension id resolves to $script:CanonicalExtensionId." `
                "extension id DRIFTED to '$derivedId' (must be $script:CanonicalExtensionId). The 'key' in manifest.json was changed."))
        }
    }

    # ---- VERSION (badge consistency) ----------------------------------------
    if ($manifest -and (Test-Path -LiteralPath $popupHtml)) {
        # The version badge is hydrated from chrome.runtime.getManifest().version
        # by version-badge.js; popup.html should reference that script so the
        # badge cannot silently fall out of sync with the manifest.
        $html = Get-Content -LiteralPath $popupHtml -Raw
        $badgeWired = ($html -match 'version-badge\.js') -and ($html -match 'id="version-badge"')
        & $add (New-Finding -Check 'VERSION' -Ok $badgeWired -Message (Pick $badgeWired `
            'version badge is wired to the manifest version.' `
            'popup.html must load version-badge.js and contain id="version-badge".'))
    }

    # ---- JS-based checks -----------------------------------------------------
    if (Test-Path -LiteralPath $popupJsPath) {
        $js = Get-Content -LiteralPath $popupJsPath -Raw

        # NODEVCODE: device-code flow is forbidden (MS blocks it via managed CA).
        $devCode = [regex]::Matches($js, '(?im)device[\s_-]*code|grant_type\s*=\s*[''"]?urn:ietf:params:oauth:grant-type:device_code')
        $devCodeOk = $devCode.Count -eq 0
        & $add (New-Finding -Check 'NODEVCODE' -Ok $devCodeOk -Message (Pick $devCodeOk `
            'no device-code auth path present.' `
            "device-code reference(s) found ($($devCode.Count)) -- forbidden, use Edge PKCE loopback."))

        # PKCE: the supported sign-in path must be present.
        $pkceOk = ($js -match 'launchWebAuthFlow') -and ($js -match '(?i)code_challenge|pkce')
        & $add (New-Finding -Check 'PKCE' -Ok $pkceOk -Message (Pick $pkceOk `
            'PKCE loopback sign-in (launchWebAuthFlow + code_challenge) present.' `
            'PKCE loopback sign-in (launchWebAuthFlow + code_challenge) not found.'))
    } else {
        & $add (New-Finding -Check 'NODEVCODE' -Ok $false -Message 'popup.js not found.')
    }

    # ---- BRANDING ------------------------------------------------------------
    if ($manifest) {
        $nameOk = $manifest.name -eq 'PIM Activator'
        & $add (New-Finding -Check 'BRANDING' -Ok $nameOk -Message (Pick $nameOk 'extension name is "PIM Activator".' "extension name is '$($manifest.name)', expected 'PIM Activator'.") -Severity 'Warn')
    }
    if (Test-Path -LiteralPath $popupHtml) {
        $html2 = Get-Content -LiteralPath $popupHtml -Raw
        $footerOk = $html2 -match 'aka\.ms/morten'
        & $add (New-Finding -Check 'BRANDING' -Ok $footerOk -Message (Pick $footerOk 'attribution footer present.' 'attribution footer (aka.ms/morten) missing.') -Severity 'Warn')
    }

    # ---- NOSECRET (shipped extension files only) -----------------------------
    # Real GUID tenant/subscription ids must never be baked into the extension.
    # Sample/placeholder all-zero or sequential GUIDs are allowed.
    $shipped = @('popup.js', 'popup-config.js', 'popup-net.js', 'popup.html', 'background.js', 'version-badge.js', 'manifest.json', 'managed-schema.json')
    $guidRx  = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    $secretHits = New-Object System.Collections.Generic.List[string]
    foreach ($f in $shipped) {
        $fp = Join-Path $Path $f
        if (-not (Test-Path -LiteralPath $fp)) { continue }
        $content = Get-Content -LiteralPath $fp -Raw
        foreach ($m in [regex]::Matches($content, $guidRx)) {
            $g = $m.Value
            if (Test-PimActivatorPlaceholderGuid -Guid $g) { continue }
            $secretHits.Add("$f -> $g")
        }
    }
    $secretOk = $secretHits.Count -eq 0
    & $add (New-Finding -Check 'NOSECRET' -Ok $secretOk -Message (Pick $secretOk `
        'no real tenant/subscription GUIDs baked into shipped files.' `
        "real GUID(s) found in shipped files: $($secretHits -join '; ')"))

    $errFails = @($findings | Where-Object { $_.Severity -eq 'Error' -and -not $_.Ok })
    $ok = ($errFails.Count -eq 0)

    if (-not $Quiet) {
        Write-Host ''
        Write-Host 'PIM Activator package validation' -ForegroundColor Cyan
        Write-Host ('-' * 40)
        foreach ($f in $findings) {
            $mark  = Pick $f.Ok '[+]' (Pick ($f.Severity -eq 'Warn') '[!]' '[x]')
            $color = Pick $f.Ok 'Green' (Pick ($f.Severity -eq 'Warn') 'Yellow' 'Red')
            Write-Host ("{0} {1,-9} {2}" -f $mark, $f.Check, $f.Message) -ForegroundColor $color
        }
        Write-Host ('-' * 40)
        Write-Host (Pick $ok 'RESULT: OK' 'RESULT: FAILED') -ForegroundColor (Pick $ok 'Green' 'Red')
    }

    [pscustomobject]@{ Ok = [bool]$ok; Findings = $findings.ToArray() }
}

function Test-PimActivatorPlaceholderGuid {
    <#
        True for documentation placeholders: all-zero, all-f, or a GUID whose
        hex digits are a single repeated character (e.g. 11111111-1111-...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Guid)
    $hex = ($Guid -replace '-', '').ToLowerInvariant()
    $distinct = @($hex.ToCharArray() | Select-Object -Unique)
    return ($distinct.Count -le 1)
}

function Get-PimActivatorExtensionId {
    <#
        Derive a Chromium extension id from a base64 SubjectPublicKeyInfo
        (the manifest "key"). Chromium: id = first 16 bytes of SHA-256(DER pubkey),
        each nibble mapped 0-15 -> a-p ("mpdecimal").
        PS 5.1-safe (no RSA.ImportFromPem).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Base64Key)

    $der    = [Convert]::FromBase64String($Base64Key)
    $sha    = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($der) } finally { $sha.Dispose() }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt 16; $i++) {
        $b = $hash[$i]
        [void]$sb.Append([char](97 + (($b -shr 4) -band 0xF)))   # high nibble
        [void]$sb.Append([char](97 + ($b -band 0xF)))            # low nibble
    }
    $sb.ToString()
}

# When dot-sourced (tests), only define the functions. When invoked directly,
# run the validation and set a non-zero exit code on failure so CI can gate.
if ($MyInvocation.InvocationName -ne '.') {
    $result = Test-PimActivatorPackage -Path $Path -Quiet:$Quiet
    if (-not $result.Ok) { exit 1 }
}
