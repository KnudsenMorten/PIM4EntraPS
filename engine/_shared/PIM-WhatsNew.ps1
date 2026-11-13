# =================================================================================================
# PIM-WhatsNew.ps1 -- What's new (framework WHATS-NEW-1, owner 2026-11-13: "all solutions have a whats new which is human
# friendly info from release notes" / "all must have same"). The Manager serves, READ-ONLY:
#   * the release files SHIPPED with this version: whats-new/<version>.json (one per release, the format of Invardia's
#     tools/whatsnew/whats-new.schema.json) -> GET /api/whats-new, every signed-in role;
#   * Invardia's ONE shared renderer, embedded UNCHANGED: tools/pim-manager/whatsnew/whats-new.js + whats-new.css ->
#     GET /app/whats-new/<file> (the page imports the module and links the style sheet).
# Nothing here writes. The files never change while the Manager runs, so the answer is read once and kept.
# PS 5.1 parses this file.
# =================================================================================================

Set-StrictMode -Off

function Get-PimWhatsNewAssetTypes {
    # the ONLY files GET /app/whats-new/<file> serves, with their content type (a fixed list, never a path)
    return @{ 'whats-new.js' = 'text/javascript; charset=utf-8'; 'whats-new.css' = 'text/css; charset=utf-8' }
}

function Get-PimWhatsNewDir {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$SolutionRoot)
    return (Join-Path $SolutionRoot 'whats-new')
}

function Get-PimWhatsNewAssetDir {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$SolutionRoot)
    return (Join-Path $SolutionRoot 'tools\pim-manager\whatsnew')
}

function Get-PimWhatsNewAnswer {
    <#
      The body of GET /api/whats-new as a JSON TEXT: {"ok":true,"version":"<running>","count":N,"files":[<file>,...]}. Each
      file is passed through as it is on disk (never re-serialised, so the words are exactly the shipped ones); a file whose
      name is not <version>.json or that is not JSON is left out (the renderer also leaves out any file that fails the
      schema). Kept per folder after the first read: the shipped folder does not change while the Manager runs.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir, [string]$Version = '', [switch]$NoCache)
    if ($null -eq $script:PimWhatsNewCache) { $script:PimWhatsNewCache = @{} }
    $key = "$Dir|$Version"
    if (-not $NoCache -and $script:PimWhatsNewCache.ContainsKey($key)) { return $script:PimWhatsNewCache[$key] }
    $parts = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $Dir -PathType Container) {
        foreach ($f in @(Get-ChildItem -LiteralPath $Dir -File -Filter '*.json' | Sort-Object Name)) {
            if ($f.Name -notmatch '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?\.json$') { continue }
            $t = ([IO.File]::ReadAllText($f.FullName)).TrimStart([char]0xFEFF).Trim()
            try { $null = $t | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if (-not $t.StartsWith('{')) { continue }
            $parts.Add($t)
        }
    }
    $verJson = ConvertTo-Json -InputObject ("$Version") -Compress
    $json = '{"ok":true,"version":' + $verJson + ',"count":' + $parts.Count + ',"files":[' + ($parts.ToArray() -join ',') + ']}'
    if (-not $NoCache) { $script:PimWhatsNewCache[$key] = $json }
    return $json
}

function Get-PimWhatsNewAsset {
    <#
      One file of the shared renderer: @{ ok; bytes; contentType; error }. ONLY whats-new.js and whats-new.css -- a name is
      looked up in a fixed list, never used as a path, so no request reads anything else.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$AssetDir, [AllowEmptyString()][string]$Name)
    $types = Get-PimWhatsNewAssetTypes
    if (-not $types.ContainsKey("$Name")) { return @{ ok = $false; error = 'not found' } }
    $p = Join-Path $AssetDir "$Name"
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ ok = $false; error = 'not found' } }
    $item = Get-Item -LiteralPath $p
    return @{ ok = $true; bytes = [IO.File]::ReadAllBytes($item.FullName); contentType = $types["$Name"]; error = '' }
}
