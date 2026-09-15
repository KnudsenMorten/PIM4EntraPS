#Requires -Version 5.1
<#
  PIM-MailTemplateStore.ps1 -- ONE mail template store, in SQL (operator decision 2026-09-13).

  pim.Settings['MailTemplates'] holds every mail template ONCE:
    { "templates": { "<type>": { "body": "<html>", "source": "shipped" | "edited",
                                 "shippedHash": "<sha256 of the shipped body it came from>",
                                 "updatedUtc": "...", "updatedBy": "..." } },
      "legacyOverridesMergedUtc": "..." }

  * The shipped templates (templates/mail/<type>.mailtemplate.html) SEED the store and are the
    default a reset returns to. An entry still 'shipped' follows a newer shipped body on the next
    Update-PimMailTemplateStore; an 'edited' entry is kept.
  * The Manager's edits write the SAME store (Set-PimMailTemplateStoreEntry /
    Reset-PimMailTemplateStoreEntry). The engine reads it at send time (Get-PimMailTemplateEffective).
  * REMOVED: the separate override layer pim.Settings['MailTemplateOverrides'] and the file
    override <type>.mailtemplate.custom.html. Existing MailTemplateOverrides values are merged into
    the store ONCE by Update-PimMailTemplateStore -- additively (an entry already edited in the store
    is never overwritten) and audited -- and the override setting is not read after that.

  PS 5.1-safe. ASCII only (no BOM).
#>
Set-StrictMode -Off

function Get-PimMailTemplateStoreName { 'MailTemplates' }
function Get-PimMailTemplateLegacyOverrideName { 'MailTemplateOverrides' }

function Get-PimMailTemplateHash {
    # SHA-256 of the body with line endings normalised, so a CRLF/LF difference is not "a change".
    param([AllowEmptyString()][string]$Text)
    $norm = ("$Text" -replace "`r`n", "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($norm)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-PimShippedMailTemplateDir {
    if ("$($global:PIM_MailTemplateDir)".Trim()) { return "$($global:PIM_MailTemplateDir)" }
    if ($PSScriptRoot) { return (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'templates\mail') }
    return $null
}

function Read-PimShippedMailTemplates {
    # type -> shipped body (hashtable). Missing directory -> empty.
    param([string]$TemplateDir)
    if (-not "$TemplateDir".Trim()) { $TemplateDir = Get-PimShippedMailTemplateDir }
    $out = @{}
    if (-not $TemplateDir -or -not (Test-Path -LiteralPath $TemplateDir)) { return $out }
    foreach ($f in @(Get-ChildItem -LiteralPath $TemplateDir -Filter '*.mailtemplate.html' -File -ErrorAction SilentlyContinue)) {
        # A leftover <type>.mailtemplate.custom.html is NOT a shipped template (and is never read).
        if ($f.Name -match '\.mailtemplate\.custom\.html$') { continue }
        $type = $f.Name -replace '\.mailtemplate\.html$', ''
        $out[$type] = [System.IO.File]::ReadAllText($f.FullName, (New-Object System.Text.UTF8Encoding($false)))
        if ($out[$type].Length -gt 0 -and [int][char]$out[$type][0] -eq 0xFEFF) { $out[$type] = $out[$type].Substring(1) }
    }
    return $out
}

function Get-PimMailTemplateField {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    if ($Obj.PSObject) { $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value } }
    return $null
}

function ConvertTo-PimMailTemplateStoreDocument {
    # Normalise a stored value (JSON text, parsed object or dictionary) to
    # @{ templates = @{ <type> = [ordered]@{ body; source; shippedHash; updatedUtc; updatedBy } }; legacyOverridesMergedUtc }
    param([object]$Value)
    $doc = @{ templates = @{}; legacyOverridesMergedUtc = '' }
    if ($null -eq $Value) { return $doc }
    if ($Value -is [string]) {
        if (-not "$Value".Trim()) { return $doc }
        try { $Value = $Value | ConvertFrom-Json } catch { return $doc }
        if ($Value -is [string]) { try { $Value = $Value | ConvertFrom-Json } catch { return $doc } }
    }
    $doc.legacyOverridesMergedUtc = "$(Get-PimMailTemplateField $Value 'legacyOverridesMergedUtc')"
    $tpls = Get-PimMailTemplateField $Value 'templates'
    if ($null -eq $tpls) { return $doc }
    $names = if ($tpls -is [System.Collections.IDictionary]) { @($tpls.Keys) } else { @($tpls.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $e = Get-PimMailTemplateField $tpls $n
        $body = "$(Get-PimMailTemplateField $e 'body')"
        if (-not $body.Trim()) { continue }
        $src = "$(Get-PimMailTemplateField $e 'source')".Trim(); if ($src -ne 'edited') { $src = 'shipped' }
        $doc.templates["$n"] = [ordered]@{
            body = $body; source = $src
            shippedHash = "$(Get-PimMailTemplateField $e 'shippedHash')"
            updatedUtc  = "$(Get-PimMailTemplateField $e 'updatedUtc')"
            updatedBy   = "$(Get-PimMailTemplateField $e 'updatedBy')"
        }
    }
    return $doc
}

function Get-PimMailTemplateStoreDocument {
    <#
      The store document. -ConnectionString reads SQL directly; otherwise the Get-PimSetting bridge
      (Manager / scheduler) is asked, else the value hydrated into $global:PIM_NamingConventions at
      process start. Never throws; nothing stored -> an empty document.
    #>
    param([string]$ConnectionString)
    $raw = $null
    try {
        if ("$ConnectionString".Trim() -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $raw = Get-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimMailTemplateStoreName)
        } elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
            $raw = Get-PimSetting -Name (Get-PimMailTemplateStoreName)
        } elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains((Get-PimMailTemplateStoreName))) {
            $raw = $global:PIM_NamingConventions[(Get-PimMailTemplateStoreName)]
        }
    } catch { Write-Warning "  [mail-templates] store read failed: $($_.Exception.Message)"; $raw = $null }
    return (ConvertTo-PimMailTemplateStoreDocument $raw)
}

function Save-PimMailTemplateStoreDocument {
    # Persist the document. THROWS when there is no store or it rejects the write (SQL-only).
    param([Parameter(Mandatory)][hashtable]$Document, [string]$ConnectionString)
    $value = [ordered]@{ templates = $Document.templates; legacyOverridesMergedUtc = "$($Document.legacyOverridesMergedUtc)" }
    if ("$ConnectionString".Trim() -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        Set-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimMailTemplateStoreName) -Value $value
    } elseif (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        Set-PimSetting -Name (Get-PimMailTemplateStoreName) -Value $value | Out-Null
    } else {
        throw 'no SQL store is wired -- mail templates live in SQL pim.Settings[''MailTemplates''] only (PIM v2 is SQL-only)'
    }
    # Keep this process's hydrated copy in step, so a send in the same process sees the change.
    if (-not ($global:PIM_NamingConventions -is [System.Collections.IDictionary])) { $global:PIM_NamingConventions = @{} }
    $global:PIM_NamingConventions[(Get-PimMailTemplateStoreName)] = $value
}

function Write-PimMailTemplateAudit {
    param([string]$ConnectionString, [string]$Action, [string]$Target, [object]$After, [string]$Actor = 'engine')
    try {
        if ("$ConnectionString".Trim() -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'mail-template-store' -Action $Action -Target $Target -After $After | Out-Null
            return $true
        }
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action $Action -Target $Target -After $After -Actor $Actor | Out-Null
            return $true
        }
    } catch { Write-Warning "  [mail-templates] audit write failed for '$Action': $($_.Exception.Message)" }
    return $false
}

function Update-PimMailTemplateStore {
    <#
      Seed + upgrade + one-time legacy merge. Idempotent.
        * a shipped type missing from the store  -> seeded (source 'shipped')
        * a 'shipped' entry whose shipped body changed -> upgraded to the new shipped body
        * an 'edited' entry                       -> kept
        * legacy pim.Settings['MailTemplateOverrides'] (read ONLY here, ONLY until merged): each
          non-empty override becomes an 'edited' entry, unless the store already holds an 'edited'
          entry for that type (additive -- never overwrites a newer store edit). The merge is audited
          and stamped (legacyOverridesMergedUtc), so it runs once.
      Returns @{ count; seeded; upgraded; kept; merged; mergedTypes; reason }.
    #>
    param([string]$ConnectionString, [string]$TemplateDir, [string]$Actor = 'engine')
    $doc = Get-PimMailTemplateStoreDocument -ConnectionString $ConnectionString
    $shipped = Read-PimShippedMailTemplates -TemplateDir $TemplateDir
    $now = [datetime]::UtcNow.ToString('o')
    $seeded = 0; $upgraded = 0; $kept = 0
    foreach ($type in @($shipped.Keys | Sort-Object)) {
        $h = Get-PimMailTemplateHash -Text $shipped[$type]
        $cur = $doc.templates[$type]
        if ($null -eq $cur) {
            $doc.templates[$type] = [ordered]@{ body = $shipped[$type]; source = 'shipped'; shippedHash = $h; updatedUtc = $now; updatedBy = 'shipped' }
            $seeded++
        } elseif ($cur.source -eq 'shipped') {
            if ($cur.shippedHash -ne $h) {
                $doc.templates[$type] = [ordered]@{ body = $shipped[$type]; source = 'shipped'; shippedHash = $h; updatedUtc = $now; updatedBy = 'shipped' }
                $upgraded++
            }
        } else { $kept++ }
    }
    $merged = 0; $mergedTypes = @()
    if (-not "$($doc.legacyOverridesMergedUtc)".Trim()) {
        $legacy = $null
        try {
            if ("$ConnectionString".Trim() -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
                $legacy = Get-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimMailTemplateLegacyOverrideName)
            } elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
                $legacy = Get-PimSetting -Name (Get-PimMailTemplateLegacyOverrideName)
            }
        } catch { throw "the legacy MailTemplateOverrides setting could not be read, so it was NOT merged (retry): $($_.Exception.Message)" }
        if ($legacy -is [string]) { if ("$legacy".Trim()) { try { $legacy = $legacy | ConvertFrom-Json } catch { $legacy = $null } } else { $legacy = $null } }
        if ($null -ne $legacy) {
            $names = if ($legacy -is [System.Collections.IDictionary]) { @($legacy.Keys) } else { @($legacy.PSObject.Properties | ForEach-Object { $_.Name }) }
            foreach ($type in $names) {
                $body = "$(Get-PimMailTemplateField $legacy $type)"
                if (-not $body.Trim()) { continue }
                $cur = $doc.templates["$type"]
                if ($null -ne $cur -and $cur.source -eq 'edited') { continue }   # additive: a store edit wins
                $sh = if ($shipped.ContainsKey("$type")) { Get-PimMailTemplateHash -Text $shipped["$type"] } else { '' }
                $doc.templates["$type"] = [ordered]@{ body = $body; source = 'edited'; shippedHash = $sh; updatedUtc = $now; updatedBy = 'merged from MailTemplateOverrides' }
                $merged++; $mergedTypes += "$type"
            }
        }
        $doc.legacyOverridesMergedUtc = $now
    }
    $changed = ($seeded -or $upgraded -or $merged -or ($doc.legacyOverridesMergedUtc -eq $now))
    if ($changed) { Save-PimMailTemplateStoreDocument -Document $doc -ConnectionString $ConnectionString }
    if ($merged) {
        [void](Write-PimMailTemplateAudit -ConnectionString $ConnectionString -Action 'mailtemplate.legacy-overrides.merged' -Target 'MailTemplates' -Actor $Actor `
            -After ([ordered]@{ merged = $merged; types = @($mergedTypes); note = 'MailTemplateOverrides merged into the single MailTemplates store; the override setting is no longer read' }))
    }
    $reason = "seeded $seeded, upgraded $upgraded, kept $kept edited" + $(if ($merged) { ", merged $merged legacy override(s)" } else { '' })
    return [pscustomobject]@{ count = $doc.templates.Count; seeded = $seeded; upgraded = $upgraded; kept = $kept; merged = $merged; mergedTypes = @($mergedTypes); reason = $reason }
}

function Get-PimMailTemplateEffective {
    <#
      The body a send uses for -Type: the store entry, else the shipped file (a type the store has not
      been seeded with yet). Returns @{ text; source ('store'|'shipped'); customized; shipped } or $null
      when the type exists nowhere. -Document skips the store read (callers that already have it).
    #>
    param([Parameter(Mandatory)][string]$Type, [object]$Document, [string]$TemplateDir, [string]$ConnectionString)
    $doc = if ($PSBoundParameters.ContainsKey('Document') -and $Document) { $Document } else { Get-PimMailTemplateStoreDocument -ConnectionString $ConnectionString }
    $shipped = $null
    if (-not "$TemplateDir".Trim()) { $TemplateDir = Get-PimShippedMailTemplateDir }
    if ($TemplateDir) {
        $sp = Join-Path $TemplateDir "$Type.mailtemplate.html"
        if (Test-Path -LiteralPath $sp) { $shipped = [System.IO.File]::ReadAllText($sp, (New-Object System.Text.UTF8Encoding($false))) }
    }
    $e = $doc.templates[$Type]
    if ($null -ne $e -and "$($e.body)".Trim()) {
        return @{ text = "$($e.body)"; source = 'store'; customized = ($e.source -eq 'edited'); shipped = $shipped }
    }
    if ($null -ne $shipped) { return @{ text = $shipped; source = 'shipped'; customized = $false; shipped = $shipped } }
    return $null
}

function Set-PimMailTemplateStoreEntry {
    # Save an operator's edit into the store (source 'edited'). THROWS on no store / empty body.
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Body, [string]$By = '', [string]$ConnectionString, [string]$TemplateDir)
    if (-not "$Body".Trim()) { throw 'body cannot be empty (reset the template to return to the shipped default)' }
    $doc = Get-PimMailTemplateStoreDocument -ConnectionString $ConnectionString
    $shipped = Read-PimShippedMailTemplates -TemplateDir $TemplateDir
    $sh = if ($shipped.ContainsKey($Type)) { Get-PimMailTemplateHash -Text $shipped[$Type] } else { '' }
    $doc.templates[$Type] = [ordered]@{ body = $Body; source = 'edited'; shippedHash = $sh; updatedUtc = [datetime]::UtcNow.ToString('o'); updatedBy = $By }
    Save-PimMailTemplateStoreDocument -Document $doc -ConnectionString $ConnectionString
}

function Reset-PimMailTemplateStoreEntry {
    # Return a type to the shipped default (source 'shipped'). Returns $true when it had been edited.
    param([Parameter(Mandatory)][string]$Type, [string]$By = '', [string]$ConnectionString, [string]$TemplateDir)
    $doc = Get-PimMailTemplateStoreDocument -ConnectionString $ConnectionString
    $shipped = Read-PimShippedMailTemplates -TemplateDir $TemplateDir
    $wasEdited = ($null -ne $doc.templates[$Type] -and $doc.templates[$Type].source -eq 'edited')
    if ($shipped.ContainsKey($Type)) {
        $doc.templates[$Type] = [ordered]@{ body = $shipped[$Type]; source = 'shipped'; shippedHash = (Get-PimMailTemplateHash -Text $shipped[$Type]); updatedUtc = [datetime]::UtcNow.ToString('o'); updatedBy = $By }
    } else {
        $doc.templates.Remove($Type)
    }
    Save-PimMailTemplateStoreDocument -Document $doc -ConnectionString $ConnectionString
    return $wasEdited
}
