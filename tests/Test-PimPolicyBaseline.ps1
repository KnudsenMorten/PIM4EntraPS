#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-55 -- a roll must be able to say whether the image changes DESIRED STATE, before rolling.

    v2.4.246 was built to ship a scheduler-lease fix. The image is built from `git archive HEAD`,
    so it also carried policy-template edits sitting in HEAD that had never been approved. The
    roll succeeded, the tick began applying them every 5 minutes, and 217 of 325 production group
    policies were rewritten overnight. Nothing alerted -- it was found by a WhatIf run for an
    unrelated reason reporting update=217 where 0 was expected.

    These tests pin the PURE half: the fingerprint of the shipped templates and the three-way
    verdict the roll gate acts on. Offline -- temp files only, no Azure, no Graph, no git.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $solRoot 'engine\_shared\PIM-PolicyBaseline.ps1')

Write-Host "=== BUG-55: desired-state fingerprint + roll verdict ===" -ForegroundColor Cyan

# ---- a scratch template dir we control completely -------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimbase-" + [guid]::NewGuid().ToString('n').Substring(0,8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
function Write-Tpl($name, $obj) { $obj | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $tmp $name) -Encoding UTF8 }

try {
    $base = [ordered]@{
        id    = 'T1'
        rules = [ordered]@{
            Enablement = [ordered]@{ EndUser_Assignment = @('MultiFactorAuthentication','Justification'); Admin_Eligibility = @() }
            Expiration = [ordered]@{ EndUser_Assignment = [ordered]@{ maximumDuration = 'PT8H'; isExpirationRequired = $true } }
        }
    }
    Write-Tpl 'a.policytemplate.json' $base
    $fp1 = Get-PimPolicyBaselineFingerprint -TemplateDir $tmp
    Assert "fingerprints the shipped templates"                 ($fp1.count -eq 1 -and $fp1.hash)
    Assert "  ...and keeps a PER-TEMPLATE hash so a change can be NAMED" ($fp1.templates.ContainsKey('a.policytemplate.json'))
    Assert "  ...hash is tag-safe (short hex, no separators)"   ($fp1.hash -match '^[0-9a-f]{16}$')

    # --- STABILITY: the things that must NOT read as a desired-state change ---------------
    $fp2 = Get-PimPolicyBaselineFingerprint -TemplateDir $tmp
    Assert "same content -> same fingerprint (deterministic)"   ($fp2.hash -eq $fp1.hash)

    # Annotations are commentary. THIS SESSION edited exactly these fields on a shipped template
    # to correct a note that described the wrong mechanism; if that read as a baseline change the
    # gate would fire on documentation and get bypassed on the deploy that mattered.
    $withNotes = [ordered]@{
        id = 'T1'; description = 'a long human explanation'
        rules = [ordered]@{
            Enablement = [ordered]@{ EndUser_Assignment = @('MultiFactorAuthentication','Justification'); Admin_Eligibility = @() }
            Expiration = [ordered]@{ EndUser_Assignment = [ordered]@{ maximumDuration = 'PT8H'; isExpirationRequired = $true } }
            _why = 'commentary that is not desired state'
        }
        _measured = 'more commentary'
    }
    Write-Tpl 'a.policytemplate.json' $withNotes
    Assert "adding _annotations + description is NOT a baseline change" ((Get-PimPolicyBaselineFingerprint -TemplateDir $tmp).hash -eq $fp1.hash)

    # Formatting churn (CRLF vs LF, key order, indentation) must not fire either -- on a Windows
    # checkout a line-ending flip alone would otherwise flag every template.
    $reordered = "{`r`n `"rules`" : {`r`n `"Expiration`":{`"EndUser_Assignment`":{`"isExpirationRequired`":true,`"maximumDuration`":`"PT8H`"}},`r`n" +
                 " `"Enablement`":{`"Admin_Eligibility`":[],`"EndUser_Assignment`":[`"MultiFactorAuthentication`",`"Justification`"]}`r`n },`r`n `"id`":`"T1`"`r`n}"
    Set-Content -LiteralPath (Join-Path $tmp 'a.policytemplate.json') -Value $reordered -Encoding UTF8
    Assert "key order / whitespace / CRLF churn is NOT a baseline change" ((Get-PimPolicyBaselineFingerprint -TemplateDir $tmp).hash -eq $fp1.hash)

    # --- SENSITIVITY: the things that MUST read as a change -------------------------------
    # The 217-policy incident in miniature: one enablement value moves.
    $changed = [ordered]@{
        id    = 'T1'
        rules = [ordered]@{
            Enablement = [ordered]@{ EndUser_Assignment = @('MultiFactorAuthentication','Justification'); Admin_Eligibility = @('Justification') }
            Expiration = [ordered]@{ EndUser_Assignment = [ordered]@{ maximumDuration = 'PT8H'; isExpirationRequired = $true } }
        }
    }
    Write-Tpl 'a.policytemplate.json' $changed
    $fpChanged = Get-PimPolicyBaselineFingerprint -TemplateDir $tmp
    Assert "Admin_Eligibility [] -> ['Justification'] IS a baseline change" ($fpChanged.hash -ne $fp1.hash)

    Write-Tpl 'a.policytemplate.json' $base
    Write-Tpl 'b.policytemplate.json' ([ordered]@{ id='T2'; rules=[ordered]@{ Enablement=[ordered]@{ Admin_Assignment=@() } } })
    $fpAdded = Get-PimPolicyBaselineFingerprint -TemplateDir $tmp
    Assert "ADDING a template is a baseline change"             ($fpAdded.hash -ne $fp1.hash -and $fpAdded.count -eq 2)
    Remove-Item (Join-Path $tmp 'b.policytemplate.json')
    Assert "removing it again restores the original fingerprint" ((Get-PimPolicyBaselineFingerprint -TemplateDir $tmp).hash -eq $fp1.hash)

    # --- the VERDICT the gate acts on ------------------------------------------------------
    $cur = Get-PimPolicyBaselineFingerprint -TemplateDir $tmp

    $v = Compare-PimPolicyBaseline -Current $cur -RecordedHash $cur.hash
    Assert "recorded == current -> unchanged and allowed"       ((-not $v.changed) -and $v.allowed -and (-not $v.unknown))

    # First roll into an environment: nothing recorded. Blocking here would make the gate's own
    # rollout impossible, so it warns and proceeds -- honest about not knowing.
    $v = Compare-PimPolicyBaseline -Current $cur -RecordedHash ''
    Assert "nothing recorded -> UNKNOWN, allowed, and says why"  ($v.unknown -and $v.allowed -and ("$($v.reason)" -match 'no policy baseline recorded'))

    # The load-bearing case: the roll carries desired state nobody asked for.
    $v = Compare-PimPolicyBaseline -Current $cur -RecordedHash 'deadbeefdeadbeef'
    Assert "recorded != current -> CHANGED and REFUSED by default" ($v.changed -and (-not $v.allowed))
    Assert "  ...and the reason names the baseline as the problem" ("$($v.reason)" -match 'CHANGES THE POLICY BASELINE')

    $v = Compare-PimPolicyBaseline -Current $cur -RecordedHash 'deadbeefdeadbeef' -Accept
    Assert "  ...and -AcceptBaselineChange is what allows it"    ($v.changed -and $v.allowed)

    # When the per-template recording is available the verdict NAMES what moved -- the difference
    # between a message someone acts on and one they click past.
    $recTemplates = @{ 'a.policytemplate.json' = 'oldhash'; 'gone.policytemplate.json' = 'x' }
    $v = Compare-PimPolicyBaseline -Current $cur -RecordedHash 'deadbeefdeadbeef' -RecordedTemplates $recTemplates
    Assert "names the MODIFIED template"                        (@($v.modified) -contains 'a.policytemplate.json')
    Assert "names the REMOVED template"                         (@($v.removed)  -contains 'gone.policytemplate.json')

    # A missing directory must not throw -- a gate that crashes gets disabled.
    $none = Get-PimPolicyBaselineFingerprint -TemplateDir (Join-Path $tmp 'does-not-exist')
    Assert "a missing template dir yields count=0, not an exception" ($none.count -eq 0 -and -not $none.hash)
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("BUG-55 policy-baseline gate: {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
