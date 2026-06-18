#Requires -Version 5.1
<#
    Pester suite for the PIM Activator browser-extension package validator
    (tools/pim-activator/Test-PimActivatorPackage.ps1).

    These are pure, offline unit tests: they exercise the extension-id
    derivation and each package check against the real shipped package plus
    synthetic fixtures, with NO signing and NO network. Documented in
    docs/TESTS.md (lockstep with this file).

    Run:  Invoke-Pester -Path TESTS\PIM.Activator.Tests.ps1
#>
BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:Activator = Join-Path $Root 'tools\pim-activator'
    $script:Helper    = Join-Path $Activator 'Test-PimActivatorPackage.ps1'
    # Dot-source for the function definitions (the script self-detects dot-source
    # and does NOT auto-run the validation in that mode).
    . $script:Helper
    # REST-first backend write helpers (REQUIREMENTS §19). Pure builders only --
    # no network, no Graph/Az modules. Dot-source defines functions with no
    # side effects on load.
    . (Join-Path $script:Activator '_PimActivatorBackend.ps1')
}

Describe 'PIM Activator: extension-id derivation' {
    It 'derives the canonical id from the real manifest key' {
        $manifest = Get-Content (Join-Path $Activator 'manifest.json') -Raw | ConvertFrom-Json
        Get-PimActivatorExtensionId -Base64Key $manifest.key |
            Should -Be 'eheocihmlppcophaeakmdenhgcookkab'
    }

    It 'produces a 32-char a-p (mpdecimal) id' {
        $manifest = Get-Content (Join-Path $Activator 'manifest.json') -Raw | ConvertFrom-Json
        $id = Get-PimActivatorExtensionId -Base64Key $manifest.key
        $id.Length | Should -Be 32
        $id | Should -Match '^[a-p]{32}$'
    }

    It 'is deterministic (same key -> same id)' {
        $manifest = Get-Content (Join-Path $Activator 'manifest.json') -Raw | ConvertFrom-Json
        $a = Get-PimActivatorExtensionId -Base64Key $manifest.key
        $b = Get-PimActivatorExtensionId -Base64Key $manifest.key
        $a | Should -Be $b
    }
}

Describe 'PIM Activator: placeholder-GUID detection' {
    It 'treats an all-zero GUID as a placeholder' {
        Test-PimActivatorPlaceholderGuid -Guid '00000000-0000-0000-0000-000000000000' | Should -BeTrue
    }
    It 'treats a single-repeated-char GUID as a placeholder' {
        Test-PimActivatorPlaceholderGuid -Guid '11111111-1111-1111-1111-111111111111' | Should -BeTrue
    }
    It 'treats a real-looking GUID as NOT a placeholder' {
        Test-PimActivatorPlaceholderGuid -Guid 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' | Should -BeFalse
    }
}

Describe 'PIM Activator: shipped package validates clean' {
    BeforeAll { $script:result = Test-PimActivatorPackage -Path $Activator -Quiet }

    It 'returns Ok = $true (no error-severity failures)' {
        $script:result.Ok | Should -BeTrue
    }
    It 'IDLOCK passes (extension id has not drifted)' {
        ($script:result.Findings | Where-Object Check -eq 'IDLOCK').Ok | Should -Not -Contain $false
    }
    It 'NODEVCODE passes (no device-code flow anywhere)' {
        ($script:result.Findings | Where-Object Check -eq 'NODEVCODE').Ok | Should -Not -Contain $false
    }
    It 'PKCE passes (Edge loopback sign-in present)' {
        ($script:result.Findings | Where-Object Check -eq 'PKCE').Ok | Should -Not -Contain $false
    }
    It 'NOSECRET passes (no real tenant/subscription GUIDs in shipped files)' {
        ($script:result.Findings | Where-Object Check -eq 'NOSECRET').Ok | Should -Not -Contain $false
    }
    It 'VERSION passes (badge wired to manifest)' {
        ($script:result.Findings | Where-Object Check -eq 'VERSION').Ok | Should -Not -Contain $false
    }
}

Describe 'PIM Activator: validator catches regressions (synthetic fixtures)' {
    BeforeEach {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("pimact_" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        # Copy the real package so each fixture starts from a valid baseline.
        Copy-Item -Path (Join-Path $Activator '*') -Destination $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    AfterEach {
        if ($script:tmp -and (Test-Path $script:tmp)) { Remove-Item $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a drifted extension-id key (IDLOCK error)' {
        $mp = Join-Path $tmp 'manifest.json'
        $m  = Get-Content $mp -Raw | ConvertFrom-Json
        # A different but valid base64 SPKI -> different id. Mutate a few chars.
        $m.key = $m.key.Substring(0, $m.key.Length - 8) + 'AAAAAAAA'
        $m | ConvertTo-Json -Depth 6 | Set-Content -Path $mp -Encoding UTF8
        $r = Test-PimActivatorPackage -Path $tmp -Quiet
        $r.Ok | Should -BeFalse
        ($r.Findings | Where-Object Check -eq 'IDLOCK').Ok | Should -Contain $false
    }

    It 'flags an injected device-code flow (NODEVCODE error)' {
        $jp = Join-Path $tmp 'popup.js'
        Add-Content -Path $jp -Value "`n// regression: const grant = 'urn:ietf:params:oauth:grant-type:device_code'"
        $r = Test-PimActivatorPackage -Path $tmp -Quiet
        $r.Ok | Should -BeFalse
        ($r.Findings | Where-Object Check -eq 'NODEVCODE').Ok | Should -Contain $false
    }

    It 'flags a real tenant GUID baked into a shipped file (NOSECRET error)' {
        $jp = Join-Path $tmp 'popup.js'
        Add-Content -Path $jp -Value "`n// regression: const t = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'"
        $r = Test-PimActivatorPackage -Path $tmp -Quiet
        $r.Ok | Should -BeFalse
        ($r.Findings | Where-Object Check -eq 'NOSECRET').Ok | Should -Contain $false
    }

    It 'flags a real GUID baked into popup-config.js (NOSECRET scans the new module)' {
        $cp = Join-Path $tmp 'popup-config.js'
        Add-Content -Path $cp -Value "`n// regression: const t = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'"
        $r = Test-PimActivatorPackage -Path $tmp -Quiet
        $r.Ok | Should -BeFalse
        ($r.Findings | Where-Object Check -eq 'NOSECRET').Ok | Should -Contain $false
    }
}

Describe 'PIM Activator: package validator is wired into the repack/deploy gate' {
    BeforeAll {
        $script:Update = Join-Path $Activator 'Update-PimActivator-Extension.ps1'
        $script:UpdateText = Get-Content -LiteralPath $Update -Raw
    }
    It 'the repack path dot-sources + calls Test-PimActivatorPackage before signing' {
        $UpdateText | Should -Match 'Test-PimActivatorPackage\.ps1'
        $UpdateText | Should -Match 'Test-PimActivatorPackage\s+-Path'
    }
    It 'refuses to repack when the validator fails (hard throw on .Ok = false)' {
        $UpdateText | Should -Match 'if\s*\(-not\s+\$pkg\.Ok\)'
    }
    It 'the validator gate runs before the CRX sign step (ordering)' {
        $idxGate = $UpdateText.IndexOf('Test-PimActivatorPackage -Path')
        $idxSign = $UpdateText.IndexOf('--pack-extension')
        $idxGate | Should -BeGreaterThan 0
        $idxSign | Should -BeGreaterThan 0
        $idxGate | Should -BeLessThan $idxSign
    }
}

Describe 'PIM Activator: configurable bulk-activate confirm threshold' {
    BeforeDiscovery {
        # -Skip: is evaluated at DISCOVERY time, so the node-present check must
        # happen here (not in BeforeAll, which runs later).
        $script:HasNode = [bool](Get-Command node -ErrorAction SilentlyContinue)
    }
    BeforeAll {
        $script:Node = (Get-Command node -ErrorAction SilentlyContinue)
        $script:ConfigJs = Join-Path $Activator 'popup-config.js'
    }
    It 'ships the pure resolver module popup-config.js' {
        Test-Path -LiteralPath $script:ConfigJs | Should -BeTrue
    }
    It 'popup.js imports the resolver from popup-config.js (single definition, no drift)' {
        $popup = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw
        # import may carry additional named symbols (e.g. BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT) alongside the resolver
        $popup | Should -Match "import\s*\{[^}]*\bresolveBulkActivateConfirmThreshold\b[^}]*\}\s*from\s*'\./popup-config\.js'"
        # The inline copy must be gone -- only the import remains.
        ([regex]::Matches($popup, 'function\s+resolveBulkActivateConfirmThreshold')).Count | Should -Be 0
    }
    It 'the activate guard reads the resolved threshold from cfg (not a hard-coded 5)' {
        $popup = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw
        $popup | Should -Match 'const BULK_ACTIVATE_CONFIRM_THRESHOLD = resolveBulkActivateConfirmThreshold\('
    }
    It 'resolver clamps + defaults correctly (Node)' -Skip:(-not $script:HasNode) {
        $expr = @'
import { resolveBulkActivateConfirmThreshold as f, BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT as D } from "./popup-config.js";
const cases = [[undefined,D],[null,D],["",D],["abc",D],[0,D],[-3,D],[5,5],["7",7],[7.9,7],[1,1],[100,100],[101,100],[200,100],["  12  ",12]];
let bad=0; for (const [i,e] of cases){ if (f(i)!==e) { bad++; console.error("FAIL",JSON.stringify(i),"=>",f(i),"exp",e); } }
console.log(bad===0 ? "ALL-PASS" : ("FAILS="+bad)); process.exit(bad?1:0);
'@
        Push-Location $Activator
        try { $out = $expr | & $script:Node.Source --input-type=module 2>&1 } finally { Pop-Location }
        $LASTEXITCODE | Should -Be 0
        ($out -join "`n") | Should -Match 'ALL-PASS'
    }
    It 'is documented as a managed-config key (managed-schema.json)' {
        $schema = Get-Content -LiteralPath (Join-Path $Activator 'managed-schema.json') -Raw | ConvertFrom-Json
        $schema.properties.PSObject.Properties.Name | Should -Contain 'bulkActivateConfirmThreshold'
        $schema.properties.bulkActivateConfirmThreshold.type | Should -Be 'integer'
    }
    It 'is pushable via the ADMX/ADML (both browsers)' {
        [xml]$admx = Get-Content -LiteralPath (Join-Path $Activator 'intune\PIM4EntraPS.PimActivator.admx') -Raw
        $names = $admx.policyDefinitions.policies.policy.name
        $names | Should -Contain 'BulkThreshold_Edge'
        $names | Should -Contain 'BulkThreshold_Chrome'
        # The element must write the exact managed-config valueName the popup reads.
        ($admx.policyDefinitions.policies.policy |
            Where-Object name -eq 'BulkThreshold_Edge').elements.decimal.valueName |
            Should -Be 'bulkActivateConfirmThreshold'
        [xml]$adml = Get-Content -LiteralPath (Join-Path $Activator 'intune\en-US\PIM4EntraPS.PimActivator.adml') -Raw
        ($adml.policyDefinitionResources.resources.stringTable.string.id) | Should -Contain 'BulkThreshold_Explain'
    }
}

Describe 'PIM Activator: delegation-load network resilience (v1.6.31 hang fix)' {
    BeforeDiscovery {
        $script:HasNode = [bool](Get-Command node -ErrorAction SilentlyContinue)
    }
    BeforeAll {
        $script:Node    = (Get-Command node -ErrorAction SilentlyContinue)
        $script:NetJs   = Join-Path $Activator 'popup-net.js'
        $script:NetTest = Join-Path $Activator 'tests\test-network-resilience.js'
        $script:Popup   = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw
    }

    It 'ships the DOM/chrome-free network module popup-net.js' {
        Test-Path -LiteralPath $script:NetJs | Should -BeTrue
    }
    It 'popup.js imports the timeout + watchdog helpers from popup-net.js' {
        $script:Popup | Should -Match "import\s*\{[^}]*fetchWithTimeout[^}]*\}\s*from\s*'\./popup-net\.js'"
        $script:Popup | Should -Match "import\s*\{[^}]*withWatchdog[^}]*\}\s*from\s*'\./popup-net\.js'"
    }
    It 'every Graph/token/ARM call goes through fetchWithTimeout (no bare fetch except the helper)' {
        # The only legitimate bare "await fetch(" is inside popup-net.js (the
        # helper). popup.js itself must use fetchWithTimeout everywhere.
        ([regex]::Matches($script:Popup, 'await\s+fetch\(')).Count | Should -Be 0
        ([regex]::Matches($script:Popup, 'fetchWithTimeout\(')).Count | Should -BeGreaterThan 5
    }
    It 'the delegation-load bounds EACH eligibility source independently (resilient load, not all-or-nothing)' {
        # v1.6.7x customer fix ("Loading your PIM assignments did not complete within 75s"):
        # the load no longer wraps all 6 sources in a single withWatchdog(Promise.all(...)) --
        # one slow/throttled optional source would trip the whole-path watchdog and wipe the
        # list. Each source is now bounded on its own (settleWithin + SOURCE_WATCHDOG_MS) and
        # the load renders whatever succeeded.
        $script:Popup | Should -Match 'settleWithin\('
        ([regex]::Matches($script:Popup, 'settleWithin\(')).Count | Should -BeGreaterOrEqual 6
        $script:Popup | Should -Match 'SOURCE_WATCHDOG_MS'
        # the all-or-nothing wrapper must be GONE from the load path
        $script:Popup | Should -Not -Match 'withWatchdog\(Promise\.all\('
        # group-name resolution is still individually bounded
        $script:Popup | Should -Match "withWatchdog\(hydrateGroupNames\("
    }
    It 'a failed/partial load still captures a per-source diagnostics snapshot' {
        # The old code captured diagnostics only AFTER a successful Promise.all, so a
        # timeout left the Diagnostics panel on "no snapshot captured yet". Now per-source
        # status is recorded before any early return.
        $script:Popup | Should -Match 'lastLoadStatus'
        $script:Popup | Should -Match "lastDiagText\s*=\s*'LOAD STATUS"
    }
    It 'a load failure renders a visible, actionable error state (never an infinite spinner)' {
        $script:Popup | Should -Match 'function\s+showLoadFailure'
        $script:Popup | Should -Match 'showLoadFailure\('
        # Report-bug affordance + Retry button are part of the error card.
        $script:Popup | Should -Match 'load-report'
        $script:Popup | Should -Match 'load-retry'
    }
    It 'boot() has a last-resort catch so a rejected boot cannot hang the popup' {
        $script:Popup | Should -Match 'boot\(\)\.catch\('
    }
    It 'ships the offline node test for the resilience primitives' {
        Test-Path -LiteralPath $script:NetTest | Should -BeTrue
    }
    It 'the offline node test passes (timeout / watchdog / network-error logic)' -Skip:(-not $script:HasNode) {
        Push-Location $Activator
        try { $out = & $script:Node.Source 'tests/test-network-resilience.js' 2>&1 } finally { Pop-Location }
        $LASTEXITCODE | Should -Be 0
        ($out -join "`n") | Should -Match '0 failed'
    }
}

Describe 'PIM Activator: Diagnostics environment self-check' {
    BeforeAll { $script:Popup = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw }
    It 'defines the environment-check engine + the endpoints it probes' {
        $script:Popup | Should -Match 'function\s+runEnvironmentChecks'
        $script:Popup | Should -Match 'const ENV_CHECK_ENDPOINTS'
        # probes every endpoint PIMA actually calls (login / graph / arm / update feed)
        $script:Popup | Should -Match 'login\.microsoftonline\.com'
        $script:Popup | Should -Match 'graph\.microsoft\.com'
        $script:Popup | Should -Match 'management\.azure\.com'
        $script:Popup | Should -Match 'knudsenmorten\.github\.io/PIM4EntraPS/updates\.xml'
    }
    It 'checks clock skew + scopes + version + runtime wiring (not just reachability)' {
        $script:Popup | Should -Match 'Device clock vs Microsoft'
        $script:Popup | Should -Match 'missingScopes\('
        $script:Popup | Should -Match 'Extension version'
        $script:Popup | Should -Match 'chrome\.identity'
    }
    It 'each probe is independently bounded (never hangs the popup)' {
        $script:Popup | Should -Match 'fetchWithTimeout\(ep\.url'
    }
    It 'the Run-checks button is wired to runEnvironmentChecks (no dead view) + feeds the copy-able panel' {
        $script:Popup | Should -Match 'id="pim-diag-check"'
        $script:Popup | Should -Match 'runEnvironmentChecks\(\)'
        $script:Popup | Should -Match 'lastEnvChecks'
        $script:Popup | Should -Match '=== Environment checks ==='
    }
}

Describe 'PIM Activator: per-group auto-activate (no chain)' {
    BeforeAll { $script:Popup = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw }
    It 'defines per-group auto-activate opt-in storage (chrome.storage.local, off by default)' {
        $script:Popup | Should -Match 'function\s+isAutoActivate'
        $script:Popup | Should -Match 'function\s+toggleAutoActivate'
        $script:Popup | Should -Match "getStored\(\['autoActivate'\]\)"
        $script:Popup | Should -Match 'setStored\(\{ autoActivate \}\)'
    }
    It 'renders a per-row auto-activate CHECKBOX (labelled, off by default) on DIRECT group rows, wired to toggleAutoActivate' {
        $script:Popup | Should -Match "canAuto\s*=\s*\(r\.kind === 'group' && !r\.depth\)"
        # a real labelled checkbox (operator: the bolt icon was unclear) -- not an icon
        $script:Popup | Should -Match 'type="checkbox" class="auto-cb"'
        $script:Popup | Should -Match '>auto</label>'   # plain "auto" label (no widening state suffix)
        # checked ONLY when isAuto -> off by default (autoActivate store starts empty)
        $script:Popup | Should -Match "isAuto \? 'checked'"
        $script:Popup | Should -Match 'toggleAutoActivate\(idAttr\)'
        # no leftover bolt glyph
        $script:Popup | Should -Not -Match '&#x26A1;'
    }
    It 'ticking auto STARTS the activation immediately (this group only) -- not just a next-open preference' {
        # onchange is async + activates the single group via the normal activateGroup path
        $script:Popup | Should -Match 'autoCb\.onchange = async'
        $script:Popup | Should -Match 'if \(autoCb\.checked && !r\.isActive && r\.groupId\)'
        $script:Popup | Should -Match 'await activateGroup\(tok, r\.groupId'
        # no chain: it activates r.groupId only (no nested/children expansion in the handler)
    }
    It 'the auto label carries NO inline state suffix (avoids horizontal scroll; state shown via badge/propagation)' {
        $script:Popup | Should -Not -Match 'autoState'
        $script:Popup | Should -Not -Match "auto<span"
    }
    It 'the fun-box waits 10s then shows a RANDOM line every 5s (no immediate repeat)' {
        $script:Popup | Should -Match 'FUN_START_DELAY_MS\s*=\s*10000'
        $script:Popup | Should -Match 'FUN_ROTATE_MS\s*=\s*5000'
        $script:Popup | Should -Match '_funDelay\s*=\s*setTimeout'
        $script:Popup | Should -Match 'while \(n === _funIdx\) n = Math\.floor\(Math\.random'
    }
    It 'on-open sweep activates direct groups only, never chains, runs once, and is hooked into load' {
        $script:Popup | Should -Match 'function\s+runAutoActivations'
        $script:Popup | Should -Match 'if \(autoActivateRunDone\) return'
        # direct + eligible + not-active + not-nested filter (the "no chain" guarantee)
        $script:Popup | Should -Match "r\.kind === 'group' && !r\.depth && !r\.isNested && !r\.isActive"
        # activates via the normal single-group path, not any chain/nested expansion
        $script:Popup | Should -Match 'await activateGroup\(token, r\.groupId'
        $script:Popup | Should -Match 'runAutoActivations\(token\)'
    }
}

Describe 'PIM Activator: first-run getting-started tip' {
    BeforeAll { $script:Popup = Get-Content -LiteralPath (Join-Path $Activator 'popup.js') -Raw }
    It 'defines the one-time tip function' {
        $Popup | Should -Match 'function\s+maybeShowGettingStartedTip'
    }
    It 'is shown after the activate list renders' {
        $Popup | Should -Match 'maybeShowGettingStartedTip\(readyCount\)'
    }
    It 'persists a dismiss flag so it only shows once' {
        $Popup | Should -Match 'gettingStartedTipDismissed'
    }
    It 'points the user at bulk-activate + the My Access tab' {
        $Popup | Should -Match 'Activate selected'
        $Popup | Should -Match 'My Access'
    }
}

# ---------------------------------------------------------------------------
# REST-first backend write path (REQUIREMENTS §19 -- Write/activator path).
# Pure builders + the SDK-routing seam: no network, no Graph/Az modules.
# ---------------------------------------------------------------------------
Describe 'PIM Activator backend: REST write builders' {

    It 'Resolve-PaGraphScopeIds maps values to ids, preserves order, accepts camel + Pascal shapes' {
        $sp = @(
            [pscustomobject]@{ value = 'Group.Read.All'; id = 'g1' },
            [pscustomobject]@{ Value = 'User.Read';      Id = 'u1' },   # Pascal alias
            [pscustomobject]@{ value = 'PrivilegedAccess.ReadWrite.AzureADGroup'; id = 'p1' }
        )
        $m = Resolve-PaGraphScopeIds -Oauth2PermissionScopes $sp -Names @('PrivilegedAccess.ReadWrite.AzureADGroup','Group.Read.All','User.Read')
        @($m.Keys)   | Should -Be @('PrivilegedAccess.ReadWrite.AzureADGroup','Group.Read.All','User.Read')
        @($m.Values) | Should -Be @('p1','g1','u1')
    }

    It 'Resolve-PaGraphScopeIds throws (fails loud) on a scope the SP does not expose' {
        $sp = @([pscustomobject]@{ value = 'Group.Read.All'; id = 'g1' })
        { Resolve-PaGraphScopeIds -Oauth2PermissionScopes $sp -Names @('Not.A.Scope') } |
            Should -Throw -ExpectedMessage "*Not.A.Scope*not found*"
    }

    It 'New-PaRequiredResourceAccess emits lowercase REST keys for Graph + ASM' {
        $ids = [ordered]@{ 'Group.Read.All' = 'g1'; 'User.Read' = 'u1' }
        $rra = New-PaRequiredResourceAccess -GraphAppId '00000003-0000-0000-c000-000000000000' `
            -GraphScopeIds $ids -AsmAppId '797f4846-ba00-4fd7-ba43-dac1f8f63013' -AsmScopeId 'asm1'
        $rra.Count | Should -Be 2
        $rra[0].resourceAppId | Should -Be '00000003-0000-0000-c000-000000000000'
        $rra[0].resourceAccess.Count | Should -Be 2
        $rra[0].resourceAccess[0].type | Should -Be 'Scope'
        $rra[1].resourceAppId | Should -Be '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $rra[1].resourceAccess[0].id | Should -Be 'asm1'
    }

    It 'New-PaAppRegistrationBody registers BOTH SPA URIs, clears public client, no fallback' {
        $body = New-PaAppRegistrationBody -DisplayName 'PIM Activator' -ExtensionId ('a' * 32) -RequiredResourceAccess @() -IncludeDisplayName
        $body.spa.redirectUris | Should -Contain ('https://' + ('a' * 32) + '.chromiumapp.org/')
        $body.spa.redirectUris | Should -Contain ('chrome-extension://' + ('a' * 32) + '/')
        $body.publicClient.redirectUris.Count | Should -Be 0
        $body.isFallbackPublicClient | Should -BeFalse
        $body.signInAudience | Should -Be 'AzureADMyOrg'
    }

    It 'New-PaAppRegistrationBody includes displayName only on create (PATCH must not rename)' {
        $create = New-PaAppRegistrationBody -DisplayName 'PIM Activator' -ExtensionId ('a' * 32) -RequiredResourceAccess @() -IncludeDisplayName
        $update = New-PaAppRegistrationBody -DisplayName 'PIM Activator' -ExtensionId ('a' * 32) -RequiredResourceAccess @()
        $create.ContainsKey('displayName') | Should -BeTrue
        $update.ContainsKey('displayName') | Should -BeFalse
    }

    It 'New-PaConsentScopeString appends OIDC basics + offline_access and de-dups' {
        $s = New-PaConsentScopeString -Scopes @('Group.Read.All','openid','User.Read')
        $parts = $s -split ' '
        $parts | Should -Contain 'openid'
        $parts | Should -Contain 'profile'
        $parts | Should -Contain 'offline_access'
        @($parts | Where-Object { $_ -eq 'openid' }).Count | Should -Be 1   # not duplicated (@() wrap: PS 5.1 unwraps single matches)
    }

    It 'Get-PaProp reads camelCase, PascalCase, and hashtable keys; tolerates null' {
        Get-PaProp ([pscustomobject]@{ appId = 'x' }) 'appId' | Should -Be 'x'
        Get-PaProp ([pscustomobject]@{ AppId = 'y' }) 'appId' | Should -Be 'y'
        Get-PaProp @{ appId = 'z' } 'appId'                   | Should -Be 'z'
        Get-PaProp $null 'id'                                 | Should -BeNullOrEmpty
    }

    It 'Invoke-PaGraph defaults to the REST data plane (SDK only when opted in)' {
        $global:PIM_UseGraphSdk = $null
        Test-PaUseGraphSdk | Should -BeFalse
        $global:PIM_UseGraphSdk = $true
        Test-PaUseGraphSdk | Should -BeTrue
        $global:PIM_UseGraphSdk = $false   # restore REST default
    }
}

Describe 'PIM Activator backend: module-free by construction' {
    BeforeAll {
        $script:DeployScript = Join-Path $script:Activator 'Deploy-PimActivatorBackend.ps1'
        $script:BackendHelper = Join-Path $script:Activator '_PimActivatorBackend.ps1'
    }

    It 'the deploy script no longer hard-requires the Microsoft.Graph SDK modules' {
        $txt = Get-Content $script:DeployScript -Raw
        $txt | Should -Not -Match '(?im)^\s*#Requires\s+-Modules.*Microsoft\.Graph'
    }

    It 'the write path uses Invoke-PaGraph, not SDK write cmdlets' {
        $txt = Get-Content $script:DeployScript -Raw
        # No application / SP / consent-grant SDK write cmdlets remain on the write path.
        $txt | Should -Not -Match '(?m)New-MgApplication|Update-MgApplication|Get-MgApplication'
        $txt | Should -Not -Match '(?m)New-MgOauth2PermissionGrant|Update-MgOauth2PermissionGrant|Get-MgOauth2PermissionGrant'
        $txt | Should -Match 'Invoke-PaGraph'
    }

    It 'the REST seam routes through the module-free PIM-Rest data plane' {
        $txt = Get-Content $script:BackendHelper -Raw
        $txt | Should -Match 'Invoke-PimGraph'
        $txt | Should -Match 'PIM_UseGraphSdk'
    }

    It 'introduces no device-code flow (NODEVCODE invariant holds for the new helper)' {
        $txt = Get-Content $script:BackendHelper -Raw
        $txt | Should -Not -Match '(?i)device[\s_-]*code'
    }
}
