#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 Phase-2 DOWNLINK + scenario-runner offline test. Proves the PURE cores
    in engine/_shared/PIM-Downlink.ps1:
      1. RING FILTER       -- Select-PimDownlinkAdmins keeps admin.Ring <= slave.Ring
                              (ring 0 broad reaches all; ring 2 only ring-2 slaves);
                              no-ring rows fail-safe drop; result is deterministic.
      2. SIGNATURE VERIFY  -- Test-PimDownlinkBaseline accepts a VALID signed bundle,
                              rejects a TAMPERED payload, an EXPIRED bundle, a
                              ROLLBACK (version < last-applied), and a WRONG-KEY
                              signature -- all with an EPHEMERAL in-memory RSA
                              keypair (the real signing key never leaves mgmt1; NO
                              RSA.ImportFromPem).
      3. SYNC-FILE PATHS   -- Resolve-PimDownlinkSyncPath routes central-msp (S5) to
                              the central root, local-slave (S6) to the local root,
                              none (single) to no staging, per-tenant subfolder.
      4. IDEMPOTENCY       -- Test-PimDownlinkIdempotent: identical content = no-op;
                              a changed file is detected; CRLF/LF round-trip is not a
                              false change.
      5. DOWNLINK PLAN     -- Get-PimDownlinkPlan composes verify+ring+paths+content
                              and REFUSES on a bad signature.
      6. RUNNER BRANCH     -- Get-PimScenarioRunPlan: single/master = engine-apply
                              only; managed (S5/S6) = downlink-sync THEN engine-apply.

    All OFFLINE (no live tenant, az, SQL, HTTP, file writes beyond a temp dir for
    the idempotency byte-compare). Run standalone (exit 0 green / 1 red) or via
    Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $root 'engine\_shared\PIM-Baseline.ps1')

# ---------------------------------------------------------------------------
# Helper: sign a baseline payload with an EPHEMERAL RSA key (mirrors
# New-PimBaselineBundle's RSA-SHA256-PKCS1 over the UTF8 payload bytes). Returns
# @{ doc; rsaPublic }. The private key never touches disk.
# ---------------------------------------------------------------------------
function New-TestSignedBaseline {
    param(
        [object[]]$Rows = @(),
        [int64]$Version = 2606170000,
        [string]$ValidToUtc,
        [System.Security.Cryptography.RSA]$Signer,
        [string]$Product = 'PIM4EntraPS',
        [string]$Kind = 'baseline',
        # MSP-2 / control #2. Omitted => the payload carries NO assignments key,
        # which is exactly the shape an older master publishes.
        [object[]]$Assignments,
        # BUG-59. Same rule: omitted => no definitions key, i.e. a master that
        # publishes memberships but cannot stand up the model.
        [object]$Definitions,
        # The per-relationship policy, keyed by tenant id, as the producer emits it.
        [object]$ProjectionPolicy
    )
    if (-not $ValidToUtc) { $ValidToUtc = [datetime]::UtcNow.AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $payload = [ordered]@{
        product        = $Product
        kind           = $Kind
        version        = $Version
        scope          = 'fleet'
        generatedAtUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        validToUtc     = $ValidToUtc
        rows           = $Rows
    }
    if ($PSBoundParameters.ContainsKey('Assignments') -and $null -ne $Assignments) { $payload['assignments'] = $Assignments }
    if ($PSBoundParameters.ContainsKey('Definitions') -and $null -ne $Definitions) { $payload['definitions'] = $Definitions }
    if ($PSBoundParameters.ContainsKey('ProjectionPolicy') -and $null -ne $ProjectionPolicy) { $payload['projectionPolicy'] = $ProjectionPolicy }
    $payloadJson  = ($payload | ConvertTo-Json -Depth 6 -Compress)
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
    $sig = $Signer.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $doc = [pscustomobject]@{
        product       = $Product
        payloadB64    = [Convert]::ToBase64String($payloadBytes)
        signature     = [Convert]::ToBase64String($sig)
        keyThumbprint = 'EPHEMERAL-TEST-KEY'
    }
    return @{ doc = $doc; payloadBytes = $payloadBytes }
}

# Two independent ephemeral keypairs (signer + an unrelated "wrong" key).
$rsaSigner = [System.Security.Cryptography.RSA]::Create(2048)
$rsaWrong  = [System.Security.Cryptography.RSA]::Create(2048)

# A small synthetic baseline admin set (ring-stamped), mirroring the seeder.
$baselineAdmins = @(
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPGlobal-L0-T0-ID'; Ring = 0; Template = 'msp-operator'; DisplayName = 'MSP Global' }
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPCloud-L1-T1-ID';  Ring = 1; Template = 'consultant';   DisplayName = 'MSP Cloud' }
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPHelp-L2-T2-ID';   Ring = 2; Template = 'consultant';   DisplayName = 'MSP Help' }
)

# ===========================================================================
Write-Host "`n== 1. RING FILTER (admin.Ring <= slave.Ring) ==" -ForegroundColor Cyan
# ===========================================================================
$ring2 = @(Select-PimDownlinkAdmins -Admins $baselineAdmins -SlaveRing 2)
$ring1 = @(Select-PimDownlinkAdmins -Admins $baselineAdmins -SlaveRing 1)
$ring0 = @(Select-PimDownlinkAdmins -Admins $baselineAdmins -SlaveRing 0)
T 'ring-2 slave gets all 3 admins (ring 0,1,2)' ($ring2.Count -eq 3)
T 'ring-1 slave gets 2 admins (ring 0,1 -- NOT ring 2)' ($ring1.Count -eq 2 -and ($ring1.UserName -notcontains 'PIMSCEN-Admin-MSPHelp-L2-T2-ID'))
T 'ring-0 slave gets ONLY the broad ring-0 admin' ($ring0.Count -eq 1 -and $ring0[0].UserName -eq 'PIMSCEN-Admin-MSPGlobal-L0-T0-ID')
# fail-safe: a row with no Ring is dropped (never silently synced everywhere)
$withNoRing = $baselineAdmins + @([pscustomobject]@{ UserName = 'PIMSCEN-NoRing'; Template = 'x' })
T 'a no-ring admin row is dropped (fail-safe)' ((@(Select-PimDownlinkAdmins -Admins $withNoRing -SlaveRing 2)).Count -eq 3)
# deterministic order (ring then name)
T 'filtered set is sorted by ring then name' ($ring2[0].Ring -le $ring2[1].Ring -and $ring2[1].Ring -le $ring2[2].Ring)
# hashtable rows (the seeder shape) also work
$htAdmins = @(@{ UserName = 'A-L0'; Ring = 0 }, @{ UserName = 'A-L2'; Ring = 2 })
T 'ring filter accepts hashtable rows too' ((@(Select-PimDownlinkAdmins -Admins $htAdmins -SlaveRing 0)).Count -eq 1)

# ===========================================================================
Write-Host "`n== 2. SIGNATURE / VALIDITY VERIFY (ephemeral key) ==" -ForegroundColor Cyan
# ===========================================================================
$good = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner
$vGood = Test-PimDownlinkBaseline -Doc $good.doc -PublicKey $rsaSigner
T 'VALID signed bundle verifies' ($vGood.ok -and $null -ne $vGood.payload)

# tampered: flip a byte in the payloadB64 (decode, mutate, re-encode) -> sig must fail
$pb = [Convert]::FromBase64String($good.doc.payloadB64); $pb[10] = [byte](($pb[10] + 1) % 256)
$tampered = [pscustomobject]@{ product='PIM4EntraPS'; payloadB64=[Convert]::ToBase64String($pb); signature=$good.doc.signature; keyThumbprint='x' }
$vTamper = Test-PimDownlinkBaseline -Doc $tampered -PublicKey $rsaSigner
T 'TAMPERED payload is rejected (sig invalid)' (-not $vTamper.ok -and $vTamper.reason -match '(?i)invalid|verify')

# wrong key: verify the good doc with an unrelated public key -> fail
$vWrong = Test-PimDownlinkBaseline -Doc $good.doc -PublicKey $rsaWrong
T 'WRONG-KEY signature is rejected' (-not $vWrong.ok)

# expired: validToUtc in the past -> fail (signature is valid; expiry gate trips)
$exp = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -ValidToUtc ([datetime]::UtcNow.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ'))
$vExp = Test-PimDownlinkBaseline -Doc $exp.doc -PublicKey $rsaSigner
T 'EXPIRED bundle is rejected' (-not $vExp.ok -and $vExp.reason -match '(?i)expired')

# anti-rollback: version below the last-applied floor -> fail
$old = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Version 100
$vRb = Test-PimDownlinkBaseline -Doc $old.doc -PublicKey $rsaSigner -LastVersion 200
T 'ROLLBACK (version < last-applied) is refused' (-not $vRb.ok -and $vRb.reason -match '(?i)rollback')
# same version (==) is allowed (re-apply is idempotent, not a rollback)
$vSame = Test-PimDownlinkBaseline -Doc $old.doc -PublicKey $rsaSigner -LastVersion 100
T 'same version (re-apply) is allowed (not a rollback)' ($vSame.ok)

# wrong product / kind rejected even with a valid signature
$badKind = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Kind 'central-kill'
$vKind = Test-PimDownlinkBaseline -Doc $badKind.doc -PublicKey $rsaSigner -AllowedKind @('baseline')
T 'unexpected kind is rejected' (-not $vKind.ok -and $vKind.reason -match '(?i)kind')

# malformed doc (no signature) -> not-a-bundle, never throws
$vNone = Test-PimDownlinkBaseline -Doc ([pscustomobject]@{ payloadB64 = 'x' }) -PublicKey $rsaSigner
T 'doc missing signature -> ok=false (no throw)' (-not $vNone.ok)

# ===========================================================================
Write-Host "`n== 3. SYNC-FILE PATH RESOLUTION (per scenario) ==" -ForegroundColor Cyan
# ===========================================================================
$cRoot = 'C:\msp\sync'; $lRoot = 'C:\local\sync'; $tid = '11111111-2222-3333-4444-555555555552'
$pC = Resolve-PimDownlinkSyncPath -SyncFileLocation 'central-msp' -TenantId $tid -CentralRoot $cRoot -LocalRoot $lRoot
$pL = Resolve-PimDownlinkSyncPath -SyncFileLocation 'local-slave' -TenantId $tid -CentralRoot $cRoot -LocalRoot $lRoot
$pN = Resolve-PimDownlinkSyncPath -SyncFileLocation 'none'        -TenantId $tid -CentralRoot $cRoot -LocalRoot $lRoot
T 'central-msp routes to the CENTRAL root, per-tenant subfolder' ($pC.stage -and $pC.tenantFolder -eq (Join-Path $cRoot $tid))
T 'local-slave routes to the LOCAL root, per-tenant subfolder'   ($pL.stage -and $pL.tenantFolder -eq (Join-Path $lRoot $tid))
T 'none stages nothing'                                          (-not $pN.stage)
T 'central path matches what the matrix reads ($env:PIM_SyncRootCentral/<tid>/*.json)' ($pC.files.admins -like (Join-Path (Join-Path $cRoot $tid) '*.json'))
# the resolved syncFileLocation per scenario MATCHES Get-PimScenarioEntryPlan (S5 central, S6 local)
T 'S5 entry-plan syncFileLocation = central-msp' ((Get-PimScenarioEntryPlan -Scenario 'S5').syncFileLocation -eq 'central-msp')
T 'S6 entry-plan syncFileLocation = local-slave' ((Get-PimScenarioEntryPlan -Scenario 'S6').syncFileLocation -eq 'local-slave')

# ===========================================================================
Write-Host "`n== 4. SYNC CONTENT + IDEMPOTENCY ==" -ForegroundColor Cyan
# ===========================================================================
$content1 = New-PimDownlinkSyncContent -Admins $ring2 -TenantId $tid -SlaveRing 2 -BaselineVersion 100
$content2 = New-PimDownlinkSyncContent -Admins $ring2 -TenantId $tid -SlaveRing 2 -BaselineVersion 100
T 'identical inputs produce byte-identical content (stable JSON)' ($content1.admins -eq $content2.admins -and $content1.manifest -eq $content2.manifest)
$idemSame = Test-PimDownlinkIdempotent -NewContent $content1 -ExistingContent $content2
T 'idempotent: identical existing content -> no change (second pass no-op)' (-not $idemSame.changed)
# a different admin set -> changed
$content3 = New-PimDownlinkSyncContent -Admins $ring1 -TenantId $tid -SlaveRing 1 -BaselineVersion 100
$idemDiff = Test-PimDownlinkIdempotent -NewContent $content3 -ExistingContent $content1
T 'idempotent: changed content is detected' ($idemDiff.changed -and $idemDiff.changedFiles.Count -gt 0)
# CRLF/LF round-trip is not a false change (normalise to LF first, then to CRLF,
# so JSON that already carries CRLF isn't turned into CR-CR-LF)
$toCrlf = { param($s) ($s -replace "`r`n", "`n") -replace "`n", "`r`n" }
$crlf = @{ admins = (& $toCrlf $content1.admins); manifest = (& $toCrlf $content1.manifest) }
$idemCrlf = Test-PimDownlinkIdempotent -NewContent $content1 -ExistingContent $crlf
T 'CRLF/LF round-trip is NOT a false change' (-not $idemCrlf.changed)
# missing existing file -> changed (first write)
$idemMissing = Test-PimDownlinkIdempotent -NewContent $content1 -ExistingContent @{}
T 'missing existing files -> changed (first write)' ($idemMissing.changed)

# ===========================================================================
Write-Host "`n== 5. DOWNLINK PLAN (verify + ring + paths + content) ==" -ForegroundColor Cyan
# ===========================================================================
$planS6 = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner `
    -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot
T 'S6 plan OK; 3 admins reach ring-2 slave' ($planS6.ok -and $planS6.admins.Count -eq 3)
T 'S6 plan stages to the LOCAL root' ($planS6.sync.stage -and $planS6.sync.tenantFolder -eq (Join-Path $lRoot $tid))
$planS5 = Get-PimDownlinkPlan -Scenario 'S5' -Doc $good.doc -PublicKey $rsaSigner `
    -TenantId $tid -SlaveRing 1 -CentralRoot $cRoot -LocalRoot $lRoot
T 'S5 plan OK; ring-1 slave gets 2 admins; CENTRAL root' ($planS5.ok -and $planS5.admins.Count -eq 2 -and $planS5.sync.tenantFolder -eq (Join-Path $cRoot $tid))
# bad signature -> plan REFUSES (ok=false, no admins, no staging)
$planBad = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaWrong `
    -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot
T 'bad-signature plan REFUSES (ok=false, empty admins)' (-not $planBad.ok -and $planBad.admins.Count -eq 0)
# a non-managed scenario (S1) is refused by the downlink plan
$planS1 = Get-PimDownlinkPlan -Scenario 'S1' -Doc $good.doc -PublicKey $rsaSigner `
    -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot
T 'S1 (single) is not a downlink scenario -> plan ok=false' (-not $planS1.ok)
# plan can take BaselineAdmins explicitly (overriding payload.rows)
$planExplicit = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner `
    -BaselineAdmins @([pscustomobject]@{ UserName='X'; Ring=0 }) -TenantId $tid -SlaveRing 0 -CentralRoot $cRoot -LocalRoot $lRoot
T 'explicit -BaselineAdmins are used + ring-gated' ($planExplicit.ok -and $planExplicit.admins.Count -eq 1)

# ===========================================================================
Write-Host "`n== 6. SCENARIO RUNNER TOPOLOGY BRANCH ==" -ForegroundColor Cyan
# ===========================================================================
$rS1 = Get-PimScenarioRunPlan -Scenario 'S1'
$rS3 = Get-PimScenarioRunPlan -Scenario 'S3'
$rS5 = Get-PimScenarioRunPlan -Scenario 'S5'
$rS6 = Get-PimScenarioRunPlan -Scenario 'S6'
T 'S1 (single) -> engine-apply only, no downlink' (-not $rS1.runDownlink -and $rS1.steps -contains 'engine-apply' -and $rS1.steps -notcontains 'downlink-sync')
T 'S3 (master) -> engine-apply only, no downlink' (-not $rS3.runDownlink -and $rS3.steps -notcontains 'downlink-sync')
T 'S5 (managed central) -> downlink-sync THEN engine-apply' ($rS5.runDownlink -and $rS5.steps[0] -eq 'downlink-sync' -and $rS5.steps[-1] -eq 'engine-apply')
T 'S6 (managed local) -> downlink-sync THEN engine-apply'   ($rS6.runDownlink -and $rS6.steps[0] -eq 'downlink-sync' -and $rS6.steps[-1] -eq 'engine-apply')

# ===========================================================================
Write-Host "`n== 7. CAPABILITY PROBE (matrix Get-Command targets exist) ==" -ForegroundColor Cyan
# ===========================================================================
# The live matrix's Test-SyncWiringBuilt probes for these names via Get-Command;
# the scenario-runner steps probe for Invoke-PimScenarioDeploy. Assert they resolve
# when PIM-ScenarioProfile.ps1 is loaded (the matrix's load path).
T 'Invoke-PimManagedDownlink is defined (sync-wiring-built probe)' ($null -ne (Get-Command Invoke-PimManagedDownlink -ErrorAction SilentlyContinue))
T 'Sync-PimMasterToSlave is defined (sync-wiring-built probe)'     ($null -ne (Get-Command Sync-PimMasterToSlave -ErrorAction SilentlyContinue))
T 'Invoke-PimScenarioSync is defined (sync-wiring-built probe)'    ($null -ne (Get-Command Invoke-PimScenarioSync -ErrorAction SilentlyContinue))
T 'Invoke-PimScenarioDeploy is defined (scenario-runner probe)'    ($null -ne (Get-Command Invoke-PimScenarioDeploy -ErrorAction SilentlyContinue))

# ===========================================================================
Write-Host "`n== 8. RING GATE: ONE CUSTOMER, BOTH DIRECTIONS (Test-PimDownlinkRingGate) ==" -ForegroundColor Cyan
# ===========================================================================
# Operator directive 2026-08-07: measure the MSP ring promise with ONE customer whose
# ring MOVES, simulated on the two test tenants, rather than blocking on a third,
# slave-only tenant. The live matrix (tests/live/Test-PimScenarioMatrix.ps1, step
# 'ring-gate-one-customer-both-directions') feeds the REAL signed baseline through
# Get-PimDownlinkPlan at rings 0/1/2 and hands the result to THIS SAME pure function --
# so proving it here proves the live verdict's logic, and the two cannot drift.
#
# Why this replaced a presence check: asking "does admin X exist in the slave tenant?"
# is unanswerable when the slave IS the master (it holds every admin from its own
# estate). Asking what the gate SELECTS for one customer is a property of the DECISION,
# so a shared tenant cannot confound it.

# Build the ring->selection map through the REAL gate + the REAL signed bundle.
$rgRows = @{}
foreach ($r in 0, 1, 2) {
    $p = Get-PimDownlinkPlan -Scenario 'S5' -Doc $good.doc -PublicKey $rsaSigner `
            -TenantId $tid -SlaveRing $r -CentralRoot $cRoot -LocalRoot $lRoot
    $rgRows[$r] = @($p.admins)
}
$rgGood = Test-PimDownlinkRingGate -RingRows $rgRows
T 'a CORRECT gate passes on one customer'                  ($rgGood.ok)
T '  ...and is not vacuous (the ring genuinely changes it)' (-not $rgGood.vacuous)
T '  ...with no failures recorded'                          ($rgGood.failures.Count -eq 0)
T '  BOTH DIRECTIONS: ring-2 admin excluded at ring 0, admitted at ring 2' `
    ($rgGood.gained -contains 'PIMSCEN-Admin-MSPHelp-L2-T2-ID' -and $rgGood.gained -contains 'PIMSCEN-Admin-MSPCloud-L1-T1-ID')
T '  narrow ring really is narrower (ring0=1, ring2=3)' ($rgGood.names[0].Count -eq 1 -and $rgGood.names[2].Count -eq 3)

# --- DETECTION: a gate that LEAKS must be caught (this is the whole point) ---
# Simulate the failure the MSP promise is about: a ring-2 admin reaching a ring-0
# customer. If this passed, the assertion would be decorative.
$leaky = @{
    0 = @($baselineAdmins)                                            # <- everything, at ring 0
    1 = @($baselineAdmins)
    2 = @($baselineAdmins)
}
$rgLeak = Test-PimDownlinkRingGate -RingRows $leaky
T 'DETECTION: a gate that ships everything to ring 0 FAILS' (-not $rgLeak.ok)
T '  ...and reports it as a RING LEAK'                      (($rgLeak.failures -join ' ') -match 'RING LEAK at ring 0')

# --- DETECTION: a NON-MONOTONIC gate must be caught ---
# A wider ring must never drop somebody a narrower ring selected.
$nonMono = @{
    0 = @($baselineAdmins | Where-Object { $_.Ring -eq 0 })
    1 = @($baselineAdmins | Where-Object { $_.Ring -eq 1 })           # <- lost the ring-0 admin
    2 = @($baselineAdmins)
}
$rgNM = Test-PimDownlinkRingGate -RingRows $nonMono
T 'DETECTION: a non-monotonic gate FAILS'      (-not $rgNM.ok)
T '  ...and says it is not monotonic'          (($rgNM.failures -join ' ') -match 'not a monotonic gate')

# --- VACUOUS is reported as vacuous, never as a quiet pass ---
# An estate whose admins all sit at ring 0 satisfies monotonicity and exclusion while
# proving nothing about gating. The live matrix turns this into a SKIP with the reason.
$allRing0 = @([pscustomobject]@{ UserName = 'A-L0'; Ring = 0 })
$rgVac = Test-PimDownlinkRingGate -RingRows @{ 0 = $allRing0; 1 = $allRing0; 2 = $allRing0 }
T 'VACUOUS estate is flagged vacuous, not passed' ($rgVac.vacuous -and -not $rgVac.ok)
T '  ...and records no false failure'             ($rgVac.failures.Count -eq 0)
T '  ...and explains it as an ESTATE SHAPE (admins all at the narrowest ring)' `
    ($rgVac.vacuousReason -match 'already reaches the narrowest ring')

# --- an EMPTY baseline must NOT be reported as "all admins are at ring 0" ---
# These two are both "vacuous" but have different causes: an empty bundle is a BROKEN
# INPUT (e.g. signed before the estate was seeded), not an estate shape. The live run of
# 2026-08-07 hit exactly this and the original wording -- "every baseline admin (0)
# already reaches ring 0" -- actively misdirected the diagnosis.
$rgEmpty = Test-PimDownlinkRingGate -RingRows @{ 0 = @(); 1 = @(); 2 = @() }
T 'EMPTY baseline is vacuous'                        ($rgEmpty.vacuous -and -not $rgEmpty.ok)
T '  ...and is named as an EMPTY/BROKEN baseline'    ($rgEmpty.vacuousReason -match 'NO admin rows at all')
T '  ...and points at the generated-before-seed cause' ($rgEmpty.vacuousReason -match 'AFTER the estate was seeded')

# ===========================================================================
Write-Host "`n== 9. BUG-29 WIRING -- the version gate is actually REACHABLE ==" -ForegroundColor Cyan
# ===========================================================================
# The gate itself was built in session 9 and asserted here. What was NEVER built was
# the path TO it: nothing constructed a plan and nothing passed one. Worse, on
# inspection PIM-RingGate.ps1 was dot-sourced by NO runtime path at all -- only by
# Test-PimDeployContract.ps1 -- so Get-PimTemplateRingPlan was not even DEFINED in a
# production process. These assertions are about the WIRING, not the decision.
. (Join-Path $root 'engine\_shared\PIM-RingGate.ps1')

$blv = "$($good.doc.payload.version)"
if (-not $blv.Trim()) { $blv = "$((Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot).baselineVersion)" }

$mapAssign = [pscustomobject]@{ "$tid" = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ ring = 2 } } }
$mapMatch  = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ '2' = [pscustomobject]@{ version = $blv } } } }
$mapAhead  = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ '2' = [pscustomobject]@{ version = '9999999999' } } } }
$mapNone   = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ '1' = [pscustomobject]@{ version = $blv } } } }

# The plan builder the entry script uses must exist and resolve.
T 'Get-PimTemplateRingPlan is DEFINED (RingGate is reachable)' ([bool](Get-Command Get-PimTemplateRingPlan -ErrorAction SilentlyContinue))

$rpMatch = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId $tid -Assignments $mapAssign -Promotions $mapMatch
T 'assigned + approved version -> update' ($rpMatch.Action -eq 'update' -and "$($rpMatch.Version)" -eq $blv)
$pMatch = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot -RingPlan $rpMatch
T 'the APPROVED version passes the gate' ($pMatch.ok -and $pMatch.admins.Count -eq 3)

$rpAhead = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId $tid -Assignments $mapAssign -Promotions $mapAhead
$pAhead = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot -RingPlan $rpAhead
T 'a version the ring does NOT approve is REFUSED' (-not $pAhead.ok)
T '  ...and the reason names both versions' ($pAhead.reason -match 'ring version mismatch' -and $pAhead.reason -match '9999999999')
T '  ...and it stages NOTHING' (@($pAhead.admins).Count -eq 0 -and $null -eq $pAhead.sync)

$rpHold = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId $tid -Assignments $mapAssign -Promotions $mapNone
T 'assigned to a ring with NO promotion -> hold' ($rpHold.Action -eq 'hold')
$pHold = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot -RingPlan $rpHold
T 'a HOLD pulls nothing (a forgotten promotion is not success)' (-not $pHold.ok -and $pHold.reason -match 'ring HOLD')

# 🔒 THE NON-BREAKING RULE, asserted twice: an UNASSIGNED tenant, and no map at all,
# must both behave exactly as the VERIFIED S5/S6 runs did.
$rpUnassigned = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'nobody-at-all' -Assignments $mapAssign -Promotions $mapMatch
T 'an UNASSIGNED managed tenant -> track-current' ($rpUnassigned.Action -eq 'track-current')
$pUnassigned = Get-PimDownlinkPlan -Scenario 'S6' -Doc $good.doc -PublicKey $rsaSigner -TenantId $tid -SlaveRing 2 -CentralRoot $cRoot -LocalRoot $lRoot -RingPlan $rpUnassigned
T '  ...and pulls exactly as before (no version restriction)' ($pUnassigned.ok -and $pUnassigned.admins.Count -eq 3)
T 'NO -RingPlan at all is byte-identical to before' ($planS6.ok -and $planS6.admins.Count -eq 3)

# The ORCHESTRATOR must forward the plan -- this is the link that did not exist.
$dlSrc = Get-Content -Raw (Join-Path $root 'engine\_shared\PIM-Downlink.ps1')
T 'Invoke-PimManagedDownlink accepts -RingPlan' ($dlSrc -match '(?s)function Invoke-PimManagedDownlink.{0,2000}?\[object\]\$RingPlan')
T '  ...and forwards it to Get-PimDownlinkPlan' ($dlSrc -match "planArgs\['RingPlan'\]" -and $dlSrc -match '-LastVersion \$LastVersion @planArgs')

# IMP-12: WHICH mechanism creates the accounts is a property of the TOPOLOGY, and the
# S6 branch did not exist -- Invoke-PimDownlinkAdminApply was called by this test file and
# nothing else, while the orchestrator ran the S5 fan-out on both topologies. On S6 that
# created no accounts at all, so every projected membership pointed at a principal that
# does not exist while the roles apply still reported success.
T 'IMP-12: the orchestrator stages the admins itself on the PULL topology' ($dlSrc -match '(?s)function Invoke-PimManagedDownlink.*?Invoke-PimDownlinkAdminApply')
T '  ...and branches on the topology, not on a borrowed variable' ($dlSrc -match '\$isPushTopology = Test-PimDownlinkPushTopology -Scenario \$Scenario' -and $dlSrc -match 'if \(\$isPushTopology\) \{')
# The branch itself, tested as a decision rather than as source text. It resolves the
# scenario itself on purpose: an earlier draft read a variable belonging to another
# function, which answered "not push" for EVERY scenario and disabled the fan-out on the
# one topology that needs it.
T 'S5 (central-hosted) is a PUSH topology -- the central host writes the accounts' (Test-PimDownlinkPushTopology -Scenario 'S5')
T 'S6 (local-hosted) is a PULL topology -- the managed tenant writes its own' (-not (Test-PimDownlinkPushTopology -Scenario 'S6'))
T 'a scenario that stages nothing is never treated as push' (-not (Test-PimDownlinkPushTopology -Scenario 'S1'))
T '  ...taking the slave domain from a parameter or the ambient tenant, never a guess' `
    ($dlSrc -match '\[string\]\$SlaveDefaultDomain' -and $dlSrc -match 'Get-PimTargetDefaultDomain' -and $dlSrc -match 'Refusing to build UPNs at a guessed domain')
T '  ...and reports the admin apply in its result' ($dlSrc -match 'admins = \$adminApply')

# The ENTRY SCRIPT must build the plan from the master's published map.
$syncSrc = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'setup\Invoke-PimDownlinkSync.ps1')
T 'IMP-12: the entry script exposes -SlaveDefaultDomain and forwards it' ($syncSrc -match '\$SlaveDefaultDomain' -and $syncSrc -match "dlArgs\['SlaveDefaultDomain'\]")
# BUG-63: the entry script reads and writes the SLAVE's Azure SQL, which needs a token --
# and it never loaded the token provider. A dot-sourced function's $script: binds to the
# CALLING scope, so PIM-Rest's resource/cache tables were $null there: every token attempt
# threw, New-PimSqlConnection presented NO credential, and Azure SQL answered
# "Login failed for user ''" -- which reads as a permissions problem and is not one.
$restIdx = $syncSrc.IndexOf("PIM-Rest.ps1")
$storeIdx = $syncSrc.IndexOf("PIM-SqlStore.ps1")
$profIdx = $syncSrc.IndexOf("PIM-ScenarioProfile.ps1")
T 'BUG-63: the entry script dot-sources the token provider at all' ($restIdx -ge 0)
T '  ...BEFORE PIM-SqlStore, which is the documented order' ($restIdx -ge 0 -and $storeIdx -gt $restIdx)
T '  ...and before the scenario profile pulls in the SQL-touching cores' ($restIdx -ge 0 -and $profIdx -gt $restIdx)
# ...and the provider itself must survive being called from a scope that did not load it.
$restSrc = Get-Content -Raw (Join-Path $root 'engine\_shared\PIM-Rest.ps1')
T '  ...and the resource map re-seeds itself when called cross-scope' ($restSrc -match 'if \(-not \$script:PimRestResources\) \{ \$script:PimRestResources = Get-PimRestResourceMap \}')
T '  ...as does the token cache (an unseeded cache is a MISS, not a throw)' ($restSrc -match 'if \(-not \$script:PimTokenCache\) \{ \$script:PimTokenCache = @\{\} \}')
# BUG-60: a slave's existing group tags live across the definition entities the ENGINE
# reads. Reading only 'PIM-Definitions' reported a fully-modelled tenant as having none.
T 'BUG-60: the entry script reads the slave tags from every definition entity' ($syncSrc -match "PIM-Definitions-Roles'\s*,\s*'PIM-Definitions-Services")
T 'the entry script dot-sources PIM-RingGate.ps1' ($syncSrc -match "PIM-RingGate\.ps1")
T '  ...exposes -TemplateRingMapPath/-Url' ($syncSrc -match '\$TemplateRingMapPath' -and $syncSrc -match '\$TemplateRingMapUrl')
T '  ...builds the plan from the map' ($syncSrc -match 'Get-PimTemplateRingPlan')
T '  ...and passes it to the orchestrator' ($syncSrc -match "dlArgs\['RingPlan'\]")
T '  ...and SAYS SO when no map is supplied' ($syncSrc -match 'version gate INERT')
# BUG-26 discipline in new code: assign, then use. Never @(pipeline).
T '  ...and parses the map by assigning first (BUG-26)' ($syncSrc -notmatch '@\(Get-Content -LiteralPath \$TemplateRingMapPath -Raw \| ConvertFrom-Json\)')

# The shipped sample map must be real, parseable, and shaped as the resolver expects.
$sampleRing = Join-Path (Split-Path -Parent $PSScriptRoot) 'config\template-ring-map.sample.json'
T 'a sample template ring map ships' (Test-Path $sampleRing)
if (Test-Path $sampleRing) {
    $srm = (Get-Content -Raw $sampleRing) | ConvertFrom-Json
    T '  ...it parses and has assignments + promotions' ($null -ne $srm.assignments -and $null -ne $srm.promotions)
    T '  ...default is null (the non-breaking rule)' ($null -eq $srm.default)
    $sampleTid = @($srm.assignments.PSObject.Properties)[0].Name
    $rpSample = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId $sampleTid -Assignments $srm.assignments -Promotions $srm.promotions
    T '  ...and the SHIPPED file resolves to a real update' ($rpSample.Action -eq 'update' -and "$($rpSample.Version)".Trim())
    # 🪤 THE CHANNEL TRAP, pinned. Plane 2 defaults to -Channel 'managed'; plane 1 uses
    # 'internal'. This sample was FIRST WRITTEN with 'internal' and resolved to a silent
    # -looking HOLD -- caught by the assertion above. Both halves are asserted so the
    # sample and the resolver can never drift apart on channel vocabulary.
    T '  ...on the MANAGED channel, not plane 1s internal' ($null -ne $srm.promotions.'Baseline'.'managed')
    $rpWrongChan = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId $sampleTid -Assignments $srm.assignments -Promotions $srm.promotions -Channel 'internal'
    T '  ...and the WRONG channel HOLDS loudly, never falls back' ($rpWrongChan.Action -eq 'hold' -and $rpWrongChan.Reason -match "no 'internal' channel")
}

# ===========================================================================
Write-Host "`n== 7. ROLE PROJECTION -- control #2 (MSP-2) ==" -ForegroundColor Cyan
# ===========================================================================
# The master's admin->PIM-group memberships, keyed on the LOGIN name (what the
# bundle carries; the slave rebuilds the UPN). Ring 0/1/2 admins as above.
$mspAssignments = @(
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPGlobal-L0-T0-ID'; GroupTag = 'ROLE-SecurityLead';  AssignmentType = 'Eligible'; Permanent = 'FALSE'; NumOfDaysWhenExpire = '365' }
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPCloud-L1-T1-ID';  GroupTag = 'ROLE-CloudEngineer'; AssignmentType = 'Eligible'; Permanent = 'FALSE'; NumOfDaysWhenExpire = '90' }
    [pscustomobject]@{ UserName = 'PIMSCEN-Admin-MSPHelp-L2-T2-ID';   GroupTag = 'ROLE-Helpdesk';      AssignmentType = 'Eligible'; Permanent = 'FALSE'; NumOfDaysWhenExpire = '90' }
)
$allNames = @($baselineAdmins | ForEach-Object { $_.UserName })

# -- default: no policy => allow ALL (the operator decision) ------------------
$pDefault = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $allNames
T 'no policy projects every assignment (allow-all default)' (@($pDefault.projected).Count -eq 3 -and @($pDefault.excluded).Count -eq 0)

# -- deny narrows, and says why ----------------------------------------------
$pDeny = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $allNames `
    -Policy @(@{ Mode = 'deny'; GroupTag = 'ROLE-SecurityLead' })
T 'a deny rule removes exactly that tag' (@($pDeny.projected).Count -eq 2 -and @($pDeny.projected | Where-Object { $_.GroupTag -eq 'ROLE-SecurityLead' }).Count -eq 0)
T '  ...and the exclusion carries a reason' (@($pDeny.excluded).Count -eq 1 -and "$($pDeny.excluded[0].reason)" -match 'denied by relationship policy')

# -- any allow rule flips to allow-LIST --------------------------------------
$pAllow = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $allNames `
    -Policy @(@{ Mode = 'allow'; GroupTag = 'ROLE-CloudEngineer' })
T 'an allow rule makes it an allow-LIST (1 of 3)' (@($pAllow.projected).Count -eq 1 -and $pAllow.projected[0].GroupTag -eq 'ROLE-CloudEngineer')
T '  ...the rest are excluded as not-allow-listed' (@($pAllow.excluded).Count -eq 2 -and "$($pAllow.excluded[0].reason)" -match 'allow-list')

# -- deny beats allow --------------------------------------------------------
$pBoth = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $allNames `
    -Policy @(@{ Mode = 'allow'; GroupTag = 'ROLE-*' }, @{ Mode = 'deny'; GroupTag = 'ROLE-SecurityLead' })
T 'deny wins over a matching allow' (@($pBoth.projected).Count -eq 2 -and @($pBoth.projected | Where-Object { $_.GroupTag -eq 'ROLE-SecurityLead' }).Count -eq 0)
T 'a trailing-* allow pattern matches by prefix' (@($pBoth.projected | Where-Object { $_.GroupTag -eq 'ROLE-CloudEngineer' }).Count -eq 1)

# -- 🔒 the ring gate must bind the ROLES too, not just the accounts ----------
# A ring-2 consultant does not reach a ring-1 slave; neither may their roles.
$ring1Names = @($ring1 | ForEach-Object { $_.UserName })
$pRing = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $ring1Names
T 'an admin outside the ring cannot project roles' (@($pRing.projected).Count -eq 2 -and @($pRing.projected | Where-Object { $_.UserName -eq 'PIMSCEN-Admin-MSPHelp-L2-T2-ID' }).Count -eq 0)
T '  ...and that exclusion names the ring as the cause' ("$(@($pRing.excluded)[0].reason)" -match 'did not reach')

# -- unresolvable tags are REPORTED, never silently dropped ------------------
$pUnres = Select-PimProjectedAssignments -Assignments $mspAssignments -AdminUserNames $allNames `
    -SlaveGroupTags @('ROLE-CloudEngineer', 'ROLE-Helpdesk')
T 'a tag the slave has no group for is UNRESOLVED, not projected' (@($pUnres.projected).Count -eq 2 -and @($pUnres.unresolved).Count -eq 1)
T '  ...and it is not silently counted as excluded-by-policy' ($pUnres.unresolved[0].GroupTag -eq 'ROLE-SecurityLead' -and @($pUnres.excluded).Count -eq 0)

# -- malformed rows do not become half-rows ----------------------------------
$pBad = Select-PimProjectedAssignments -Assignments @([pscustomobject]@{ UserName = 'x'; GroupTag = '' }) -AdminUserNames @('x')
T 'a row with no GroupTag is excluded as malformed' (@($pBad.projected).Count -eq 0 -and "$($pBad.excluded[0].reason)" -match 'malformed')

# -- the PLAN carries it end to end, and stays inert for an OLD bundle --------
$docWith = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Assignments $mspAssignments
$planWith = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docWith.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP
T 'the plan projects assignments carried by the bundle' ($planWith.ok -and @($planWith.assignments).Count -eq 3)
T '  ...and reports the count in its reason' ("$($planWith.reason)" -match '3 role assignment\(s\) projected')
T '  ...and stages an assignments sync file' ($planWith.content.ContainsKey('assignments'))
T '  ...whose manifest counts them' (("$($planWith.content.manifest)" | ConvertFrom-Json).assignmentCount -eq 3)

$docNone = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner
$planNone = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docNone.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP
T 'an OLD bundle (no assignments key) projects nothing' ($planNone.ok -and @($planNone.assignments).Count -eq 0 -and $null -eq $planNone.projection)
T '  ...and stages NO assignments file (byte-identical to pre-control-#2)' (-not $planNone.content.ContainsKey('assignments'))
T '  ...and its admins file is unchanged by the feature' ("$($planNone.content.admins)" -eq "$($planWith.content.admins)")

# -- the policy reaches the plan ---------------------------------------------
$planDeny = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docWith.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP `
    -ProjectionPolicy @(@{ Mode = 'deny'; GroupTag = 'ROLE-SecurityLead' })
T 'a relationship policy reaches the plan' (@($planDeny.assignments).Count -eq 2)
T '  ...and the reason says how many were excluded' ("$($planDeny.reason)" -match '1 excluded by policy')

# unresolved tags must be visible in the plan's reason, not buried in a file
$planUnres = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docWith.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP `
    -SlaveGroupTags @('ROLE-CloudEngineer')
T 'unresolved tags are surfaced in the plan reason' ("$($planUnres.reason)" -match 'UNRESOLVED')

# -- determinism: same input, byte-identical content (the idempotency contract)
$planWith2 = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docWith.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP
T 'projection is deterministic (byte-identical re-plan)' ("$($planWith2.content.assignments)" -eq "$($planWith.content.assignments)")
$idemProj = Test-PimDownlinkIdempotent -NewContent $planWith2.content -ExistingContent $planWith.content
T '  ...so a second pass is a no-op' (-not $idemProj.changed)

# ===========================================================================
Write-Host "`n== 8. ROLE APPLY into the slave store -- the blast-radius rules ==" -ForegroundColor Cyan
# ===========================================================================
# The apply is the one part of control #2 that can DAMAGE a customer: it writes
# into the slave's PIM-Assignments-Admins, where the customer's OWN delegation
# lives. These fakes stand in for the three store primitives so the rules are
# proven with no SQL -- what matters here is which rows it touches, not SQL.
$script:fakeStore = @{}
function Get-PimSqlRows { param($ConnectionString, $Entity) @($script:fakeStore.Values) }
function Set-PimSqlRow  { param($ConnectionString, $Entity, $Key, $Data) $script:fakeStore[$Key] = $Data }
function Remove-PimSqlRow { param($ConnectionString, $Entity, $Key) $script:fakeStore.Remove($Key) }

# The slave already has the customer's own delegation and one row this sync planted
# on a previous run. Two local shapes are present ON PURPOSE: a row stamped
# Owner='Local' (the documented tag) AND an UNSTAMPED row -- every row that predates
# this feature is unstamped, and inferring those into MSP ownership would make the
# customer's existing delegation prunable by an MSP sync. Owner is provenance, and
# absent provenance must fail SAFE to Local.
$script:fakeStore = [ordered]@{
    'local-admin-ride|ROLE-LocalOps'                  = [ordered]@{ Username = 'local-admin-ride'; GroupTag = 'ROLE-LocalOps'; Owner = 'Local' }
    'legacy-admin-ride|ROLE-Unstamped'                = [ordered]@{ Username = 'legacy-admin-ride'; GroupTag = 'ROLE-Unstamped' }
    'PIMSCEN-Admin-MSPGlobal-L0-T0-ID|ROLE-Stale'     = [ordered]@{ Username = 'PIMSCEN-Admin-MSPGlobal-L0-T0-ID'; GroupTag = 'ROLE-Stale'; Owner = 'MSP' }
}
$applied = Invoke-PimDownlinkAssignmentApply -ConnectionString 'fake' -Assignments $mspAssignments -WhatIfMode:$false
T 'the projected rows are written' ($applied.ok -and $applied.created -eq 3)
T 'SAFETY: an Owner=Local row is NEVER touched' ($script:fakeStore.Contains('local-admin-ride|ROLE-LocalOps'))
T 'SAFETY: an UNSTAMPED legacy row is NEVER touched (absent Owner fails safe to Local)' ($script:fakeStore.Contains('legacy-admin-ride|ROLE-Unstamped'))
T '  ...both counted as foreign, not as ours to prune' ($applied.skippedForeign -eq 2)
T 'a row THIS sync planted but no longer projects is pruned' (-not $script:fakeStore.Contains('PIMSCEN-Admin-MSPGlobal-L0-T0-ID|ROLE-Stale') -and $applied.removed -eq 1)
T 'rows are keyed Username|GroupTag (the stores natural key)' ($script:fakeStore.Contains('PIMSCEN-Admin-MSPCloud-L1-T1-ID|ROLE-CloudEngineer'))
$w = $script:fakeStore['PIMSCEN-Admin-MSPCloud-L1-T1-ID|ROLE-CloudEngineer']
T '  ...written as Username (lower n) or the key derives BLANK' ($w.Contains('Username'))
T '  ...carrying the BARE login name for the UPN fallback' ("$($w.Username)" -notmatch '@')
T '  ...stamped Owner=MSP -- the PROJECTS existing provenance vocabulary' ("$($w.Owner)" -eq 'MSP')

# 🔒 empty projection must NOT be read as "revoke everything"
$script:fakeStore = [ordered]@{
    'local-admin-ride|ROLE-LocalOps'      = [ordered]@{ Username = 'local-admin-ride'; GroupTag = 'ROLE-LocalOps' }
    'PIMSCEN-Admin-MSPCloud-L1-T1-ID|ROLE-CloudEngineer' = [ordered]@{ Username = 'PIMSCEN-Admin-MSPCloud-L1-T1-ID'; GroupTag = 'ROLE-CloudEngineer'; Owner = 'MSP' }
}
$empty = Invoke-PimDownlinkAssignmentApply -ConnectionString 'fake' -Assignments @() -WhatIfMode:$false
T 'SAFETY: an EMPTY projection prunes NOTHING (mass-revoke guard)' ($empty.removed -eq 0 -and @($empty.wouldPrune).Count -eq 1)
T '  ...and says so instead of reporting a clean run' ("$($empty.detail)" -match 'REFUSED to prune')
T '  ...leaving the previously-synced row in place' ($script:fakeStore.Contains('PIMSCEN-Admin-MSPCloud-L1-T1-ID|ROLE-CloudEngineer'))

# ...but an explicit decouple DOES withdraw exactly what the sync added
$decouple = Invoke-PimDownlinkAssignmentApply -ConnectionString 'fake' -Assignments @() -AllowFullPrune -WhatIfMode:$false
T 'an explicit -AllowFullPrune withdraws the synced rows' ($decouple.removed -eq 1 -and -not $script:fakeStore.Contains('PIMSCEN-Admin-MSPCloud-L1-T1-ID|ROLE-CloudEngineer'))
T '  ...and STILL leaves the customers own rows alone' ($script:fakeStore.Contains('local-admin-ride|ROLE-LocalOps'))

# whatif changes nothing
$script:fakeStore = [ordered]@{}
$wi = Invoke-PimDownlinkAssignmentApply -ConnectionString 'fake' -Assignments $mspAssignments
T 'whatif reports the plan and writes nothing' ($wi.created -eq 3 -and $script:fakeStore.Count -eq 0 -and "$($wi.detail)" -match '\[whatif\]')

# ===========================================================================
Write-Host "`n== 9. GROUP DEFINITIONS -- BUG-59, 'MSP groups, customer may extend' ==" -ForegroundColor Cyan
# ===========================================================================
# The master's model: a role group nesting two service groups, each bound to an Entra role.
$mspDefs = [ordered]@{
    groups = @(
        [pscustomobject]@{ GroupTag = 'ROLE-CloudEngineer';   GroupName = 'PIM-ROLE-CloudEngineer';   IsRoleAssignable = 'FALSE' }
        [pscustomobject]@{ GroupTag = 'ROLE-SecurityLead';    GroupName = 'PIM-ROLE-SecurityLead';    IsRoleAssignable = 'FALSE' }
        [pscustomobject]@{ GroupTag = 'SVC-IntuneAdmin-L1';   GroupName = 'PIM-SVC-IntuneAdmin-L1';   IsRoleAssignable = 'TRUE' }
        [pscustomobject]@{ GroupTag = 'SVC-GlobalAdmin-L0';   GroupName = 'PIM-SVC-GlobalAdmin-L0';   IsRoleAssignable = 'TRUE' }
        [pscustomobject]@{ GroupTag = 'ROLE-Unreferenced';    GroupName = 'PIM-ROLE-Unreferenced';    IsRoleAssignable = 'FALSE' }
    )
    # DIRECTION (BUG-61): TargetGroupTag is the ROLE group, SourceGroupTag the permission
    # group it draws from -- the shipped contract (docs/DESIGN.md, the authoring dropdowns,
    # and the engine's GroupNesting provider verified against a live tenant). These fixtures
    # had the two columns swapped, so they asserted the closure walked the wrong way.
    nestings = @(
        [pscustomobject]@{ TargetGroupTag = 'ROLE-CloudEngineer'; SourceGroupTag = 'SVC-IntuneAdmin-L1' }
        [pscustomobject]@{ TargetGroupTag = 'ROLE-SecurityLead';  SourceGroupTag = 'SVC-GlobalAdmin-L0' }
    )
    roleBindings = @(
        [pscustomobject]@{ GroupTag = 'SVC-IntuneAdmin-L1'; RoleDefinitionName = 'Intune Administrator' }
        [pscustomobject]@{ GroupTag = 'SVC-GlobalAdmin-L0'; RoleDefinitionName = 'Global Administrator' }
    )
}

# -- an EMPTY tenant (BUG-59's measured state): we stand the whole model up ---
$dEmpty = Select-PimProjectedDefinitions -Definitions $mspDefs -ProjectedTags @('ROLE-CloudEngineer') -SlaveGroupTags @()
T 'an EMPTY tenant gets the role group created' (@($dEmpty.create | Where-Object { $_.GroupTag -eq 'ROLE-CloudEngineer' }).Count -eq 1)
T '  ...AND the service group it nests (transitive closure)' (@($dEmpty.create | Where-Object { $_.GroupTag -eq 'SVC-IntuneAdmin-L1' }).Count -eq 1)
T '  ...with the nesting and the Entra role binding' (@($dEmpty.nestings).Count -eq 1 -and @($dEmpty.roleBindings).Count -eq 1 -and $dEmpty.roleBindings[0].RoleDefinitionName -eq 'Intune Administrator')
T '  ...and NOTHING for an unprojected role (no over-sharing)' (@($dEmpty.create | Where-Object { $_.GroupTag -like '*SecurityLead*' -or $_.GroupTag -eq 'ROLE-Unreferenced' }).Count -eq 0)
T '  ...the unreferenced group is skipped WITH a reason' (@($dEmpty.skipped | Where-Object { $_.GroupTag -eq 'ROLE-Unreferenced' -and $_.reason -match 'not reached' }).Count -eq 1)

# -- the CUSTOMER already owns that tag: we yield ----------------------------
$dOwned = Select-PimProjectedDefinitions -Definitions $mspDefs -ProjectedTags @('ROLE-CloudEngineer') -SlaveGroupTags @('ROLE-CloudEngineer')
T 'a tag the customer already has is DEFERRED, not created' (@($dOwned.create | Where-Object { $_.GroupTag -eq 'ROLE-CloudEngineer' }).Count -eq 0 -and @($dOwned.defer | Where-Object { $_.GroupTag -eq 'ROLE-CloudEngineer' }).Count -eq 1)
T '  ...and the deferral says the customer owns it' ("$(@($dOwned.defer)[0].reason)" -match 'customer owns it')
T 'SAFETY: no nesting is written INTO a customer-owned role group' (@($dOwned.nestings).Count -eq 0)
T '  ...and that refusal is reported, not silent' (@($dOwned.skipped | Where-Object { $_.reason -match 'role group is customer-owned' }).Count -eq 1)
T 'SAFETY: we do NOT rebind Entra roles on a group we did not create' (@($dOwned.roleBindings | Where-Object { $_.GroupTag -eq 'ROLE-CloudEngineer' }).Count -eq 0)

# -- mixed: customer owns the role group, we still create the service group --
# The service group is only reachable THROUGH the deferred role group, so its
# nesting is refused -- creating it would leave an orphan with a live Entra role.
T 'a service group reached only via a customer-owned role group is not wired up' (@($dOwned.nestings).Count -eq 0)

# -- the plan carries definitions end to end --------------------------------
$docDefs = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Assignments $mspAssignments
$planDefs = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docDefs.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP
T 'a bundle with NO definitions leaves the plan definition-free' ($null -eq $planDefs.definitions)

# 🪤 the regression BUG-59 would otherwise cause: with definitions present, a tag the
# slave lacks must NOT be called unresolved -- we are about to create it.
$defsPayload = @{ groups = @([pscustomobject]@{ GroupTag = 'ROLE-CloudEngineer'; GroupName = 'g' }); nestings = @(); roleBindings = @() }
$docFull = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Assignments @($mspAssignments[1]) -Definitions $defsPayload
$planFull = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docFull.doc -PublicKey $rsaSigner -TenantId '11111111-1111-1111-1111-111111111111' -SlaveRing 2 -LocalRoot $env:TEMP -SlaveGroupTags @()
T 'a creatable tag is NOT counted as unresolved in an empty tenant' (@($planFull.assignments).Count -eq 1 -and @($planFull.projection.unresolved).Count -eq 0)
T '  ...and the plan says the group will be created' ($null -ne $planFull.definitions -and @($planFull.definitions.create).Count -eq 1 -and "$($planFull.reason)" -match 'to CREATE')

# ===========================================================================
Write-Host "`n== 10. POLICY DELIVERED IN THE SIGNED BUNDLE (per relationship) ==" -ForegroundColor Cyan
# ===========================================================================
# 🪤 WHY THE POLICY CANNOT BE READ FROM THE MASTER REGISTRY AT DOWNLINK TIME: a process
# holds ONE ambient identity, so a run cannot read the MASTER's SQL and write the SLAVE's
# store -- different tenants, different credentials -- and in S6 the downlink runs inside
# the slave, which has no credential for the master at all. So it rides in the payload,
# keyed by tenant id, and is signed with everything else.
$tidA = '11111111-1111-1111-1111-111111111111'
$tidB = '22222222-2222-2222-2222-222222222222'
$polPayload = [ordered]@{
    $tidA = @([ordered]@{ Mode = 'deny'; GroupTag = 'ROLE-SecurityLead' })
    $tidB = @()
}
$docPol = New-TestSignedBaseline -Rows $baselineAdmins -Signer $rsaSigner -Assignments $mspAssignments -ProjectionPolicy $polPayload

$planA = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docPol.doc -PublicKey $rsaSigner -TenantId $tidA -SlaveRing 2 -LocalRoot $env:TEMP
T 'the bundles policy for THIS tenant is applied' (@($planA.assignments | Where-Object { $_.GroupTag -eq 'ROLE-SecurityLead' }).Count -eq 0 -and @($planA.assignments).Count -eq 2)
T '  ...with the deny reason preserved' (@($planA.projection.excluded | Where-Object { $_.reason -match 'denied by relationship policy' }).Count -eq 1)

# a DIFFERENT tenant in the same fleet-wide bundle is unaffected -- the whole point of keying it
$planB = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docPol.doc -PublicKey $rsaSigner -TenantId $tidB -SlaveRing 2 -LocalRoot $env:TEMP
T 'another relationship in the SAME bundle is unaffected' (@($planB.assignments).Count -eq 3)

# a tenant with no entry at all = allow-all (the operator's default), not deny-all
$planC = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docPol.doc -PublicKey $rsaSigner -TenantId '33333333-3333-3333-3333-333333333333' -SlaveRing 2 -LocalRoot $env:TEMP
T 'a tenant absent from the policy map projects everything (allow-all default)' (@($planC.assignments).Count -eq 3)

# an explicit -ProjectionPolicy still wins, for tests and one-off operator overrides
$planD = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docPol.doc -PublicKey $rsaSigner -TenantId $tidA -SlaveRing 2 -LocalRoot $env:TEMP `
    -ProjectionPolicy @(@{ Mode = 'deny'; GroupTag = 'ROLE-CloudEngineer' })
T 'an explicit -ProjectionPolicy overrides the bundles' (@($planD.assignments | Where-Object { $_.GroupTag -eq 'ROLE-SecurityLead' }).Count -eq 1)

# 🔒 the policy is INSIDE the signed payload -- widening it locally breaks the signature
$polBytes = [Convert]::FromBase64String($docPol.doc.payloadB64)
$polText = [System.Text.Encoding]::UTF8.GetString($polBytes).Replace('"deny"', '"allw"')
$forged = [pscustomobject]@{ product = 'PIM4EntraPS'; payloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($polText)); signature = $docPol.doc.signature; keyThumbprint = 'x' }
$vForged = Test-PimDownlinkBaseline -Doc $forged -PublicKey $rsaSigner
T 'SAFETY: a tenant cannot widen its OWN projection (signature breaks)' (-not $vForged.ok)

# ===========================================================================
Write-Host "`n== 11. CONTROL #1 on the S6 pull path -- admins staged into the slave store ==" -ForegroundColor Cyan
# ===========================================================================
# The fan-out PUSHES with a per-tenant certificate (S5-shaped, and IMP-11 records that
# reach as unavailable). On S6 the slave's own engine has the identity and the tick, so
# it is handed desired rows instead. Same Owner-scoped discipline as the other applies.
$script:fakeStore = [ordered]@{
    'local-admin-hogym' = [ordered]@{ UserName = 'local-admin-hogym'; DisplayName = 'HOGYM local'; Owner = 'Local' }
    'legacy-no-owner'   = [ordered]@{ UserName = 'legacy-no-owner'; DisplayName = 'predates the feature' }
    'PIMSCEN-Admin-MSPHelp-L2-T2-ID' = [ordered]@{ UserName = 'PIMSCEN-Admin-MSPHelp-L2-T2-ID'; DisplayName = 'stale'; Owner = 'MSP' }
}
$ring1Admins = @(Select-PimDownlinkAdmins -Admins $baselineAdmins -SlaveRing 1)
$adm = Invoke-PimDownlinkAdminApply -ConnectionString 'fake' -Admins $ring1Admins -DefaultDomain 'slave.onmicrosoft.com' -WhatIfMode:$false
T 'the ring-reached admins are staged' ($adm.ok -and $adm.created -eq 2)
T 'SAFETY: the customers OWN admins are untouched (Local and unstamped)' ($script:fakeStore.Contains('local-admin-hogym') -and $script:fakeStore.Contains('legacy-no-owner') -and $adm.skippedForeign -eq 2)
T 'an admin who no longer reaches this ring is withdrawn' (-not $script:fakeStore.Contains('PIMSCEN-Admin-MSPHelp-L2-T2-ID') -and $adm.removed -eq 1)
$w = $script:fakeStore['PIMSCEN-Admin-MSPGlobal-L0-T0-ID']
T 'the UPN is rebuilt against the SLAVES domain' ("$($w.UserPrincipalName)" -eq 'PIMSCEN-Admin-MSPGlobal-L0-T0-ID@slave.onmicrosoft.com')
T '  ...which is what keeps the origin legible in the name' ("$($w.UserName)" -like '*MSPGlobal*')
# 🔑 REVERSED BY OPERATOR DECISION 2026-08-13. This assertion used to demand CreateTAP='FALSE'
# ("a synced admin must not mint a TAP in a customer tenant"). Measured against a live managed
# tenant, that produced six enabled, fully-delegated accounts NOBODY COULD SIGN IN AS -- the TAP
# is the only credential an engine-created admin ever gets. The withheld credential did not
# reduce the privilege, it just made it unusable. TAP is now ON by default, per-admin overridable
# from the master's registry, and this test asserts the new contract in both directions.
T 'a synced admin CAN sign in: TAP is ON by default' ("$($w.CreateTAP)" -eq 'TRUE')
T '  ...with a concrete lifetime, never the blank that made the engine guess' ("$($w.TAPLifetimeHours)" -eq '8')
T '  ...and is stamped Owner=MSP so a decouple finds exactly these' ("$($w.Owner)" -eq 'MSP')
T '  ...keyed on UserName (the stores natural key for this entity)' ($script:fakeStore.Contains('PIMSCEN-Admin-MSPCloud-L1-T1-ID'))
T 'the run REPORTS how many admins got a TAP (never silent)' ($adm.tapEnabled -eq 2 -and "$($adm.detail)" -match 'TAP on for 2')

# The silent half: a TAP with no recipient is minted and delivered NOWHERE, and the code cannot
# be recovered. That must surface as a warning, and a supplied default must clear it.
T 'WARNS when TAP is on but no ManagerEmail can be resolved' ($adm.tapWithoutRecipient -eq 2 -and "$($adm.detail)" -match 'never delivered')
$script:fakeStore = [ordered]@{}
$admMgr = Invoke-PimDownlinkAdminApply -ConnectionString 'fake' -Admins $ring1Admins -DefaultDomain 'slave.onmicrosoft.com' -DefaultManagerEmail 'msp-ops@example.com' -WhatIfMode:$false
T '  ...and -DefaultManagerEmail gives the TAP mail somewhere to go' ($admMgr.tapWithoutRecipient -eq 0 -and "$($script:fakeStore['PIMSCEN-Admin-MSPGlobal-L0-T0-ID'].ManagerEmail)" -eq 'msp-ops@example.com')

# The opt-out still exists -- "default ON" is a default, not a removal of the choice.
$script:fakeStore = [ordered]@{}
$admOff = Invoke-PimDownlinkAdminApply -ConnectionString 'fake' -Admins $ring1Admins -DefaultDomain 'slave.onmicrosoft.com' -CreateTapDefault 'FALSE' -WhatIfMode:$false
T 'a relationship can still opt OUT of TAP issuance' ("$($script:fakeStore['PIMSCEN-Admin-MSPGlobal-L0-T0-ID'].CreateTAP)" -eq 'FALSE' -and $admOff.tapEnabled -eq 0)

# A per-admin value from the master's registry BEATS the fleet default, in both directions.
$script:fakeStore = [ordered]@{}
$perAdmin = @($ring1Admins | ForEach-Object { $c = $_.PSObject.Copy(); $c | Add-Member -NotePropertyName CreateTap -NotePropertyValue $false -Force; $c })
$admPer = Invoke-PimDownlinkAdminApply -ConnectionString 'fake' -Admins $perAdmin -DefaultDomain 'slave.onmicrosoft.com' -WhatIfMode:$false
T 'the masters PER-ADMIN intent overrides the fleet default' ($admPer.tapEnabled -eq 0)

# the same empty-desired guard as the other applies
$script:fakeStore = [ordered]@{ 'PIMSCEN-Admin-MSPCloud-L1-T1-ID' = [ordered]@{ UserName = 'PIMSCEN-Admin-MSPCloud-L1-T1-ID'; Owner = 'MSP' } }
$admEmpty = Invoke-PimDownlinkAdminApply -ConnectionString 'fake' -Admins @() -DefaultDomain 'slave.onmicrosoft.com' -WhatIfMode:$false
T 'SAFETY: an EMPTY baseline withdraws NOBODY' ($admEmpty.removed -eq 0 -and @($admEmpty.wouldPrune).Count -eq 1 -and "$($admEmpty.detail)" -match 'REFUSED to prune')

# ===========================================================================
Write-Host "`n== 12. MSP-4 TARGETING (tags) + CLASS GATING (capabilities) ==" -ForegroundColor Cyan
# ===========================================================================
# --- the target grammar ----------------------------------------------------
$tid1 = '11111111-1111-1111-1111-111111111111'
T 'no target = every tenant (absent target must not change behaviour)' ((Test-PimArtifactTarget -Target '' -TenantId $tid1).match)
T "'*' targets all" ((Test-PimArtifactTarget -Target '*' -TenantId $tid1).match)
T 'a bare word is read as a TAG (the common case)' ((Test-PimArtifactTarget -Target 'retail' -TenantId $tid1 -TenantTags @('retail')).match)
T '  ...and misses when the tenant lacks it' (-not (Test-PimArtifactTarget -Target 'retail' -TenantId $tid1 -TenantTags @('finance')).match)
T "explicit 'tag:' works too" ((Test-PimArtifactTarget -Target 'tag:tier0-pilot' -TenantId $tid1 -TenantTags @('tier0-pilot')).match)
T 'an explicit tenant id targets exactly that tenant' ((Test-PimArtifactTarget -Target "tenant:$tid1" -TenantId $tid1).match)
T '  ...and nobody else' (-not (Test-PimArtifactTarget -Target "tenant:$tid1" -TenantId '22222222-2222-2222-2222-222222222222').match)
T 'a list matches on ANY selector (5 of 28)' ((Test-PimArtifactTarget -Target 'retail;tag:vip' -TenantId $tid1 -TenantTags @('vip')).match)
T 'matching is case-insensitive' ((Test-PimArtifactTarget -Target 'Retail' -TenantId $tid1 -TenantTags @('RETAIL')).match)

# 🔒 MSP-local is declarable, and cannot be overridden by a selector added beside it
$none = Test-PimArtifactTarget -Target 'none' -TenantId $tid1 -TenantTags @('retail')
T "SAFETY: 'none' means MSP-LOCAL -- never published" (-not $none.match -and "$($none.reason)" -match 'MSP-local by declaration')
T "  ...and 'none' WINS over another selector in the same expression" (-not (Test-PimArtifactTarget -Target 'retail;none' -TenantId $tid1 -TenantTags @('retail')).match)
T 'a non-match always explains itself' ((Test-PimArtifactTarget -Target 'finance' -TenantId $tid1 -TenantTags @('retail')).reason -match 'matches none of the target selectors')

# --- the class gate (RING-1 capabilities, the CUSTOMER's own opt-out) -------
T 'nothing blocked = allowed (inert until a customer opts out)' ((Test-PimDownlinkClassAllowed -Class 'roles').allowed)
T 'a blocked class is refused' (-not (Test-PimDownlinkClassAllowed -Class 'roles' -BlockedCapabilities @('msp-roles')).allowed)
T '  ...naming the capability the CUSTOMER blocked' ((Test-PimDownlinkClassAllowed -Class 'roles' -BlockedCapabilities @('msp-roles')).reason -match 'the customer blocked')
T 'blocking one class does not block another' ((Test-PimDownlinkClassAllowed -Class 'admins' -BlockedCapabilities @('msp-roles')).allowed)
T 'class names map to the msp-* capability vocabulary' ((Get-PimDownlinkCapabilityName -Class 'policies') -eq 'msp-policies')

# --- end to end through the plan -------------------------------------------
$tgtAdmins = @(
    [pscustomobject]@{ UserName = 'A-ALL';   Ring = 2; DisplayName = 'all' }
    [pscustomobject]@{ UserName = 'A-VIP';   Ring = 2; DisplayName = 'vip only'; Target = 'vip' }
    [pscustomobject]@{ UserName = 'A-LOCAL'; Ring = 2; DisplayName = 'msp local'; Target = 'none' }
)
$tgtAssign = @(
    [pscustomobject]@{ UserName = 'A-ALL'; GroupTag = 'ROLE-CloudEngineer'; AssignmentType = 'Eligible' }
    [pscustomobject]@{ UserName = 'A-ALL'; GroupTag = 'ROLE-Special'; AssignmentType = 'Eligible'; Target = 'tag:vip' }
)
$docT = New-TestSignedBaseline -Rows $tgtAdmins -Signer $rsaSigner -Assignments $tgtAssign

$planPlain = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docT.doc -PublicKey $rsaSigner -TenantId $tid1 -SlaveRing 2 -LocalRoot $env:TEMP -TenantTags @()
T 'an untagged tenant gets only the untargeted admin' (@($planPlain.admins).Count -eq 1 -and $planPlain.admins[0].UserName -eq 'A-ALL')
T '  ...the MSP-local one is never offered' (@($planPlain.notTargeted | Where-Object { $_.name -eq 'A-LOCAL' -and $_.reason -match 'MSP-local' }).Count -eq 1)
T '  ...and the vip-only role is not projected' (@($planPlain.assignments | Where-Object { $_.GroupTag -eq 'ROLE-Special' }).Count -eq 0)
T '  ...with the plan naming targeting as the cause' ("$($planPlain.reason)" -match 'not TARGETED at this tenant')

$planVip = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docT.doc -PublicKey $rsaSigner -TenantId $tid1 -SlaveRing 2 -LocalRoot $env:TEMP -TenantTags @('vip')
T 'a vip tenant additionally gets the vip admin' (@($planVip.admins).Count -eq 2)
T '  ...and the vip role' (@($planVip.assignments | Where-Object { $_.GroupTag -eq 'ROLE-Special' }).Count -eq 1)
T '  ...but STILL never the MSP-local admin' (@($planVip.admins | Where-Object { $_.UserName -eq 'A-LOCAL' }).Count -eq 0)

# the customer's own block reaches the downlink
$planBlocked = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docT.doc -PublicKey $rsaSigner -TenantId $tid1 -SlaveRing 2 -LocalRoot $env:TEMP -TenantTags @('vip') -BlockedCapabilities @('msp-roles')
T 'a customer who blocked msp-roles gets NO roles' (@($planBlocked.assignments).Count -eq 0)
T '  ...but still gets the admins (blocking one class is not blocking all)' (@($planBlocked.admins).Count -eq 2)
T '  ...reported as HELD, not as "nothing to do"' ("$($planBlocked.reason)" -match 'HELD -- the customer blocked' -and @($planBlocked.classHeld).Count -ge 1)

# 🪤 the four narrowings must stay distinguishable
T 'SAFETY: targeting and class-gating are reported SEPARATELY' ($null -ne $planBlocked.notTargeted -and $null -ne $planBlocked.classHeld)

# tags delivered in the SIGNED bundle (a slave cannot read the master's registry)
$docTags = New-TestSignedBaseline -Rows $tgtAdmins -Signer $rsaSigner -Assignments $tgtAssign -ProjectionPolicy @{}
$payloadWithTags = [ordered]@{ $tid1 = @('vip') }
$docTags2 = New-TestSignedBaseline -Rows $tgtAdmins -Signer $rsaSigner -Assignments $tgtAssign
# rebuild with a tenantTags map by signing a payload that carries it
$plTags = [ordered]@{
    product = 'PIM4EntraPS'; kind = 'baseline'; version = 2606170000; scope = 'fleet'
    generatedAtUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    validToUtc = [datetime]::UtcNow.AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    rows = $tgtAdmins; assignments = $tgtAssign; tenantTags = $payloadWithTags
}
$plBytes = [System.Text.Encoding]::UTF8.GetBytes(($plTags | ConvertTo-Json -Depth 8 -Compress))
$docSigned = [pscustomobject]@{ product = 'PIM4EntraPS'; payloadB64 = [Convert]::ToBase64String($plBytes)
    signature = [Convert]::ToBase64String($rsaSigner.SignData($plBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)); keyThumbprint = 'x' }
$planFromBundle = Get-PimDownlinkPlan -Scenario 'S6' -Doc $docSigned -PublicKey $rsaSigner -TenantId $tid1 -SlaveRing 2 -LocalRoot $env:TEMP
T 'tenant tags ride in the SIGNED bundle (the slave cannot read the master registry)' (@($planFromBundle.admins).Count -eq 2 -and @($planFromBundle.tenantTags) -contains 'vip')

# ===========================================================================
Write-Host "`n== 13. THE TWO BUGS FOUND BY SELF-REVIEW ==" -ForegroundColor Cyan
# ===========================================================================
# BUG E: the definition closure must reach a FIXPOINT. A -> B -> C: a single pass
# stops at B, so C is never created and the admin gets part of their delegation.
$deepDefs = [ordered]@{
    groups = @(
        [pscustomobject]@{ GroupTag = 'ROLE-A'; GroupName = 'a' }
        [pscustomobject]@{ GroupTag = 'SVC-B'; GroupName = 'b' }
        [pscustomobject]@{ GroupTag = 'SVC-C'; GroupName = 'c' }
        [pscustomobject]@{ GroupTag = 'SVC-D'; GroupName = 'd' }
    )
    # ROLE-A draws from SVC-B, which draws from SVC-C, which draws from SVC-D
    # (Target = the group that RECEIVES, Source = where the permission comes FROM).
    nestings = @(
        [pscustomobject]@{ TargetGroupTag = 'ROLE-A'; SourceGroupTag = 'SVC-B' }
        [pscustomobject]@{ TargetGroupTag = 'SVC-B'; SourceGroupTag = 'SVC-C' }
        [pscustomobject]@{ TargetGroupTag = 'SVC-C'; SourceGroupTag = 'SVC-D' }
    )
    roleBindings = @([pscustomobject]@{ GroupTag = 'SVC-D'; RoleDefinitionName = 'Deep Admin' })
}
$deep = Select-PimProjectedDefinitions -Definitions $deepDefs -ProjectedTags @('ROLE-A') -SlaveGroupTags @()
T 'BUG E: a 3-deep nesting chain is followed to the END, not one level' (@($deep.create | Where-Object { $_.GroupTag -eq 'SVC-D' }).Count -eq 1)
T '  ...so all 4 groups are created' (@($deep.create).Count -eq 4)
T '  ...and the deep role binding comes with it' (@($deep.roleBindings | Where-Object { $_.RoleDefinitionName -eq 'Deep Admin' }).Count -eq 1)
# a cycle must terminate rather than hang
$cyc = [ordered]@{
    groups = @([pscustomobject]@{ GroupTag = 'G1' }, [pscustomobject]@{ GroupTag = 'G2' })
    nestings = @([pscustomobject]@{ SourceGroupTag = 'G1'; TargetGroupTag = 'G2' }, [pscustomobject]@{ SourceGroupTag = 'G2'; TargetGroupTag = 'G1' })
    roleBindings = @()
}
T '  ...and a CYCLE in the masters model terminates' ((Select-PimProjectedDefinitions -Definitions $cyc -ProjectedTags @('G1') -SlaveGroupTags @()).create.Count -eq 2)

# BUG F: the definition apply's mass-revoke guard must SAY it refused, like the others.
# 🪤 The fake store here is ENTITY-AWARE, unlike the simpler one in §8. It has to be:
# this function walks THREE entities, and a fake that returns every row for all of them
# lets a PIM-Definitions row surface again under PIM-Assignments-Roles-Groups (deriving
# the key 'ROLE-Stale|'), which inflates the count and tests nothing real. The live
# Get-PimSqlRows is scoped by entity, so the fake must be too.
$script:fakeByEntity = @{ 'PIM-Definitions' = [ordered]@{ 'ROLE-Stale' = [ordered]@{ GroupTag = 'ROLE-Stale'; Owner = 'MSP' } } }
function Get-PimSqlRows { param($ConnectionString, $Entity) if ($script:fakeByEntity.ContainsKey($Entity)) { @($script:fakeByEntity[$Entity].Values) } else { @() } }
function Set-PimSqlRow  { param($ConnectionString, $Entity, $Key, $Data) if (-not $script:fakeByEntity.ContainsKey($Entity)) { $script:fakeByEntity[$Entity] = [ordered]@{} }; $script:fakeByEntity[$Entity][$Key] = $Data }
function Remove-PimSqlRow { param($ConnectionString, $Entity, $Key) if ($script:fakeByEntity.ContainsKey($Entity)) { $script:fakeByEntity[$Entity].Remove($Key) } }

$emptyPlan = @{ create = @(); nestings = @(); roleBindings = @(); defer = @(); skipped = @() }
$defEmpty = Invoke-PimDownlinkDefinitionApply -ConnectionString 'fake' -DefinitionPlan $emptyPlan -WhatIfMode:$false
T 'BUG F: an empty definition set prunes NOTHING' ($defEmpty.removed -eq 0 -and $script:fakeByEntity['PIM-Definitions'].Contains('ROLE-Stale'))
T '  ...and REPORTS the refusal instead of skipping silently' ("$($defEmpty.detail)" -match 'REFUSED to prune' -and @($defEmpty.wouldPrune).Count -eq 1)
# ...and with something to write, the stale row IS withdrawn (the guard is not a block)
$livePlan = @{ create = @([pscustomobject]@{ GroupTag = 'ROLE-New'; GroupName = 'n' }); nestings = @(); roleBindings = @(); defer = @(); skipped = @() }
$defLive = Invoke-PimDownlinkDefinitionApply -ConnectionString 'fake' -DefinitionPlan $livePlan -WhatIfMode:$false
T '  ...but a NON-empty set does withdraw the stale row' ($defLive.removed -eq 1 -and -not $script:fakeByEntity['PIM-Definitions'].Contains('ROLE-Stale'))

# clean up the ephemeral keys
$rsaSigner.Dispose(); $rsaWrong.Dispose()

Write-Host ""
Write-Host ("==== Downlink test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
