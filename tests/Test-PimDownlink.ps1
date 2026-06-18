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
        [string]$Kind = 'baseline'
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
$cRoot = 'C:\msp\sync'; $lRoot = 'C:\local\sync'; $tid = '9927fa1f-a09b-4244-8aba-60fb9ce7335e'
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

# clean up the ephemeral keys
$rsaSigner.Dispose(); $rsaWrong.Dispose()

Write-Host ""
Write-Host ("==== Downlink test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
