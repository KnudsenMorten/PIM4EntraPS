<#
  TEST-32 -- the estate's TOPOLOGY CLAIM, made machine-readable and checkable.

  🔴 THE HAZARD THIS CLOSES, IN ONE SENTENCE: a torn-down tenant could not make the estate matrix
  fail. HOGYM's hosting was removed on 2026-08-26 and `Run-PimMatrixEstate.ps1` went on reporting a
  green "managed slave verified" against it, because the driver keeps desired state in LOCAL SQL
  Express and reads the engine identity from the tenant's OWN vault -- both of which outlive a
  teardown. It never touched the tenant's Azure stack, so nothing it checked could notice. The green
  was true about the DIRECTORY and false about the CLAIM, which is the harder kind of wrong to see.

  🔑 THE FIX IS NOT "CHECK HARDER", IT IS "STATE THE CLAIM". The driver's own header already said
  *"ask what makes that tenant an instance of the topology it is standing in for, and confirm THAT
  is still true"* -- addressed to a human, at the moment they edit a default. That is a note, not a
  guard, and TEST-32's write-up says exactly this: *"nothing machine-readable states that today."*
  `estate-topology.json` now states it; this file checks it.

  PURE: takes the declaration and the OBSERVED facts, returns a verdict. No az, no network, no SQL,
  so the decision is testable offline and the observation is the caller's job.
#>

function Get-PimEstateTopologyClaims {
    <#
      Read the declaration. A missing or unreadable file is a REFUSAL, not an empty list: "no claims
      declared" would silently restore exactly the behaviour this exists to remove.
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not "$Path".Trim()) { $Path = Join-Path (Split-Path -Parent $PSCommandPath) 'estate-topology.json' }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "TEST-32: the estate topology declaration is missing ($Path). Refusing to run: without it nothing states what makes each tenant an instance of its topology, which is the condition that let a torn-down tenant report green."
    }
    try { $doc = (Get-Content -Raw -LiteralPath $Path) | ConvertFrom-Json }
    catch { throw "TEST-32: the estate topology declaration at '$Path' could not be parsed ($($_.Exception.Message)). Refusing to run rather than proceeding with no claims." }
    return @($doc.environments)
}

function Test-PimEstateTopologyClaim {
    <#
      PURE. Does the OBSERVED state match what this environment CLAIMS to be?

      -Observed is what the caller could actually establish about the tenant:
        @{ azureStackPresent = $true|$false|$null ; isManaged = $true|$false|$null ; publishesBaseline = ... }
      🔒 `$null` means NOT OBSERVED, and it is never treated as satisfied. That distinction is the
      whole point: "we looked and it is there" and "we did not look" must not produce the same
      verdict, which is the same failure family as a skipped test counted as a pass.

      Returns @{ ok; env; topology; failures[]; checked[] } -- failures name the FACT, so an operator
      is told which claim broke rather than that "the environment failed".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Claim,
        [Parameter(Mandatory)][hashtable]$Observed
    )
    $failures = New-Object System.Collections.Generic.List[string]
    $checked  = New-Object System.Collections.Generic.List[string]

    $envName = "$($Claim.env)"
    $topo    = "$($Claim.topology)"

    # --- the fact a teardown removes ------------------------------------------------
    if ([bool]$Claim.requiresAzureStack) {
        [void]$checked.Add('azureStackPresent')
        $v = $Observed['azureStackPresent']
        if ($null -eq $v) {
            [void]$failures.Add("azureStackPresent was NOT OBSERVED -- '$envName' claims topology '$topo', which requires a live PIM stack in the tenant. Not looking is not a pass: this is precisely the check that would have caught the torn-down slave.")
        } elseif (-not [bool]$v) {
            [void]$failures.Add("azureStackPresent is FALSE -- '$envName' claims to be '$topo' but has no live PIM deployment. The directory and the vault outlive a teardown; the stack does not. This tenant USED TO BE '$topo'.")
        }
    }
    # --- relationship facts ---------------------------------------------------------
    if ([bool]$Claim.mustBeManaged) {
        [void]$checked.Add('isManaged')
        $v = $Observed['isManaged']
        if ($null -eq $v)        { [void]$failures.Add("isManaged was NOT OBSERVED -- '$envName' claims '$topo', which is defined by having a master.") }
        elseif (-not [bool]$v)   { [void]$failures.Add("isManaged is FALSE -- '$envName' claims '$topo' but has no master relationship, so it cannot be exercising the managed path.") }
    }
    if ([bool]$Claim.mustNotBeManaged) {
        [void]$checked.Add('isManaged(negated)')
        $v = $Observed['isManaged']
        if ($null -eq $v)   { [void]$failures.Add("isManaged was NOT OBSERVED -- '$envName' claims '$topo', which is defined by having NO master.") }
        elseif ([bool]$v)   { [void]$failures.Add("isManaged is TRUE -- '$envName' claims to be standalone but has acquired a master relationship, so the standalone results are measuring something else.") }
    }
    if ([bool]$Claim.mustPublishBaseline) {
        [void]$checked.Add('publishesBaseline')
        $v = $Observed['publishesBaseline']
        if ($null -eq $v)      { [void]$failures.Add("publishesBaseline was NOT OBSERVED -- '$envName' claims '$topo', whose defining act is publishing the signed baseline.") }
        elseif (-not [bool]$v) { [void]$failures.Add("publishesBaseline is FALSE -- '$envName' claims to be the master but publishes no baseline, so no slave could pull from it.") }
    }

    # 🪤 A claim with NOTHING to check is not a passing claim, it is an unfalsifiable one -- the
    # state this whole finding is about. Declaring a topology without a single fact would restore
    # "the run came back green" as the only evidence, which TEST-32 says does not answer the question.
    if ($checked.Count -eq 0) {
        [void]$failures.Add("'$envName' declares topology '$topo' with NO checkable fact. An unfalsifiable claim is the condition TEST-32 exists to remove -- add at least one of requiresAzureStack / mustBeManaged / mustNotBeManaged / mustPublishBaseline.")
    }

    return @{
        ok       = ($failures.Count -eq 0)
        env      = $envName
        topology = $topo
        checked  = $checked.ToArray()
        failures = $failures.ToArray()
    }
}
