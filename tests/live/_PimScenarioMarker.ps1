#Requires -Version 5.1
<#
  TEST-12 -- the marker contract, in one dot-sourceable place (REQUIREMENTS §33.7.e-2).

  Operator directive, given for BOTH live suites: "it must be easy to delete the tests
  (naming)." This file is the whole of that contract, isolated from any I/O so it can be
  unit-tested offline (tests/Test-PimScenarioCleanup.ps1) and reused by every scenario
  script. It has NO side effects -- dot-sourcing it only defines functions.

  ONE MARKER, one predicate, every object type: users, groups, AUs, schedules, blobs,
  files, SQL rows. Ownership is "the name CONTAINS the marker", case-insensitively.

  Why CONTAINS and not STARTS-WITH -- the trap TEST-11 paid for: a group name cannot LEAD
  with the marker. The engine's lean context fetches groups with
  startswith(displayName,'PIM') and the PimGroup filter is 'PIM-*', so a group called
  'PIMSCEN-...' is invisible to half the engine and the test silently exercises nothing.
  Scenario groups are therefore named 'PIM-PIMSCEN-<...>' and admin UPNs
  'Admin-PIMSCEN-<...>-ID@<domain>' (which must start with a configured admin prefix or
  the Admins scope's naming filter will not see them either). A CONTAINS predicate is what
  lets one rule cover both shapes.
#>

Set-StrictMode -Off

$script:PimScenarioMarker = 'PIMSCEN'

function Get-PimScenarioMarker { $script:PimScenarioMarker }

function Set-PimScenarioMarker {
    # Tests only. A blank marker would make EVERY name "owned" -- refuse it, because that
    # is the one input that would turn the guard below into a no-op.
    param([Parameter(Mandatory)][string]$Marker)
    $m = "$Marker".Trim()
    if (-not $m) { throw 'the scenario marker may never be blank -- every name would classify as owned' }
    $script:PimScenarioMarker = $m.ToUpperInvariant()
}

function Test-PimScenarioOwnedName {
    <#
      THE ownership predicate. $true only for a name this harness created.
      A null/blank name is NEVER owned -- a missing displayName must not become a licence
      to delete.
    #>
    [CmdletBinding()] param([string]$Name)
    $n = "$Name"
    if (-not $n.Trim()) { return $false }
    return $n.ToUpperInvariant().Contains($script:PimScenarioMarker)
}

function Assert-PimScenarioOwnedName {
    <#
      The guard every destructive call must pass through. THROWS on anything unmarked, so
      a run pointed at the wrong tenant deletes nothing even when the object id is real.

      Callers must NOT wrap this in the resilience try/catch they use for transient
      403/404 -- a guard failure has to surface. The convention in the sweep is to
      re-assert with this function immediately before the call, outside that catch.
    #>
    [CmdletBinding()] param([string]$Name, [string]$What = 'object')
    if (-not (Test-PimScenarioOwnedName -Name $Name)) {
        throw ("REFUSING to touch $What '$Name': it does not carry the '{0}' marker. " +
               'The scenario harness may only ever delete objects it created.') -f $script:PimScenarioMarker
    }
    return $true
}

function New-PimScenarioName {
    <#
      Build a marked name of the right SHAPE for its kind, so the naming traps above cannot
      be reintroduced by hand:
        group  -> PIM-PIMSCEN-<suffix>            (must start 'PIM-' to be visible)
        admin  -> Admin-PIMSCEN-<suffix>-ID       (must start with an admin prefix, carry -ID)
        au     -> PIMSCEN-AU-<suffix>             (no filter constraint)
        plain  -> PIMSCEN-<suffix>                (files, blobs, folders)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('group','admin','au','plain')][string]$Kind,
        [Parameter(Mandatory)][string]$Suffix
    )
    $m = $script:PimScenarioMarker
    $s = "$Suffix".Trim('-', ' ')
    switch ($Kind) {
        'group' { "PIM-$m-$s" }
        'admin' { "Admin-$m-$s-ID" }
        'au'    { "$m-AU-$s" }
        'plain' { "$m-$s" }
    }
}
