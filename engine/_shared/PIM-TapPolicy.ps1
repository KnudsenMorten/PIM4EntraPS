<#
  PIM4EntraPS -- Temporary Access Pass requests that CONFORM TO THE TENANT'S TAP POLICY.

  WHY THIS EXISTS (measured live on the internal environment, 2026-09-12 21:45 UTC):
      Create admin-...: POST /users/{id}/authentication/temporaryAccessPassMethods
      -> HTTP 400 badRequest -- Invalid IsUsableOnce specified. Tenant Policy does not allow
         multiple use temporary access pass method.
  v2 always sent isUsableOnce=$false, both from the AdminTap provider and from the Manager's queued
  tap-reset (PIM-QueueActions.ps1). A tenant whose TAP policy only allows one-time passes therefore
  could not onboard ANY admin. v1 sent isUsableOnce=$true (New-PimTemporaryAccessPass), so this was
  a v1 -> v2 regression on exactly the tenants with the stricter policy.

  THE RULE: read the tenant's TAP method configuration once per run (cached per tenant) and build
  the request from it --
      * isUsableOnce = $true when the policy forces one-time use;
      * lifetimeInMinutes clamped into [minimumLifetimeInMinutes, maximumLifetimeInMinutes].
  Reading that configuration needs Policy.Read.All (or Policy.ReadWrite.AuthenticationMethod) on the
  engine identity, which the shipped permission set does not include. When the read is not
  permitted the request keeps its defaults and, on EXACTLY the 400 above, is retried ONCE with
  isUsableOnce=$true -- and says so.

  ONE helper, used by both callers, so the two paths cannot disagree again. It never logs a code.
  PS 5.1-safe. Pure except for the two injectable scriptblocks (-Poster, -PolicyReader).
#>

Set-StrictMode -Off

function Get-PimTapTenantPolicy {
    <#
      The tenant's TAP method configuration, normalised:
        @{ readable; reason; isUsableOnce; defaultLifetimeInMinutes; minimumLifetimeInMinutes;
           maximumLifetimeInMinutes; defaultLength; state }
      Cached for -MaxAgeMinutes per tenant ($global:PIM_TapPolicyCache), so a run with many admins
      reads it once. An unreadable policy is cached too (a 403 does not become a 200 mid-run).
      -Reader: scriptblock returning the raw Graph object (test seam; the queue passes its invoker).
    #>
    [CmdletBinding()]
    param([scriptblock]$Reader, [switch]$Force, [int]$MaxAgeMinutes = 60)
    $tenant = ''
    if (Get-Command Get-PimTenantId -ErrorAction SilentlyContinue) { try { $tenant = "$(Get-PimTenantId)" } catch { $tenant = '' } }
    if (-not ($global:PIM_TapPolicyCache -is [hashtable])) { $global:PIM_TapPolicyCache = @{} }
    $key = if ($tenant) { $tenant.ToLowerInvariant() } else { 'default' }
    if (-not $Force -and $global:PIM_TapPolicyCache.ContainsKey($key)) {
        $c = $global:PIM_TapPolicyCache[$key]
        if ($c -and $c.at -and ([datetime]::UtcNow - $c.at).TotalMinutes -lt $MaxAgeMinutes) { return $c.policy }
    }
    $rd = $Reader
    if (-not $rd) { $rd = { Invoke-PimGraph -Path '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass' } }
    $pol = $null
    try {
        $raw = & $rd
        if ($null -eq $raw) { throw 'the TAP method configuration read returned nothing' }
        $num = { param($v) $n = 0; if ([int]::TryParse("$v", [ref]$n)) { return $n }; return 0 }
        $pol = [pscustomobject]@{
            readable                 = $true
            reason                   = ''
            isUsableOnce             = ("$($raw.isUsableOnce)" -match '(?i)^true$')
            defaultLifetimeInMinutes = (& $num $raw.defaultLifetimeInMinutes)
            minimumLifetimeInMinutes = (& $num $raw.minimumLifetimeInMinutes)
            maximumLifetimeInMinutes = (& $num $raw.maximumLifetimeInMinutes)
            defaultLength            = (& $num $raw.defaultLength)
            state                    = "$($raw.state)"
        }
    } catch {
        $pol = [pscustomobject]@{ readable = $false; reason = "$($_.Exception.Message)"; isUsableOnce = $false
                                  defaultLifetimeInMinutes = 0; minimumLifetimeInMinutes = 0; maximumLifetimeInMinutes = 0; defaultLength = 0; state = '' }
    }
    $global:PIM_TapPolicyCache[$key] = @{ at = [datetime]::UtcNow; policy = $pol }
    return $pol
}

function New-PimTapRequestBody {
    <#
      PURE. The TAP create body for a wanted lifetime, conformed to $Policy.
      Returns @{ body; adjustments } -- adjustments are human-readable notes (no secrets).
    #>
    [CmdletBinding()]
    param([int]$LifetimeMinutes = 240, [object]$Policy = $null, [string]$StartDateTime = '')
    $notes = New-Object System.Collections.Generic.List[string]
    $mins = $LifetimeMinutes
    # 2026-09-21 (operator: "we need to have a long tap length, 4 hr is not enough if you have 25 tenants where you must
    # login and setup"): -1 = "as long as this tenant allows" -- the tenant TAP policy's maximum (Entra allows up to 30
    # days); an unreadable policy -> 8 hours (Entra's own default maximum), never a value Entra would refuse.
    # Same day, operator: "set tap length for 48 hr", then "ignore the 48 hr tap request. we go with 8 hr" -- so -1 = 8 hours, capped at the tenant maximum.
    if ($mins -lt 0) {
        $pmax = if ($Policy -and $Policy.readable) { [int]$Policy.maximumLifetimeInMinutes } else { 0 }
        if ($pmax -gt 0) { $mins = [math]::Min(480, $pmax); [void]$notes.Add("no lifetime set on the admin -> 8 hours (480 min), capped at the tenant maximum $pmax min -> $mins min") }
        else { $mins = 480; [void]$notes.Add('no lifetime set on the admin and the tenant TAP policy could not be read -> 480 min (8 hours)') }
    }
    if ($mins -eq 0) { $mins = 240 }
    $once = $false
    if ($Policy -and $Policy.readable) {
        if ($Policy.isUsableOnce) { $once = $true; [void]$notes.Add('the tenant TAP policy forces one-time use -> isUsableOnce=true') }
        $min = [int]$Policy.minimumLifetimeInMinutes; $max = [int]$Policy.maximumLifetimeInMinutes
        if ($min -gt 0 -and $mins -lt $min) { [void]$notes.Add("lifetime $mins min is below the tenant minimum $min -> $min"); $mins = $min }
        if ($max -gt 0 -and $mins -gt $max) { [void]$notes.Add("lifetime $mins min is above the tenant maximum $max -> $max"); $mins = $max }
    }
    $body = @{ isUsableOnce = $once; lifetimeInMinutes = $mins }
    if ("$StartDateTime".Trim()) { $body['startDateTime'] = "$StartDateTime".Trim() }
    return [pscustomobject]@{ body = $body; adjustments = $notes.ToArray() }
}

function Test-PimTapUsableOnceRejection {
    # PURE. Is this the tenant refusing a MULTI-use pass? (the measured 400, and its variants)
    param([string]$Message)
    return ("$Message" -match '(?i)Invalid IsUsableOnce|does not allow multiple use temporary access pass')
}

function Invoke-PimTapCreate {
    <#
      Create ONE TAP, conformed to the tenant policy, with the single documented retry.
        -Poster       { param($Body) ... } -- performs the POST and returns the created method
        -PolicyReader { ... }              -- returns the raw TAP method configuration (optional)
      Throws whatever the POST throws when it is not the one-time-use refusal, or when the retry
      fails too. Returns the created TAP object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Poster,
        [int]$LifetimeMinutes = 240,
        [string]$StartDateTime = '',
        [scriptblock]$PolicyReader,
        [string]$UserLabel = ''
    )
    $pol = Get-PimTapTenantPolicy -Reader $PolicyReader
    $req = New-PimTapRequestBody -LifetimeMinutes $LifetimeMinutes -Policy $pol -StartDateTime $StartDateTime
    foreach ($n in @($req.adjustments)) { Write-Host "  [TAP] $UserLabel -- $n" -ForegroundColor DarkCyan }
    try {
        return (& $Poster $req.body)
    } catch {
        $msg = "$($_.Exception.Message)"
        if (-not $req.body['isUsableOnce'] -and (Test-PimTapUsableOnceRejection -Message $msg)) {
            $why = if ($pol.readable) { 'even though the policy read said multiple use is allowed' } else { "the policy could not be read ($($pol.reason)) -- grant Policy.Read.All to read it up front" }
            Write-Warning "  [TAP] $UserLabel -- the tenant only allows ONE-TIME Temporary Access Passes ($why). Retrying once with isUsableOnce=true."
            $req.body['isUsableOnce'] = $true
            # Remember it for the rest of the run, so the next admin does not hit the same 400.
            try {
                if ($global:PIM_TapPolicyCache -is [hashtable]) {
                    foreach ($k in @($global:PIM_TapPolicyCache.Keys)) {
                        $p = $global:PIM_TapPolicyCache[$k].policy
                        if ($p -and -not $p.readable) { $p.isUsableOnce = $true; $p.readable = $true; $p.reason = 'learned from a one-time-use refusal' }
                    }
                }
            } catch { }
            return (& $Poster $req.body)
        }
        throw
    }
}
