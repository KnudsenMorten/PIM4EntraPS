#Requires -Version 5.1
<#
.SYNOPSIS
    Functional test of the PIM Manager "Settings" admin area (REQUIREMENTS §11):
    naming conventions, filters, departments(+owners), approvers/owners managed
    through the active store (here: the offline file store, no SQL needed).

.DESCRIPTION
    Boots Open-PimManager.ps1 headless against a TEMP -ConfigRoot (so the file
    store + default-seeding write to a throwaway folder), captures the session
    bearer token, then proves over real HTTP (127.0.0.1):
      * GET /api/settings returns a non-empty naming map + non-empty filters
        (the hard requirement: naming/filters are auto-seeded, never empty).
      * The seed is PERSISTED -- manager-settings.custom.json appears on disk
        with NamingConventions + Filters keys.
      * PUT /api/settings/<section> round-trips for naming, filters,
        departments and approvers (write then read-back).
      * PUT rejects an EMPTY naming map / empty filter list (400) -- the
        never-empty invariant is enforced server-side.
    The launcher (no manager-access.custom.json in the temp dir) is SuperAdmin,
    so the write path is exercised. Rerunnable.
#>
[CmdletBinding()]
# -Port 0 (default) => boot helper allocates a FREE port at runtime (no fixed-port
# collision / no zombie-port hang). A non-zero -Port is accepted but ignored; the
# Manager always self-allocates and we use the port it actually bound.
param([int]$Port = 0)

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimManagerBoot.ps1')
$mgr  = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'

# Throwaway config root so seeding never touches the real config/ folder.
$cfg  = Join-Path $env:TEMP ("pim-settings-test-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $cfg -Force | Out-Null
$settingsFile = Join-Path $cfg 'manager-settings.custom.json'

$out = Join-Path $env:TEMP ("pim-settings-test-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
if (Test-Path $out) { Remove-Item $out -Force }

Write-Host "Booting Manager headless on a dynamic free port (ConfigRoot=$cfg) ..."
$ctx  = Start-PimManagerForTest -ManagerPath $mgr -ExtraArgs @('-ConfigRoot', "`"$cfg`"") -StdoutPath $out -TimeoutSec 30
$proc = $ctx.Process

try {
    $token = $ctx.Token
    T 'Manager booted + emitted session token' ([bool]$token -and $ctx.Port -gt 0)
    if (-not $token) { Get-Content $out, "$out.err" -EA SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" }; throw 'no token' }
    Write-Host "  Manager bound port $($ctx.Port)" -ForegroundColor DarkGray

    $base = $ctx.BaseUrl
    $hdr  = @{ Authorization = "Bearer $token" }
    function Beat { try { Invoke-RestMethod -Method POST -Uri "$base/api/heartbeat" -Headers $hdr -TimeoutSec 10 | Out-Null } catch {} }
    function GetJson($p) { Invoke-RestMethod -Uri "$base$p" -Headers $hdr -TimeoutSec 60 }
    function PutJson($p, $b) { Invoke-RestMethod -Method PUT -Uri "$base$p" -Headers $hdr -ContentType 'application/json' -TimeoutSec 60 -Body ($b | ConvertTo-Json -Depth 10) }

    Beat
    # ---- default-seeding: naming + filters non-empty -----------------------
    $s = GetJson '/api/settings'
    T 'GET /api/settings returns a bundle' ($null -ne $s)
    $namingKeys = @($s.naming.PSObject.Properties.Name)
    T 'naming convention auto-seeded (non-empty)' ($namingKeys.Count -ge 1)
    T 'naming includes a group pattern' ($namingKeys -contains 'PimGroupPattern')
    T 'filters auto-seeded (non-empty)' (@($s.filters).Count -ge 1)
    T 'filters include the Admins filter (renamed from AdminCandidate)' (@($s.filters | Where-Object { $_.key -eq 'Admins' }).Count -eq 1)
    T 'no filter is still labelled "candidate"' (@($s.filters | Where-Object { "$($_.key)$($_.label)" -match 'candidate' }).Count -eq 0)
    # admin-type prefix map + environment suffix map auto-seeded into the naming convention
    T 'naming auto-seeds AdminTypePrefixes map' ($null -ne $s.naming.AdminTypePrefixes)
    T 'naming auto-seeds EnvironmentSuffixes map' ($null -ne $s.naming.EnvironmentSuffixes)
    T 'internal-adminuser prefix is empty' ("$($s.naming.AdminTypePrefixes.'internal-adminuser')" -eq '')
    T 'entra environment suffix is -ID' ("$($s.naming.EnvironmentSuffixes.entra)" -eq '-ID')
    T 'server reports seeded=true on first read' ([bool]$s.namingSeeded -and [bool]$s.filtersSeeded)

    # ---- seed is PERSISTED to the store (file) -----------------------------
    T 'manager-settings.custom.json written to disk' (Test-Path -LiteralPath $settingsFile)
    if (Test-Path -LiteralPath $settingsFile) {
        $blob = Get-Content -LiteralPath $settingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        T 'persisted file carries NamingConventions' ($null -ne $blob.NamingConventions)
        T 'persisted file carries Filters' (@($blob.Filters).Count -ge 1)
    }

    # ---- second read reports NOT seeded (already persisted) -----------------
    Beat
    $s2 = GetJson '/api/settings'
    T 'second read reports seeded=false (already persisted)' (-not $s2.namingSeeded -and -not $s2.filtersSeeded)

    # ---- naming PUT round-trip ---------------------------------------------
    Beat
    $newNaming = @{ }
    foreach ($p in $s.naming.PSObject.Properties) { $newNaming[$p.Name] = $p.Value }
    $newNaming['PimGroupPattern'] = 'PIM-{Role}-{Department}-TEST'
    $r = PutJson '/api/settings/naming' @{ value = $newNaming }
    T 'PUT naming -> persisted new group pattern' ("$($r.naming.PimGroupPattern)" -eq 'PIM-{Role}-{Department}-TEST')

    # ---- admin-type prefix / environment suffix map round-trip -------------
    Beat
    $namingMaps = @{ }
    foreach ($p in $r.naming.PSObject.Properties) { $namingMaps[$p.Name] = $p.Value }   # base on the latest (carries the -TEST group pattern)
    $namingMaps['AdminTypePrefixes']   = @{ 'internal-adminuser' = ''; 'external-adminuser' = 'ext-'; 'external-guest' = 'g-' }
    $namingMaps['EnvironmentSuffixes'] = @{ 'entra' = '-ID'; 'ad' = '-AD' }
    $rm = PutJson '/api/settings/naming' @{ value = $namingMaps }
    T 'PUT naming -> external-adminuser prefix persisted (ext-)' ("$($rm.naming.AdminTypePrefixes.'external-adminuser')" -eq 'ext-')
    T 'PUT naming -> ad environment suffix persisted (-AD)' ("$($rm.naming.EnvironmentSuffixes.ad)" -eq '-AD')

    # ---- naming PUT rejects empty ------------------------------------------
    Beat
    $emptyRejected = $false
    try { PutJson '/api/settings/naming' @{ value = @{} } | Out-Null } catch { $emptyRejected = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'PUT naming rejects an empty map (400)' $emptyRejected

    # ---- filters PUT round-trip --------------------------------------------
    Beat
    $newFilters = @(
        @{ key = 'Admins'; label = 'Admins'; patterns = @('Admin-*', 'x-Admin*', 'g-Admin*'); requireAll = @('*-ID*') }
        @{ key = 'PimGroup';       label = 'PIM groups';     patterns = @('PIM-*');   requireAll = @() }
        @{ key = 'CustomFilter';   label = 'My custom';      patterns = @('X-*');     requireAll = @() }
    )
    $rf = PutJson '/api/settings/filters' @{ value = $newFilters }
    T 'PUT filters -> custom filter persisted' (@($rf.filters | Where-Object { $_.key -eq 'CustomFilter' }).Count -eq 1)

    # ---- filters PUT rejects empty -----------------------------------------
    Beat
    $emptyFiltersRejected = $false
    try { PutJson '/api/settings/filters' @{ value = @() } | Out-Null } catch { $emptyFiltersRejected = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'PUT filters rejects an empty list (400)' $emptyFiltersRejected

    # ---- departments(+owners) PUT round-trip -------------------------------
    Beat
    $depts = @(
        @{ name = 'Finance'; owners = @('owner1@contoso.com', 'owner2@contoso.com'); contact = 'fin@contoso.com'; notes = 'q' }
        @{ name = 'IT';      owners = @('itlead@contoso.com');                       contact = 'it@contoso.com';  notes = '' }
    )
    $rd = PutJson '/api/settings/departments' @{ value = $depts }
    T 'PUT departments -> 2 departments persisted' (@($rd.departments).Count -eq 2)
    T 'department resolves to its owner(s)' (@(($rd.departments | Where-Object { $_.name -eq 'Finance' }).owners).Count -eq 2)

    # ---- approvers PUT round-trip ------------------------------------------
    Beat
    $appr = @(
        @{ identity = 'approver1@contoso.com'; displayName = 'Approver One'; role = 'Owner'; notes = '' }
    )
    $ra = PutJson '/api/settings/approvers' @{ value = $appr }
    T 'PUT approvers -> 1 approver persisted' (@($ra.approvers).Count -eq 1)

    # ---- departments import endpoint (REQUIREMENTS §8/§11) -----------------
    # POST /api/settings/departments/import pulls Entra groups matching a
    # configurable pattern in as departments. OFFLINE the live Graph enumerator
    # is best-effort (returns @() with no token), so the import is a no-op upsert:
    # 200, summary present, the chosen pattern persisted, and the 2 MANUAL depts
    # above are PRESERVED (import never deletes a manually-added dept). This proves
    # the endpoint is wired + role-gated + idempotent without needing a tenant.
    Beat
    function PostJson($p, $b) { Invoke-RestMethod -Method POST -Uri "$base$p" -Headers $hdr -ContentType 'application/json' -TimeoutSec 60 -Body ($b | ConvertTo-Json -Depth 10) }
    $imp = PostJson '/api/settings/departments/import' @{ pattern = 'ORG-*' }
    T 'POST departments/import -> ok' ([bool]$imp.ok)
    T 'import echoes the pattern' ("$($imp.pattern)" -eq 'ORG-*')
    T 'import returns a summary (created/updated/skipped)' ($null -ne $imp.summary -and $null -ne $imp.summary.created)
    T 'import preserves the 2 manual departments (never deletes)' (@($imp.settings.departments).Count -eq 2)
    T 'import persists the chosen pattern into the bundle' ("$($imp.settings.deptImportPattern)" -eq 'ORG-*')
    # the persisted pattern survives a fresh GET
    Beat
    $afterImp = GetJson '/api/settings'
    T 'persisted deptImportPattern survives a fresh read' ("$($afterImp.deptImportPattern)" -eq 'ORG-*')

    # ---- approvers/owners CSV import endpoint (REQUIREMENTS §11) ------------
    # POST /api/settings/approvers/import parses a CSV
    # (Department;GroupName;approver1,approver2,...; optional 4th col = NewName)
    # and APPLIES owners/approvers per department + RENAMES. Proves the endpoint
    # is wired + role-gated + the engine apply round-trips through the store. The
    # 2 manual depts above (Finance, IT) exist; the CSV replaces Finance's owners,
    # renames IT -> IT-Ops, and creates a new HR dept.
    Beat
    $csv = "Department;GroupName;Approvers;NewName`nFinance;ORG-Finance;csv1@contoso.com,csv2@contoso.com;`nIT;ORG-IT;itowner@contoso.com;IT-Ops`nHR;ORG-HR;hr@contoso.com;"
    $impA = PostJson '/api/settings/approvers/import' @{ csv = $csv }
    T 'POST approvers/import -> ok' ([bool]$impA.ok)
    T 'approver-import returns a summary (created/updated/renamed)' ($null -ne $impA.summary -and $null -ne $impA.summary.renamed)
    T 'approver-import renamed IT -> IT-Ops' (@($impA.renamed | Where-Object { $_.to -eq 'IT-Ops' }).Count -eq 1)
    $finAfter = @($impA.settings.departments | Where-Object { $_.name -eq 'Finance' })
    T 'approver-import replaced Finance owners with the CSV list (2)' (@($finAfter[0].owners).Count -eq 2)
    T 'approver-import created the new HR department' (@($impA.settings.departments | Where-Object { $_.name -eq 'HR' }).Count -eq 1)
    T 'approver-import dropped the old IT name (renamed, not duplicated)' (@($impA.settings.departments | Where-Object { $_.name -eq 'IT' }).Count -eq 0)
    # empty CSV is rejected (400)
    Beat
    $emptyCsvRejected = $false
    try { PostJson '/api/settings/approvers/import' @{ csv = '' } | Out-Null } catch { $emptyCsvRejected = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'POST approvers/import rejects an empty csv (400)' $emptyCsvRejected

    # ---- AD OU placement (PathAdmins / PathAdminsL0T0) read/write -----------
    # These are naming-convention keys written through PUT /api/settings/naming
    # (the AD OU placement card). Prove they round-trip in the naming map.
    Beat
    $naming2 = @{ }
    foreach ($p in (GetJson '/api/settings').naming.PSObject.Properties) { $naming2[$p.Name] = $p.Value }
    $naming2['PathAdmins']     = 'OU=Admins,OU=Tier1,DC=example,DC=com'
    $naming2['PathAdminsL0T0'] = 'OU=T0Admins,OU=Tier0,DC=example,DC=com'
    $rou = PutJson '/api/settings/naming' @{ value = $naming2 }
    T 'PUT naming -> PathAdmins persisted' ("$($rou.naming.PathAdmins)" -eq 'OU=Admins,OU=Tier1,DC=example,DC=com')
    T 'PUT naming -> PathAdminsL0T0 persisted' ("$($rou.naming.PathAdminsL0T0)" -eq 'OU=T0Admins,OU=Tier0,DC=example,DC=com')
    Beat
    $afterOu = GetJson '/api/settings'
    T 'PathAdmins survives a fresh read' ("$($afterOu.naming.PathAdmins)" -eq 'OU=Admins,OU=Tier1,DC=example,DC=com')

    # ---- full bundle reflects all writes -----------------------------------
    Beat
    $final = GetJson '/api/settings'
    # After the approver-CSV import the dept list is Finance + IT-Ops + HR (= 3);
    # naming carries the -TEST group pattern + the two PathAdmins OU keys.
    T 'final bundle: naming + filters + departments + approvers all present' (
        "$($final.naming.PimGroupPattern)" -eq 'PIM-{Role}-{Department}-TEST' -and
        "$($final.naming.PathAdmins)" -eq 'OU=Admins,OU=Tier1,DC=example,DC=com' -and
        @($final.filters).Count -eq 3 -and
        @($final.departments).Count -eq 3 -and
        @($final.approvers).Count -eq 1
    )
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    Remove-Item -LiteralPath $cfg -Recurse -Force -EA SilentlyContinue
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
