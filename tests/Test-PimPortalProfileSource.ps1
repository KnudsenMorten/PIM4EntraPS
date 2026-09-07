#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-15 / §36.3 phase 2 -- the portal-admin profile READ fails CLOSED. Offline, pure: drives
    Read-PimPortalProfiles against seeded globals and temp files. No SQL, no network.

    What this used to do: prefer the SQL-hydrated setting, then fall back to
    config/portal-admins.json, and then -- if that was missing -- to portal-admins.SAMPLE.json.

    Three problems, in increasing order of seriousness:
      1. the fallback was SILENT, so nothing distinguished "the authorization model" from "a JSON
         file somebody left on the box";
      2. anyone able to write that file could grant themselves L0 across every service;
      3. it would load the SHIPPED SAMPLE as though it were configuration.

    This is an AUTHORIZATION read. The safe direction is "no profiles" (which denies every
    non-SuperAdmin), never "read whatever is on disk".

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
$lib  = Join-Path $root 'engine\_shared\PIM-PortalAccess.ps1'
T 'PIM-PortalAccess.ps1 present' (Test-Path -LiteralPath $lib)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
. $lib

# A throwaway config dir holding BOTH a real file and a sample, so "which did it read" is
# always distinguishable.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimportal-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$fileJson   = '{"portalAdmins":[{"identity":"file-user@x.io","displayName":"FROM FILE","levelMax":1,"capabilities":["manage-account"],"managedAdmins":["*"]}]}'
$sampleJson = '{"portalAdmins":[{"identity":"CONTOSO\\helpdesk1","displayName":"FROM SAMPLE","levelMax":2,"capabilities":["assign"],"managedAdmins":[]}]}'
Set-Content -LiteralPath (Join-Path $tmp 'portal-admins.json')        -Value $fileJson   -Encoding UTF8
Set-Content -LiteralPath (Join-Path $tmp 'portal-admins.sample.json') -Value $sampleJson -Encoding UTF8

function Reset-State {
    $global:PIM_NamingConventions = @{}
    Remove-Variable -Name PIM_Hosted -Scope Global -ErrorAction SilentlyContinue
    $env:PIM_HOSTED = ''
}

try {
    # === the sample is NEVER authorization data =============================
    Write-Host "`n-- the shipped SAMPLE is never read --" -ForegroundColor Cyan
    Reset-State
    Remove-Item -LiteralPath (Join-Path $tmp 'portal-admins.json') -Force
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp)
    T 'no real file + a sample present -> ZERO profiles' ($r.Count -eq 0)
    T '   ...the sample identity is NOT returned'        (-not (@($r | ForEach-Object { "$($_.displayName)" }) -contains 'FROM SAMPLE'))
    T '   ...source reported as none'                    ((Get-PimPortalProfileSource) -eq 'none')
    Set-Content -LiteralPath (Join-Path $tmp 'portal-admins.json') -Value $fileJson -Encoding UTF8

    # === hosted is SQL-ONLY =================================================
    Write-Host "`n-- hosted refuses the filesystem entirely --" -ForegroundColor Cyan
    Reset-State
    $global:PIM_Hosted = $true
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp)
    # The file is RIGHT THERE and readable. Hosted must not read it.
    T 'hosted + no SQL + a readable file -> ZERO profiles' ($r.Count -eq 0)
    T '   ...the file identity is NOT returned'           (-not (@($r | ForEach-Object { "$($_.displayName)" }) -contains 'FROM FILE'))
    T '   ...source reported as sql-empty'                ((Get-PimPortalProfileSource) -eq 'sql-empty')

    Reset-State
    $env:PIM_HOSTED = '1'
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp)
    T 'PIM_HOSTED=1 alone is enough to refuse the file'   ($r.Count -eq 0)

    # === SQL wins when present ==============================================
    Write-Host "`n-- SQL is the store when it has profiles --" -ForegroundColor Cyan
    Reset-State
    $global:PIM_Hosted = $true
    $global:PIM_NamingConventions = @{ PortalAdmins = '{"portalAdmins":[{"identity":"sql-user@x.io","displayName":"FROM SQL","levelMax":0,"capabilities":["manage-account"],"managedAdmins":["*"]}]}' }
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp)
    T 'hosted + SQL profiles -> read from SQL'   ($r.Count -eq 1 -and "$($r[0].displayName)" -eq 'FROM SQL')
    T '   ...source reported as sql'             ((Get-PimPortalProfileSource) -eq 'sql')

    # === malformed authorization JSON DENIES, it does not degrade ==========
    Write-Host "`n-- malformed SQL JSON denies rather than falling back --" -ForegroundColor Cyan
    Reset-State
    $global:PIM_NamingConventions = @{ PortalAdmins = '{ this is not json' }
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp -WarningAction SilentlyContinue)
    # 🔑 The tempting behaviour is "SQL is broken, use the file". For an authorization model that
    # is precisely wrong: it swaps the real answer for an unverified one at the worst moment.
    T 'invalid SQL JSON -> ZERO profiles'          ($r.Count -eq 0)
    T '   ...it did NOT fall back to the file'     (-not (@($r | ForEach-Object { "$($_.displayName)" }) -contains 'FROM FILE'))
    T '   ...source reported as sql-invalid'       ((Get-PimPortalProfileSource) -eq 'sql-invalid')

    # === not hosted: the file is still legitimate ==========================
    Write-Host "`n-- local/dev still reads the file (deliberately) --" -ForegroundColor Cyan
    Reset-State
    $r = @(Read-PimPortalProfiles -ConfigDir $tmp)
    T 'not hosted + a real file -> read from file' ($r.Count -eq 1 -and "$($r[0].displayName)" -eq 'FROM FILE')
    T '   ...source reported as file'              ((Get-PimPortalProfileSource) -eq 'file')

    # An explicit -ProfilesFile is a deliberate caller choice (tests, tooling) and still wins.
    Reset-State
    $global:PIM_Hosted = $true
    $r = @(Read-PimPortalProfiles -ProfilesFile (Join-Path $tmp 'portal-admins.json'))
    T 'an EXPLICIT -ProfilesFile still works when hosted' ($r.Count -eq 1)

    # === the source is reported to the GUI =================================
    Write-Host "`n-- the source reaches /api/portal-access --" -ForegroundColor Cyan
    $srv = (Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\Open-PimManager.ps1') -Raw) -replace '(?m)^\s*#.*$', ''
    T 'the endpoint reports profileSource' ($srv -match 'profileSource')
    T 'the endpoint reports hosted'        ($srv -match '(?s)/api/portal-access.{0,3000}?hosted\s*=')
    T 'the Manager publishes the hosted flag globally' ($srv -match '\$global:PIM_Hosted = \$script:PimHosted')

    # === Manager RBAC: SQL first, and hosted never reads the file ==========
    Write-Host "`n-- Manager RBAC (Get-PimManagerRole) --" -ForegroundColor Cyan
    $srvSrc = (Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\Open-PimManager.ps1') -Raw) -replace '(?m)^\s*#.*$', ''
    T 'SQL ManagerAccess is consulted'            ($srvSrc -match "PIM_NamingConventions\['ManagerAccess'\]")
    # Order matters: SQL is the authoritative home, env is the legacy one kept working.
    $iSql = $srvSrc.IndexOf("PIM_NamingConventions['ManagerAccess']")
    $iEnv = $srvSrc.IndexOf('env:PIM_SuperAdmins')
    T '   ...BEFORE the env vars'                 ($iSql -gt 0 -and $iEnv -gt 0 -and $iSql -lt $iEnv)
    T 'env vars still work (nothing stranded)'    ($srvSrc -match 'env PIM_SuperAdmins')
    # 🔒 The whole point: a hosted deployment must not fall through to
    # manager-access.custom.json, where a file on an ephemeral container filesystem would decide
    # who is SuperAdmin.
    T 'hosted STOPS before the file, failing closed' ($srvSrc -match "hosted: not in SQL ManagerAccess or env \(fail closed\)")
    $iStop = $srvSrc.IndexOf('hosted: not in SQL ManagerAccess or env')
    $iFile = $srvSrc.IndexOf("manager-access.custom.json")
    T '   ...and that stop precedes the file read' ($iStop -gt 0 -and $iFile -gt 0 -and $iStop -lt $iFile)
    # Malformed authorization JSON denies; it does not degrade to env or file.
    T 'malformed ManagerAccess JSON denies'       ($srvSrc -match "sql ManagerAccess INVALID \(fail closed\)")
    # An unknown role must not silently become something; it lands on Reader.
    T 'an unknown role falls back to Reader, not higher' ($srvSrc -match "(?s)ManagerAccess.{0,900}?'Reader','Admin','SuperAdmin','Delegated'")

    Write-Host "`n-- the installer tools exist and guard themselves --" -ForegroundColor Cyan
    $tp = Join-Path $root 'tools\setup\Set-PimPortalAdmins.ps1'
    $tm = Join-Path $root 'tools\setup\Set-PimManagerAccess.ps1'
    T 'Set-PimPortalAdmins.ps1 exists'  (Test-Path -LiteralPath $tp)
    T 'Set-PimManagerAccess.ps1 exists' (Test-Path -LiteralPath $tm)
    if ((Test-Path -LiteralPath $tp) -and (Test-Path -LiteralPath $tm)) {
        foreach ($t in @($tp, $tm)) {
            $s = (Get-Content -LiteralPath $t -Raw) -replace '(?m)^\s*#.*$', ''
            $n = Split-Path -Leaf $t
            # A read failure treated as "nothing stored" is an access-control WIPE on these tables.
            T "$n : a read failure is fatal"      ($s -match 'refusing to overwrite an unread')
            T "$n : it reads back and compares"   ($s -match 'read-back mismatch')
            T "$n : -Replace names what it drops" ($s -match 'WILL REMOVE')
        }
        $sm = (Get-Content -LiteralPath $tm -Raw) -replace '(?m)^\s*#.*$', ''
        # Locking every human out of the tool that manages privileged access is recoverable only
        # by editing the container -- the exact thing this tooling exists to stop needing.
        T 'Set-PimManagerAccess refuses a model with no SuperAdmin' ($sm -match 'has NO SuperAdmin')
        T '   ...with an explicit override for the deliberate case' ($sm -match 'AllowNoSuperAdmin')
        T 'an invalid role is rejected at INSTALL time, not sign-in' ($sm -match 'must be one of')
    }

    # === the sample-reading code is GONE, not merely unreached =============
    Write-Host "`n-- the sample fallback is removed from source --" -ForegroundColor Cyan
    $libSrc = (Get-Content -LiteralPath $lib -Raw) -replace '(?m)^\s*#.*$', ''
    T "no code path references portal-admins.sample.json" ($libSrc -notmatch 'portal-admins\.sample\.json')
} finally {
    Reset-State
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
