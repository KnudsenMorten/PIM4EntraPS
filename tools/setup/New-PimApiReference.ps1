#Requires -Version 7.0
<#
.SYNOPSIS
  APIDOC-1 (owner 2026-10-31: "all apis and mcp must be fully documented in gui and on invardia.com") -- GENERATE the PIM
  Manager's API + MCP reference from the code. Maintainer / release-host script: never run in a customer environment.

.DESCRIPTION
  Reads the code, never a hand-kept list (so the reference cannot drift):
    API  every route Open-PimManager.ps1's router serves (Handle-Request: $path -eq / -like / -match / -in conditions with
         their $method) + the 'METHOD /path' route tables of the router modules (tools/pim-manager/_*.ps1). Per route:
         method, path (a pattern becomes an OpenAPI {param} template), the role its body checks first
         (Test-PimManagerRoleAtLeast), the Pro feature it checks (Test-PimManagerProFeature), internal (page mechanics).
         Descriptions come ONLY from tools/pim-manager/api-descriptions.json (curated, reviewed text) -- never from code
         comments, which can explain past fixes in a way a public page must not (no attack hints).
    MCP  the tools exactly as the server lists them: Get-PimManagerMcpTools is loaded on its own (with PIM-Mcp.ps1 and a stub
         that lists the managing-tenant tools too) and RUN -- names, kind, minimum role, input schemas, route. No handler runs.
  Output = the Invardia hand-over shape (PIM 93.5): <OutDir>\api.json (OpenAPI 3.1), mcp.json, README.txt, SHA256SUMS.txt.
  The output is checked before it is written: no host names, tenant / subscription GUIDs, e-mail addresses or secrets.

.EXAMPLE
  pwsh -NoProfile -File tools\setup\New-PimApiReference.ps1 -OutDir C:\ProgramData\Invardia\handover\apidoc\pim-manager\3.0.11
#>
[CmdletBinding()]
param([string]$OutDir = '', [string]$Version = '', [switch]$PassThru)
$ErrorActionPreference = 'Stop'
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $Version) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
$mgrPath = Join-Path $sol 'tools\pim-manager\Open-PimManager.ps1'
$mgrSrc = [IO.File]::ReadAllText($mgrPath)
$ast = [System.Management.Automation.Language.Parser]::ParseInput($mgrSrc, [ref]$null, [ref]$null)

# ---------------------------------------------------------------------------------------------------------- the API
function ConvertTo-PimRefPathTemplate {
    # a route condition's path -> an OpenAPI path ('/api/x/{id}'), '' when it is not a plain /api path
    param([string]$Op, [string]$Value)
    switch ($Op) {
        'eq'   { return $Value }
        'like' { if ($Value -eq '/api/*') { return '' }   # the gate in front of EVERY route (auth), not a route of its own
                 # a prefix route serves the path itself AND what follows it ('/api/x*' = /api/x, /api/x?..., /api/x/...)
                 $b = (($Value -replace '\*$', '') -replace '/$', ''); return @($b, ($b + '/{path}')) }
        'match' {
            $p = $Value -replace '^\^', '' -replace '\$$', ''
            $script:__pi = 0
            # a capture group, or a bare character class with its count ([A-Za-z0-9_\-]{8,64}, [\w\.-]+), is one path parameter
            $p = [regex]::Replace($p, '\((?!\?)[^()]*\)|\[[^\]]+\](\{\d+(,\d+)?\}|\+|\*)', { param($m) $script:__pi++; '{p' + $script:__pi + '}' })
            $p = $p -replace '\\\.', '.' -replace '\\-', '-' -replace '\?$', ''
            if ($p -match '[\\\[\]\(\)\*\+\|]') { return '' }   # still a pattern: not documented as a path
            return $p
        }
    }
    return ''
}
$hr = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Handle-Request' }, $true)
$fnBodies = @{}
foreach ($fd in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like 'Invoke-PimManager*Route*' }, $true))) { $fnBodies[$fd.Name] = $fd.Extent.Text }
$internal = @('/api/heartbeat', '/api/instance', '/api/list-layouts', '/api/get-started', '/api/wizard/', '/api/diff', '/api/reports-overview',
              '/api/activator/build', '/api/activator/edge-policy', '/api/support/ticket/draft', '/api/refresh-tenant-lists')
$ops = New-Object System.Collections.Generic.List[object]
foreach ($ifs in @($hr.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true))) {
    $cond = $ifs.Clauses[0].Item1.Extent.Text
    if ($cond -notmatch '\$path') { continue }
    $paths = @()
    foreach ($m in [regex]::Matches($cond, "\`$path\s+-(eq|like|match)\s+'(/api/[^']+|\^/api/[^']+)'")) { $t = ConvertTo-PimRefPathTemplate -Op $m.Groups[1].Value -Value $m.Groups[2].Value; if ($t) { $paths += $t } }
    foreach ($m in [regex]::Matches($cond, "\`$path\s+-in\s+@\(([^)]*)\)")) { foreach ($q in [regex]::Matches($m.Groups[1].Value, "'(/api/[^']+)'")) { $paths += $q.Groups[1].Value } }
    if (-not $paths.Count) { continue }
    $methods = @([regex]::Matches($cond, "\`$method\s+-eq\s+'(\w+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() } | Select-Object -Unique)
    if (-not $methods.Count) { $methods = @('GET') }   # no method in the condition: documented as GET (the page's use)
    $body = $ifs.Clauses[0].Item2.Extent.Text
    $mv = [regex]::Match($body, '(Invoke-PimManager(?:Get|Post)Route\w+) -path')
    if ($mv.Success -and $fnBodies.ContainsKey($mv.Groups[1].Value)) { $body += $fnBodies[$mv.Groups[1].Value] }
    $role = ([regex]::Match($body, "Test-PimManagerRoleAtLeast -Minimum '(\w+)'")).Groups[1].Value
    $pro = ([regex]::Match($body, "Test-PimManagerProFeature -Key '([\w\.]+)'")).Groups[1].Value
    foreach ($p in ($paths | Select-Object -Unique)) { foreach ($me in $methods) { $ops.Add([pscustomobject]@{ method = $me; path = $p; role = $role; pro = $pro }) } }
}
foreach ($mod in @(Get-ChildItem -LiteralPath (Join-Path $sol 'tools\pim-manager') -Filter '_*.ps1' -File)) {
    $mt = [IO.File]::ReadAllText($mod.FullName)
    foreach ($m in [regex]::Matches($mt, "'(GET|POST|PUT|DELETE|PATCH) (/api/[^'\s]+)'")) { $ops.Add([pscustomobject]@{ method = $m.Groups[1].Value; path = $m.Groups[2].Value; role = ''; pro = '' }) }
}
$ops = @($ops | Sort-Object path, method -Unique)
$descFile = Join-Path $sol 'tools\pim-manager\api-descriptions.json'
$desc = @{}; if (Test-Path -LiteralPath $descFile) { $dj = Get-Content -LiteralPath $descFile -Raw | ConvertFrom-Json; foreach ($p in $dj.PSObject.Properties) { $desc[$p.Name] = "$($p.Value)" } }
$pathsObj = [ordered]@{}
foreach ($o in $ops) {
    if (-not $pathsObj.Contains($o.path)) { $pathsObj[$o.path] = [ordered]@{} }
    $key = "$($o.method) $($o.path)"
    $isInternal = [bool]@($internal | Where-Object { $o.path.StartsWith($_) }).Count
    $who = if ($o.role) { "$($o.role) or higher" } else { 'any signed-in Manager role (the route checks further where it applies)' }
    $params = @([regex]::Matches($o.path, '\{(\w+)\}') | ForEach-Object { [ordered]@{ name = $_.Groups[1].Value; in = 'path'; required = $true; schema = @{ type = 'string' } } })
    $op = [ordered]@{
        operationId = (($o.method.ToLowerInvariant()) + '_' + (($o.path -replace '^/api/', '' -replace '[{}]', '' -replace '[^A-Za-z0-9]+', '_').Trim('_')))
        summary     = $(if ($desc.ContainsKey($key)) { $desc[$key] } else { "$($o.method) $($o.path)" })
        description = "Requires: $who.$(if ($o.pro) { " Pro feature: $($o.pro)." })$(if ($isInternal) { ' Internal: a mechanic of the PIM Manager page -- not a supported integration point.' })"
        'x-pim-role' = $(if ($o.role) { $o.role } else { 'Reader' }); 'x-pim-pro-feature' = $(if ($o.pro) { $o.pro } else { $null }); 'x-internal' = $isInternal
        security    = @(@{ entraSignIn = @() })
        responses   = [ordered]@{ '200' = @{ description = 'OK' }; '400' = @{ description = 'The request is not valid (the answer says why)' }
                                  '401' = @{ description = 'Not signed in' }; '403' = @{ description = 'Your role or licence does not allow it (the answer says which)' } }
    }
    if ($params.Count) { $op['parameters'] = $params }
    if ($o.method -in 'POST', 'PUT', 'PATCH') { $op['requestBody'] = @{ required = $false; content = @{ 'application/json' = @{ schema = @{ type = 'object' } } } } }
    $pathsObj[$o.path][$o.method.ToLowerInvariant()] = $op
}
$api = [ordered]@{
    openapi = '3.1.0'
    info = [ordered]@{ title = 'PIM Manager API'; version = $Version; description = 'The API the PIM Manager page itself uses: every action of the page is a route here. Paths are relative to your own PIM Manager address. Generated from the code of this version.' }
    servers = @(@{ url = '/'; description = 'your PIM Manager' })
    components = @{ securitySchemes = @{ entraSignIn = @{ type = 'http'; scheme = 'bearer'; description = 'Microsoft Entra sign-in at the PIM Manager. Your PIM Manager role (Reader, Admin, SuperAdmin) decides what each route allows.' } } }
    paths = $pathsObj
}

# ---------------------------------------------------------------------------------------------------------- the MCP
. (Join-Path $sol 'engine\mcp\PIM-Mcp.ps1')
$toolsFn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PimManagerMcpTools' }, $true)
function Test-PimManagerIsMspMaster { $true }   # the managing-tenant tools are documented too (listed only there)
. ([scriptblock]::Create($toolsFn.Extent.Text))
$tools = @(Get-PimManagerMcpTools)
$mcp = [ordered]@{
    product = 'pim-manager'; version = $Version; generatedAt = [datetime]::UtcNow.ToString('o')
    endpoint = 'POST /mcp (JSON-RPC 2.0, streamable HTTP, JSON answers)'
    signIn = 'A person signs in with Microsoft Entra: a delegated token for api://<your PIM Manager app>/mcp.access. App-only tokens are refused. Your PIM Manager role decides which tools you see and may call; every call is audited.'
    tools = @($tools | Sort-Object name | ForEach-Object {
        [ordered]@{ name = $_.name; description = $_.description; inputSchema = $_.inputSchema
                    output = 'JSON text: the same answer the PIM Manager page gets for this action (an error says why)'
                    readOnly = ("$($_.kind)" -eq 'read'); kind = "$($_.kind)"; route = $(if ("$($_.route)") { "$($_.route)" } else { $null }); requires = "$($_.minRole)" } })
    guiOnly = 'By design NOT in the MCP (the PIM Manager page only): emergency / break-glass / restore, revoke, drift remediation and group delete, hybrid-AD delete approvals, guard release, and changes to settings, licence and managed tenants (the MCP reads them).'
}

# ---------------------------------------------------------------------------------------------------------- check + write
$apiJson = $api | ConvertTo-Json -Depth 30
$mcpJson = $mcp | ConvertTo-Json -Depth 30
$bad = @()
foreach ($pair in @(@('api.json', $apiJson), @('mcp.json', $mcpJson))) {
    $t = $pair[1]
    if ($t -match '(?i)[a-z0-9-]+\.(azurecontainerapps\.io|database\.windows\.net|blob\.core\.windows\.net|vault\.azure\.net|onmicrosoft\.com)') { $bad += "$($pair[0]): a host name ($($Matches[0]))" }
    if ($t -match '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}') { $bad += "$($pair[0]): a GUID ($($Matches[0]))" }
    if ($t -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' -and $Matches[0] -notmatch '@example\.(test|com)$') { $bad += "$($pair[0]): an e-mail address ($($Matches[0]))" }
    if ($t -match '(?i)(sig=|AccountKey=|client_secret|password\s*[:=])') { $bad += "$($pair[0]): secret-like text ($($Matches[0]))" }
}
if ($bad.Count) { throw "the generated reference is NOT clean -- nothing written:`n  " + ($bad -join "`n  ") }
$summary = [ordered]@{ version = $Version; routes = @($ops).Count; paths = $pathsObj.Count; internalRoutes = @($ops | Where-Object { $p = $_.path; @($internal | Where-Object { $p.StartsWith($_) }).Count }).Count
                       mcpTools = $tools.Count; mcpRead = @($tools | Where-Object { "$($_.kind)" -eq 'read' }).Count; mcpWrite = @($tools | Where-Object { "$($_.kind)" -ne 'read' }).Count }
if ($OutDir) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $OutDir 'api.json'), $apiJson, $utf8)
    [IO.File]::WriteAllText((Join-Path $OutDir 'mcp.json'), $mcpJson, $utf8)
    $readme = @"
PIM Manager $Version -- API and MCP reference

api.json   OpenAPI 3.1: every route the PIM Manager serves ($($summary.routes) operations on $($summary.paths) paths; $($summary.internalRoutes) marked x-internal = page
           mechanics, not a supported integration point). Each operation names the role it needs (x-pim-role) and the Pro
           feature it checks (x-pim-pro-feature). Paths are relative to the customer's own PIM Manager address.
mcp.json   the MCP tools exactly as the server lists them: $($summary.mcpTools) tools ($($summary.mcpRead) read, $($summary.mcpWrite) write), each with its input schema, the
           role it needs and the API route it runs. Writes go through the same checks as the page.

Generated from the code of PIM Manager $Version by tools/setup/New-PimApiReference.ps1 (never a hand-kept list). Summaries
come from the curated tools/pim-manager/api-descriptions.json; code comments are never published.
"@
    [IO.File]::WriteAllText((Join-Path $OutDir 'README.txt'), ($readme -replace "`r`n", "`n"), $utf8)
    $sums = foreach ($n in 'api.json', 'mcp.json', 'README.txt') { "$((Get-FileHash -LiteralPath (Join-Path $OutDir $n) -Algorithm SHA256).Hash.ToLowerInvariant())  $n" }
    [IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), $utf8)
    Write-Host "API + MCP reference $Version written to $OutDir ($($summary.routes) routes, $($summary.mcpTools) MCP tools)" -ForegroundColor Green
}
if ($PassThru -or -not $OutDir) { [pscustomobject]@{ summary = $summary; api = $api; mcp = $mcp } }
