#Requires -Version 5.1
# =====================================================================================================================
# REQ 93 -- the MCP SERVER core (Pro 'mcp.server'). Model Context Protocol over JSON-RPC 2.0, served by the Manager on
# POST /mcp (streamable HTTP, JSON responses). PURE: no HTTP, no store -- the Manager hands in the parsed message, the
# caller's Manager role and the tool table; this file decides the protocol answer.
#
# Operator decisions (REQUIREMENTS 93.2): read + propose + commit; inside the Manager; Entra sign-in -- the caller's OWN
# Manager role (Reader / Admin / SuperAdmin) decides which tools are listed and callable; every call is audited by the
# caller of this core. A commit tool goes through the SAME path as the GUI (its gates are not re-implemented here).
# =====================================================================================================================

$script:PimMcpProtocolVersions = @('2025-06-18', '2025-03-26', '2024-11-05')   # newest first
$script:PimMcpRoleRank = @{ 'reader' = 1; 'admin' = 2; 'superadmin' = 3 }

function Get-PimMcpRoleRank {
    param([AllowEmptyString()][string]$Role)
    $k = "$Role".Trim().ToLowerInvariant()
    if ($script:PimMcpRoleRank -and $script:PimMcpRoleRank.ContainsKey($k)) { return [int]$script:PimMcpRoleRank[$k] }
    switch ($k) { 'reader' { return 1 } 'admin' { return 2 } 'superadmin' { return 3 } }   # literal fallback (child-scope safe)
    return 0
}

function New-PimMcpTool {
    <#
      One tool definition. -MinRole Reader | Admin | SuperAdmin; -Kind read | propose | commit (shown to the client in the
      description, and the caller audits by it). -InputSchema is a JSON-schema object (hashtable). -Handler receives
      ($arguments, $context) and returns any object (it is serialised as the tool result) or throws (-> isError).
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Description,
          [ValidateSet('Reader', 'Admin', 'SuperAdmin')][string]$MinRole = 'Reader',
          [ValidateSet('read', 'propose', 'commit')][string]$Kind = 'read',
          [hashtable]$InputSchema = @{ type = 'object'; properties = @{} },
          [Parameter(Mandatory)][scriptblock]$Handler)
    return [pscustomobject]@{ name = $Name; description = $Description; minRole = $MinRole; kind = $Kind; inputSchema = $InputSchema; handler = $Handler }
}

function New-PimMcpError {
    param($Id, [int]$Code, [string]$Message)
    return [ordered]@{ jsonrpc = '2.0'; id = $Id; error = [ordered]@{ code = $Code; message = $Message } }
}

function Test-PimMcpArguments {
    # PURE. The minimum a tool can rely on: required properties present, declared primitive types respected. -> reason or ''.
    param([hashtable]$Schema, [object]$Arguments)
    $args2 = if ($null -eq $Arguments) { [pscustomobject]@{} } else { $Arguments }
    foreach ($r in @($Schema.required)) {
        if (-not $r) { continue }
        $p = $args2.PSObject.Properties[$r]
        if (-not $p -or $null -eq $p.Value -or ("$($p.Value)" -eq '' -and $p.Value -is [string])) { return "missing required argument '$r'" }
    }
    $props = $Schema.properties
    if ($props) {
        foreach ($k in @($props.Keys)) {
            $p = $args2.PSObject.Properties[$k]; if (-not $p -or $null -eq $p.Value) { continue }
            $t = "$($props[$k].type)"
            if ($t -eq 'string' -and $p.Value -isnot [string]) { return "argument '$k' must be a string" }
            if ($t -eq 'integer' -and -not ($p.Value -is [int] -or $p.Value -is [long] -or ("$($p.Value)" -match '^-?\d+$'))) { return "argument '$k' must be an integer" }
            if ($t -eq 'boolean' -and $p.Value -isnot [bool]) { return "argument '$k' must be true or false" }
            if ($t -eq 'array' -and -not ($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string])) { return "argument '$k' must be an array" }
            if ($props[$k].enum -and @($props[$k].enum) -notcontains "$($p.Value)") { return "argument '$k' must be one of: $(@($props[$k].enum) -join ', ')" }
        }
    }
    return ''
}

function Invoke-PimMcpMessage {
    <#
      PURE (apart from running the chosen tool's handler). One JSON-RPC message -> @{ status; body; audit }.
        status 200 + body  = a response;  status 202 + no body = a notification was accepted;  400 = not JSON-RPC.
        audit              = $null, or @{ tool; kind; ok; detail } for the caller to write to pim.AuditEvents.
      -Message is the parsed JSON object; -Role the caller's Manager role; -Tools from New-PimMcpTool; -Context is handed
      to each handler (the caller identity, the store, ...).
    #>
    param([AllowNull()][object]$Message, [AllowEmptyString()][string]$Role, [object[]]$Tools = @(), [hashtable]$Context = @{},
          [string]$ServerVersion = '0.0.0')
    $res = { param($id, $result) @{ status = 200; body = [ordered]@{ jsonrpc = '2.0'; id = $id; result = $result }; audit = $null } }
    $err = { param($id, $code, $msg) @{ status = 200; body = (New-PimMcpError -Id $id -Code $code -Message $msg); audit = $null } }
    if ($null -eq $Message -or $Message -is [array] -or $Message -is [string] -or -not $Message.PSObject.Properties['jsonrpc'] -or "$($Message.jsonrpc)" -ne '2.0' -or -not "$($Message.method)".Trim()) {
        return @{ status = 400; body = (New-PimMcpError -Id $null -Code -32600 -Message 'not a JSON-RPC 2.0 request (one message per POST; batches are not supported)'); audit = $null }
    }
    $method = "$($Message.method)"
    $hasId = $null -ne $Message.PSObject.Properties['id'] -and $null -ne $Message.id
    $id = if ($hasId) { $Message.id } else { $null }
    if (-not $hasId) { return @{ status = 202; body = $null; audit = $null } }   # a notification (notifications/initialized, cancelled ...)
    $rank = Get-PimMcpRoleRank -Role $Role
    if ($rank -lt 1) { return (& $err $id -32001 'no Manager role -- ask a SuperAdmin for Reader, Admin or SuperAdmin in the PIM Manager') }
    switch ($method) {
        'initialize' {
            $want = "$(if ($Message.params) { $Message.params.protocolVersion })".Trim()
            $ver = if ($script:PimMcpProtocolVersions -contains $want) { $want } else { $script:PimMcpProtocolVersions[0] }
            return (& $res $id ([ordered]@{
                protocolVersion = $ver
                capabilities = [ordered]@{ tools = [ordered]@{ listChanged = $false } }
                serverInfo = [ordered]@{ name = 'pim4entraps'; title = 'PIM4EntraPS'; version = $ServerVersion }
                instructions = "PIM4EntraPS -- privileged access in Microsoft Entra ID and Azure. Your tools follow your Manager role ($Role). Changes are STAGED as pending changes; a commit tool writes them through the same checks as the Manager (validation, second approver, Tier 0/1 review). Nothing here activates a role." }))
        }
        'ping' { return (& $res $id ([ordered]@{})) }
        'tools/list' {
            $list = @($Tools | Where-Object { (Get-PimMcpRoleRank -Role $_.minRole) -le $rank } | Sort-Object name | ForEach-Object {
                [ordered]@{ name = $_.name; description = "[$($_.kind)] $($_.description)"; inputSchema = $_.inputSchema } })
            return (& $res $id ([ordered]@{ tools = $list }))
        }
        'tools/call' {
            $name = "$(if ($Message.params) { $Message.params.name })".Trim()
            $tool = @($Tools | Where-Object { $_.name -eq $name })[0]
            if (-not $tool) { return (& $err $id -32602 "unknown tool '$name'") }
            if ((Get-PimMcpRoleRank -Role $tool.minRole) -gt $rank) {
                $r = & $err $id -32001 "'$name' needs the $($tool.minRole) role in the PIM Manager (you are $Role)"
                $r.audit = @{ tool = $name; kind = $tool.kind; ok = $false; detail = 'refused: role' }; return $r
            }
            $a = if ($Message.params -and $Message.params.PSObject.Properties['arguments']) { $Message.params.arguments } else { $null }
            $why = Test-PimMcpArguments -Schema $tool.inputSchema -Arguments $a
            if ($why) { return (& $err $id -32602 $why) }
            try {
                $out = & $tool.handler $a $Context
                $text = if ($out -is [string]) { $out } else { $out | ConvertTo-Json -Depth 12 }
                $r = & $res $id ([ordered]@{ content = @([ordered]@{ type = 'text'; text = "$text" }); isError = $false })
                $r.audit = @{ tool = $name; kind = $tool.kind; ok = $true; detail = '' }
                return $r
            } catch {
                # a tool failure is a RESULT the model can read (isError), not a protocol error
                $r = & $res $id ([ordered]@{ content = @([ordered]@{ type = 'text'; text = "$($_.Exception.Message)" }); isError = $true })
                $r.audit = @{ tool = $name; kind = $tool.kind; ok = $false; detail = "$($_.Exception.Message)" }
                return $r
            }
        }
        default { return (& $err $id -32601 "method '$method' is not supported (tools only)") }
    }
}
