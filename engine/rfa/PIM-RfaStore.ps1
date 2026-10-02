#Requires -Version 5.1
<#
  §82 RFA -- the RFA STORE adapter (Pro). REQUIREMENTS §82.6.

  The public RFA portal and the internal engine never talk to each other. They share ONE storage account (Tables,
  Entra-only, shared keys disabled): the portal writes submitted requests, PIN challenges and review answers; the engine
  PULLS them with its managed identity, decides, and writes back status + the published eligibility list.

  Tables (created by the deploy, P4):
    RfaConfig        PK 'config'     RK 'salt' | 'settings'          what the portal needs to know
    RfaEligibility   PK 'acct'       RK <accountKey>                 contactEmail, mode, durations (no UPN)
    RfaRequests      PK 'req'        RK <request id>                 state, source, accountKey | upn, hours, kind, ...
    RfaReviews       PK 'review'     RK <campaign id>                company, contact hashes, the consultant list (JSON)
    RfaAnswers       PK 'ans'        RK <answer id>                  campaignId, upn, answer, leaveUntil, by
  PIN challenges and rate counters are portal-only tables (RfaPins, RfaRate); the engine never reads them.

  A store is a hashtable, never a closure (engine code must not use GetNewClosure -- it cannot see script-scope
  functions): @{ kind = 'azure'; account = '<name>' } or @{ kind = 'memory'; tables = @{} } (tests).
#>

$script:PimRfaTableApiVersion = '2020-12-06'

function New-PimRfaStore {
    # The store for the engine side: the storage account named in RfaSettings, or $null when RFA is not deployed.
    param([AllowNull()][object]$Settings)
    $acct = "$(if ($Settings) { $Settings.storeAccount })".Trim()
    if (-not $acct) { return $null }
    if ($acct -notmatch '^[a-z0-9]{3,24}$') { throw "RfaSettings.storeAccount '$acct' is not a storage account name" }
    return @{ kind = 'azure'; account = $acct }
}

function New-PimRfaMemoryStore {
    # An in-memory store for the offline tests (same calls, same shapes).
    return @{ kind = 'memory'; tables = @{} }
}

function ConvertTo-PimRfaODataKey {
    # A key inside (PartitionKey='..',RowKey='..'): quotes doubled, then URL-encoded.
    param([AllowEmptyString()][string]$Value)
    return [uri]::EscapeDataString(("$Value" -replace "'", "''"))
}

function Get-PimRfaStoreHeaders {
    param([Parameter(Mandatory)][hashtable]$Store)
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { throw 'the RFA store needs engine\_shared\PIM-Rest.ps1 (Get-PimRestToken)' }
    $tok = Get-PimRestToken -Resource 'https://storage.azure.com'
    return @{ Authorization = "Bearer $tok"; 'x-ms-version' = $script:PimRfaTableApiVersion; 'x-ms-date' = [datetime]::UtcNow.ToString('R')
              Accept = 'application/json;odata=nometadata' }
}

function Get-PimRfaStoreEntities {
    <#
      All entities of a table, optionally filtered by PartitionKey and an equality on one property (applied AFTER the
      read in memory, so no OData filter is ever built from data). Follows continuation headers.
    #>
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Table, [string]$PartitionKey = '',
          [string]$Property = '', [string]$Value = '')
    $rows = @()
    if ($Store.kind -eq 'memory') {
        if ($Store.tables.ContainsKey($Table)) { $rows = @($Store.tables[$Table].Values | ForEach-Object { [pscustomobject]$_ }) }
    } elseif ($Store.kind -eq 'azure') {
        $base = "https://$($Store.account).table.core.windows.net/$Table()"
        $q = if ("$PartitionKey".Trim()) { '?$filter=' + [uri]::EscapeDataString("PartitionKey eq '$("$PartitionKey" -replace "'", "''")'") } else { '' }
        $next = ''
        for ($page = 0; $page -lt 500; $page++) {
            $uri = $base + $q + $next
            $resp = Invoke-WebRequest -Method GET -Uri $uri -Headers (Get-PimRfaStoreHeaders -Store $Store) -UseBasicParsing -ErrorAction Stop
            $body = "$($resp.Content)" | ConvertFrom-Json
            $rows += @($body.value)
            $np = "$(@($resp.Headers['x-ms-continuation-NextPartitionKey'])[0])"; $nr = "$(@($resp.Headers['x-ms-continuation-NextRowKey'])[0])"
            if (-not $np) { break }
            $sep = if ($q) { '&' } else { '?' }
            $next = "$($sep)NextPartitionKey=$([uri]::EscapeDataString($np))" + $(if ($nr) { "&NextRowKey=$([uri]::EscapeDataString($nr))" } else { '' })
        }
    } else { throw "unknown RFA store kind '$($Store.kind)'" }
    if ("$PartitionKey".Trim()) { $rows = @($rows | Where-Object { "$($_.PartitionKey)" -eq $PartitionKey }) }
    if ("$Property".Trim()) { $rows = @($rows | Where-Object { $_.PSObject.Properties[$Property] -and "$($_.$Property)" -eq $Value }) }
    return @($rows)
}

function Set-PimRfaStoreEntity {
    # Insert-or-replace one entity. -Entity is a hashtable/object WITHOUT the keys; values are written as strings / numbers.
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey,
          [Parameter(Mandatory)][string]$RowKey, [Parameter(Mandatory)][object]$Entity)
    $e = [ordered]@{ PartitionKey = $PartitionKey; RowKey = $RowKey }
    $props = if ($Entity -is [System.Collections.IDictionary]) { @($Entity.Keys | ForEach-Object { @{ n = "$_"; v = $Entity[$_] } }) } else { @($Entity.PSObject.Properties | ForEach-Object { @{ n = $_.Name; v = $_.Value } }) }
    foreach ($p in $props) {
        if ($p.n -in @('PartitionKey', 'RowKey', 'Timestamp', 'odata.etag')) { continue }
        $v = $p.v
        $e[$p.n] = $(if ($null -eq $v) { '' } elseif ($v -is [int] -or $v -is [long] -or $v -is [bool]) { $v } elseif ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { "$v" })
    }
    if ($Store.kind -eq 'memory') {
        if (-not $Store.tables.ContainsKey($Table)) { $Store.tables[$Table] = @{} }
        $Store.tables[$Table]["$PartitionKey|$RowKey"] = $e
        return
    }
    if ($Store.kind -ne 'azure') { throw "unknown RFA store kind '$($Store.kind)'" }
    $uri = "https://$($Store.account).table.core.windows.net/$Table(PartitionKey='$(ConvertTo-PimRfaODataKey $PartitionKey)',RowKey='$(ConvertTo-PimRfaODataKey $RowKey)')"
    $h = Get-PimRfaStoreHeaders -Store $Store; $h['Content-Type'] = 'application/json'
    [void](Invoke-WebRequest -Method PUT -Uri $uri -Headers $h -Body ([Text.Encoding]::UTF8.GetBytes(($e | ConvertTo-Json -Compress -Depth 4))) -UseBasicParsing -ErrorAction Stop)
}

function Remove-PimRfaStoreEntity {
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey, [Parameter(Mandatory)][string]$RowKey)
    if ($Store.kind -eq 'memory') { if ($Store.tables.ContainsKey($Table)) { [void]$Store.tables[$Table].Remove("$PartitionKey|$RowKey") }; return }
    if ($Store.kind -ne 'azure') { throw "unknown RFA store kind '$($Store.kind)'" }
    $uri = "https://$($Store.account).table.core.windows.net/$Table(PartitionKey='$(ConvertTo-PimRfaODataKey $PartitionKey)',RowKey='$(ConvertTo-PimRfaODataKey $RowKey)')"
    $h = Get-PimRfaStoreHeaders -Store $Store; $h['If-Match'] = '*'
    try { [void](Invoke-WebRequest -Method DELETE -Uri $uri -Headers $h -UseBasicParsing -ErrorAction Stop) }
    catch { if ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -notmatch '\b404\b|ResourceNotFound') { throw } }
}
