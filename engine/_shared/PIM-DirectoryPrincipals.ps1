#Requires -Version 5.1
<#
.SYNOPSIS
    GRAPH-PICKER (framework SECURE-WEB-1, owner 2026-11-16 "yes extend the rule to pim too"): the directory people / groups
    the web app needs, read by the ENGINE and stored in PIM's SQL. The web app searches SQL -- it makes no Graph call.

.DESCRIPTION
    THE RULE (Invardia, binding): the internet-facing WEB identity (id-pim-web; the Manager process) never holds or uses a
    directory-read Graph permission -- no app role, no OBO/delegated. The NON-internet collector (the engine identity, its
    'tenant-cache' job) reads the directory and stores it here; the web searches its own SQL. A name that is not there yet
    is a TARGETED COLLECT the web asks for: one validated request row (pim.DirectoryLookupRequest) + the engine woken on the
    pim-wake queue (Request-PimManagerEngineTenantCache -Scope 'directory-lookup' -> trigger + Send-PimManagerWake: the wake
    message is still a job NAME only). The engine collects that principal into pim.DirectoryPrincipal and the web reads it.

    TWO TABLES (created by Initialize-PimSqlStore, the updater's schema step -- the web holds no DDL right):
      pim.DirectoryPrincipal      Kind (user|group|approles) + ObjectId -> DisplayName, UserPrincipalName, Mail,
                                  OnPremisesSyncEnabled, AccountEnabled, DetailJson (approles: the role list), Source, CollectedUtc
      pim.DirectoryLookupRequest  one row per targeted collect: Kind, KeyType (upn|mail|id|prefix), KeyValue, Status
                                  (pending|done|notfound|error|refused|expired), RequestedUtc/By, DoneUtc, Found, Detail

    THE QUEUE CONTRACT (internet-facing input -- Test-PimDirectoryLookupKey, checked by the web AND again by the engine):
      kind user     keyType upn | mail (name@domain, <= 120 chars) | id (a GUID) | prefix (2-64 letters, digits, space . _ @ ' & ( ) -)
      kind group    keyType id | prefix
      kind approles keyType id (an application id or a service principal object id)
      A request NEVER carries a Graph URL or filter text: the engine builds the path itself from the validated key
      (ConvertTo-PimODataStringLiteral, [uri]::EscapeDataString). Dedupe: a pending request for the same key is reused;
      a key answered within the last 2 minutes is not asked again. Rate: at most 30 new requests a minute in the store and
      10 a minute per requester (the web also caps 20 a minute per process).

    WEB half (SQL only): Get-PimDirectoryPrincipal, Search-PimDirectoryPrincipals, Get-PimDirectoryLookupState,
                         Add-PimDirectoryLookupRequest.
    ENGINE half (Graph, as the engine identity; run by _tenantSync.ps1 Invoke-PimTenantListRefresh):
                         Invoke-PimDirectoryLookupQueue (the targeted collects), Invoke-PimDirectoryPrincipalCollect (the
                         scoped collect: the principals the active-assignment snapshot already holds -- members and holders
                         of PIM's groups and roles --, PIM's groups, and every account named in PIM's rows / settings).
                         Never a whole-directory crawl.

    PS 5.1 + 7, ASCII, no modules. Depends on PIM-SqlStore.ps1 (Invoke-PimSqlQuery / -NonQuery); every SQL and Graph call
    takes a seam (-Query / -Exec / -Graph) so the offline suites drive it.
#>
Set-StrictMode -Off

function Get-PimDirectoryLookupPendingText { return 'PIM is looking this up in the directory -- this takes about a minute' }
function Get-PimDirectoryLookupNotFoundText { param([string]$What = 'it') return "PIM looked $What up in the directory and did not find it" }
function Get-PimDirectoryLookupKinds { return [ordered]@{ user = @('upn', 'mail', 'id', 'prefix'); group = @('id', 'prefix'); approles = @('id') } }
function Get-PimDirectoryUserSelect { return 'id,displayName,userPrincipalName,mail,onPremisesSyncEnabled,accountEnabled' }
function Get-PimDirectoryGroupSelect { return 'id,displayName,mail,description,securityEnabled,mailEnabled,groupTypes' }

function Get-PimDirectoryPrincipalDdl {
    <# PURE. The two tables + indexes. Idempotent, additive only. #>
@'
IF OBJECT_ID('pim.DirectoryPrincipal') IS NULL
CREATE TABLE pim.DirectoryPrincipal (
    Kind                  NVARCHAR(10)  NOT NULL,
    ObjectId              NVARCHAR(64)  NOT NULL,
    DisplayName           NVARCHAR(400) NULL,
    UserPrincipalName     NVARCHAR(400) NULL,
    Mail                  NVARCHAR(400) NULL,
    OnPremisesSyncEnabled BIT           NULL,
    AccountEnabled        BIT           NULL,
    DetailJson            NVARCHAR(MAX) NULL,
    Source                NVARCHAR(40)  NULL,
    CollectedUtc          DATETIME2     NOT NULL CONSTRAINT DF_pim_DirPrincipal_Collected DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_pim_DirectoryPrincipal PRIMARY KEY (Kind, ObjectId)
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_DirPrincipal_Upn' AND object_id = OBJECT_ID('pim.DirectoryPrincipal'))
CREATE INDEX IX_pim_DirPrincipal_Upn ON pim.DirectoryPrincipal (UserPrincipalName);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_DirPrincipal_Mail' AND object_id = OBJECT_ID('pim.DirectoryPrincipal'))
CREATE INDEX IX_pim_DirPrincipal_Mail ON pim.DirectoryPrincipal (Mail);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_DirPrincipal_Name' AND object_id = OBJECT_ID('pim.DirectoryPrincipal'))
CREATE INDEX IX_pim_DirPrincipal_Name ON pim.DirectoryPrincipal (Kind, DisplayName);
IF OBJECT_ID('pim.DirectoryLookupRequest') IS NULL
CREATE TABLE pim.DirectoryLookupRequest (
    Id            BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_pim_DirectoryLookupRequest PRIMARY KEY,
    Kind          NVARCHAR(10)  NOT NULL,
    KeyType       NVARCHAR(10)  NOT NULL,
    KeyValue      NVARCHAR(256) NOT NULL,
    Status        NVARCHAR(12)  NOT NULL CONSTRAINT DF_pim_DirLookup_Status DEFAULT N'pending',
    RequestedUtc  DATETIME2     NOT NULL CONSTRAINT DF_pim_DirLookup_Requested DEFAULT SYSUTCDATETIME(),
    RequestedBy   NVARCHAR(200) NULL,
    DoneUtc       DATETIME2     NULL,
    Found         INT           NULL,
    Detail        NVARCHAR(400) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_DirLookup_Key' AND object_id = OBJECT_ID('pim.DirectoryLookupRequest'))
CREATE INDEX IX_pim_DirLookup_Key ON pim.DirectoryLookupRequest (Kind, KeyType, KeyValue, Id DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_DirLookup_Status' AND object_id = OBJECT_ID('pim.DirectoryLookupRequest'))
CREATE INDEX IX_pim_DirLookup_Status ON pim.DirectoryLookupRequest (Status, Id);
'@
}

function Test-PimDirectoryLookupKey {
    <#
      PURE. THE GATE on the internet-facing input (the web before it writes a request, the engine again before it reads).
      Returns @{ ok; kind; keyType; key; reason } -- key normalised (upn / mail / id lower-case, prefix trimmed).
    #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$KeyType, [AllowEmptyString()][string]$Key)
    $o = [ordered]@{ ok = $false; kind = "$Kind".Trim().ToLowerInvariant(); keyType = "$KeyType".Trim().ToLowerInvariant(); key = "$Key".Trim(); reason = '' }
    $kinds = Get-PimDirectoryLookupKinds
    if (-not $kinds.Contains($o.kind)) { $o.reason = "'$($o.kind)' is not a lookup kind (user, group, approles)"; return [pscustomobject]$o }
    if (@($kinds[$o.kind]) -notcontains $o.keyType) { $o.reason = "a $($o.kind) is looked up by $(@($kinds[$o.kind]) -join ', ') -- not '$($o.keyType)'"; return [pscustomobject]$o }
    if ($o.key.Length -gt 120) { $o.reason = 'the lookup key is longer than 120 characters'; return [pscustomobject]$o }
    if ($o.key -match '[\x00-\x1F\x7F]') { $o.reason = 'the lookup key carries a control character'; return [pscustomobject]$o }
    switch ($o.keyType) {
        { $_ -in @('upn', 'mail') } {
            if ($o.key -notmatch "^[A-Za-z0-9._%+'#!$&*=?^{}|~-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$") { $o.reason = "'$($o.key)' is not a name@domain address"; return [pscustomobject]$o }
            $o.key = $o.key.ToLowerInvariant()
        }
        'id' {
            if ($o.key -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { $o.reason = "'$($o.key)' is not an object id (GUID)"; return [pscustomobject]$o }
            $o.key = $o.key.ToLowerInvariant()
        }
        'prefix' {
            if ($o.key.Length -lt 2 -or $o.key.Length -gt 64) { $o.reason = 'a name search takes 2 to 64 characters'; return [pscustomobject]$o }
            if ($o.key -notmatch "^[\p{L}\p{M}\p{N} ._@'&()-]+$") { $o.reason = 'a name search takes letters, digits, spaces and . _ @ '' & ( ) - only'; return [pscustomobject]$o }
        }
    }
    $o.ok = $true
    return [pscustomobject]$o
}

function ConvertTo-PimDirectoryLikePattern {
    # PURE. '%<text>%' for T-SQL LIKE with [ ] % _ escaped (the text is a parameter; this is about the wildcards only).
    param([AllowEmptyString()][string]$Text)
    return ('%' + ("$Text".Trim() -replace '([\[\]%_])', '[$1]') + '%')
}

function ConvertFrom-PimDirectoryPrincipalRow {
    param($Row)
    if ($null -eq $Row) { return $null }
    $b = { param($v) if ($null -eq $v -or $v -is [DBNull]) { $null } else { [bool]$v } }
    $s = { param($v) if ($null -eq $v -or $v -is [DBNull]) { '' } else { "$v" } }
    $det = $null; $dj = & $s $Row.DetailJson; if ($dj) { try { $det = $dj | ConvertFrom-Json } catch { $det = $null } }
    $cu = $null; if ($Row.CollectedUtc -and $Row.CollectedUtc -isnot [DBNull]) { try { $cu = ([datetime]$Row.CollectedUtc).ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { $cu = "$($Row.CollectedUtc)" } }
    return [pscustomobject]@{
        kind = (& $s $Row.Kind); id = (& $s $Row.ObjectId).ToLowerInvariant(); displayName = (& $s $Row.DisplayName)
        userPrincipalName = (& $s $Row.UserPrincipalName); mail = (& $s $Row.Mail)
        onPremisesSyncEnabled = (& $b $Row.OnPremisesSyncEnabled); accountEnabled = (& $b $Row.AccountEnabled)
        detail = $det; source = (& $s $Row.Source); collectedUtc = $cu
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# WEB half -- SQL only. Never Graph.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimDirectoryPrincipal {
    <# WEB. The stored principal(s) for one validated key. upn: exact UPN; mail: mail OR UPN (every match -- the caller wants
       exactly one); id: the object. Returns @() when none. -Query is a seam (param($cs, $sql, $params) -> rows). #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$KeyType, [Parameter(Mandatory)][string]$Key, [scriptblock]$Query)
    $v = Test-PimDirectoryLookupKey -Kind $Kind -KeyType $KeyType -Key $Key
    if (-not $v.ok -or $v.keyType -eq 'prefix') { return @() }
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    $cols = 'Kind, ObjectId, DisplayName, UserPrincipalName, Mail, OnPremisesSyncEnabled, AccountEnabled, DetailJson, Source, CollectedUtc'
    $sql = switch ($v.keyType) {
        'upn'  { "SELECT TOP (5) $cols FROM pim.DirectoryPrincipal WHERE Kind = N'user' AND UserPrincipalName = @v" }
        'mail' { "SELECT TOP (5) $cols FROM pim.DirectoryPrincipal WHERE Kind = N'user' AND (Mail = @v OR UserPrincipalName = @v)" }
        'id'   { "SELECT TOP (1) $cols FROM pim.DirectoryPrincipal WHERE Kind = @k AND ObjectId = @v" }
    }
    $rows = @(& $Query $ConnectionString $sql @{ k = $v.kind; v = $v.key })
    return @($rows | ForEach-Object { ConvertFrom-PimDirectoryPrincipalRow -Row $_ } | Where-Object { $_ })
}

function Search-PimDirectoryPrincipals {
    <# WEB. The picker's search: a contains-match on the name, UPN or mail of the stored principals of -Kind; at most -Top + 1
       (so the caller can say "more match"). #>
    param([string]$ConnectionString, [Parameter(Mandatory)][ValidateSet('user', 'group')][string]$Kind, [Parameter(Mandatory)][string]$Term, [int]$Top = 25, [scriptblock]$Query)
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    $n = [Math]::Max(1, [Math]::Min(100, $Top)) + 1
    $sql = "SELECT TOP (@n) Kind, ObjectId, DisplayName, UserPrincipalName, Mail, OnPremisesSyncEnabled, AccountEnabled, DetailJson, Source, CollectedUtc FROM pim.DirectoryPrincipal " +
           "WHERE Kind = @k AND (DisplayName LIKE @t OR UserPrincipalName LIKE @t OR Mail LIKE @t) ORDER BY DisplayName, ObjectId"
    $rows = @(& $Query $ConnectionString $sql @{ n = $n; k = $Kind; t = (ConvertTo-PimDirectoryLikePattern -Text $Term) })
    return @($rows | ForEach-Object { ConvertFrom-PimDirectoryPrincipalRow -Row $_ } | Where-Object { $_ })
}

function Get-PimDirectoryLookupState {
    <# WEB. The newest request for this key: @{ id; status; requestedUtc; doneUtc; found; detail; ageMinutes } or $null. #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$KeyType, [Parameter(Mandatory)][string]$Key, [scriptblock]$Query, [datetime]$NowUtc = [datetime]::UtcNow)
    $v = Test-PimDirectoryLookupKey -Kind $Kind -KeyType $KeyType -Key $Key
    if (-not $v.ok) { return $null }
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    $r = @(& $Query $ConnectionString 'SELECT TOP (1) Id, Status, RequestedUtc, DoneUtc, Found, Detail FROM pim.DirectoryLookupRequest WHERE Kind = @k AND KeyType = @t AND KeyValue = @v ORDER BY Id DESC' @{ k = $v.kind; t = $v.keyType; v = $v.key })[0]
    if ($null -eq $r) { return $null }
    $at = if ($r.DoneUtc -and $r.DoneUtc -isnot [DBNull]) { [datetime]$r.DoneUtc } else { [datetime]$r.RequestedUtc }
    return [pscustomobject]@{ id = [long]$r.Id; status = "$($r.Status)"; requestedUtc = $r.RequestedUtc; doneUtc = $(if ($r.DoneUtc -is [DBNull]) { $null } else { $r.DoneUtc })
        found = $(if ($null -eq $r.Found -or $r.Found -is [DBNull]) { $null } else { [int]$r.Found }); detail = $(if ($r.Detail -is [DBNull]) { '' } else { "$($r.Detail)" })
        ageMinutes = [Math]::Round(($NowUtc - [datetime]::SpecifyKind($at, [DateTimeKind]::Utc)).TotalMinutes, 1) }
}

function Get-PimDirectoryLookupRequestSql {
    <# PURE. ONE batch: reuse a pending request, skip a key answered within @fresh seconds, refuse over the rate caps, else
       insert. Answers one row { Id; Outcome = deduped | answered | rate-limited | queued }. #>
@'
SET NOCOUNT ON; SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @id BIGINT = NULL, @outcome NVARCHAR(20) = NULL;
SELECT TOP (1) @id = Id FROM pim.DirectoryLookupRequest WITH (UPDLOCK, HOLDLOCK)
 WHERE Kind = @k AND KeyType = @t AND KeyValue = @v AND Status = N'pending' ORDER BY Id DESC;
IF @id IS NOT NULL SET @outcome = N'deduped';
IF @outcome IS NULL
BEGIN
    SELECT TOP (1) @id = Id FROM pim.DirectoryLookupRequest
     WHERE Kind = @k AND KeyType = @t AND KeyValue = @v AND Status IN (N'done', N'notfound') AND DoneUtc > DATEADD(SECOND, -@fresh, SYSUTCDATETIME()) ORDER BY Id DESC;
    IF @id IS NOT NULL SET @outcome = N'answered';
END
IF @outcome IS NULL
BEGIN
    IF (SELECT COUNT(*) FROM pim.DirectoryLookupRequest WHERE RequestedUtc > DATEADD(SECOND, -60, SYSUTCDATETIME())) >= @capAll
       OR (SELECT COUNT(*) FROM pim.DirectoryLookupRequest WHERE RequestedBy = @by AND RequestedUtc > DATEADD(SECOND, -60, SYSUTCDATETIME())) >= @capBy
        SET @outcome = N'rate-limited';
    ELSE
    BEGIN
        INSERT INTO pim.DirectoryLookupRequest (Kind, KeyType, KeyValue, RequestedBy) VALUES (@k, @t, @v, @by);
        SET @id = SCOPE_IDENTITY(); SET @outcome = N'queued';
    END
END
COMMIT;
SELECT @id AS Id, @outcome AS Outcome;
'@
}

function Add-PimDirectoryLookupRequest {
    <# WEB. Validate, then ONE request row (Get-PimDirectoryLookupRequestSql). Returns @{ ok; outcome; id; reason }. Never throws. #>
    param([string]$ConnectionString, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$KeyType, [Parameter(Mandatory)][AllowEmptyString()][string]$Key,
          [string]$RequestedBy = 'PIM Manager', [int]$FreshSeconds = 120, [int]$CapPerMinute = 30, [int]$CapPerRequester = 10, [scriptblock]$Query)
    $v = Test-PimDirectoryLookupKey -Kind $Kind -KeyType $KeyType -Key $Key
    if (-not $v.ok) { return [pscustomobject]@{ ok = $false; outcome = 'refused'; id = $null; reason = $v.reason } }
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    $by = ("$RequestedBy" -replace '[\x00-\x1F\x7F]', ' ').Trim(); if ($by.Length -gt 200) { $by = $by.Substring(0, 200) }; if (-not $by) { $by = 'PIM Manager' }
    try {
        $r = @(& $Query $ConnectionString (Get-PimDirectoryLookupRequestSql) @{ k = $v.kind; t = $v.keyType; v = $v.key; by = $by; fresh = $FreshSeconds; capAll = $CapPerMinute; capBy = $CapPerRequester })[0]
        $oc = "$($r.Outcome)"
        return [pscustomobject]@{ ok = ($oc -in @('queued', 'deduped', 'answered')); outcome = $oc; id = $(if ($null -eq $r.Id -or $r.Id -is [DBNull]) { $null } else { [long]$r.Id })
            reason = $(if ($oc -eq 'rate-limited') { 'too many directory lookups this minute -- try again in a minute' } else { '' }) }
    } catch { return [pscustomobject]@{ ok = $false; outcome = 'error'; id = $null; reason = (("$($_.Exception.Message)" -split "`n")[0]) } }
}

# ---------------------------------------------------------------------------------------------------------------------
# ENGINE half -- live Graph reads as the ENGINE identity. Called only from _tenantSync.ps1 Invoke-PimTenantListRefresh.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimDirectoryLookupGraphPath {
    <# PURE. The ONE Graph path for a validated key -- built here, never taken from a request. #>
    param([Parameter(Mandatory)][object]$Key, [int]$Top = 25)
    $us = Get-PimDirectoryUserSelect; $gs = Get-PimDirectoryGroupSelect
    $lit = { param($s) "'" + ("$s" -replace "'", "''") + "'" }
    $k = $Key.key
    switch ("$($Key.kind)|$($Key.keyType)") {
        'user|upn'     { return "/users/$([uri]::EscapeDataString($k))?`$select=$us" }
        'user|id'      { return "/users/$k`?`$select=$us" }
        'user|mail'    { $l = & $lit $k; return "/users?`$filter=$([uri]::EscapeDataString("mail eq $l or userPrincipalName eq $l"))&`$select=$us&`$top=5" }
        'user|prefix'  { $l = & $lit $k; return "/users?`$filter=$([uri]::EscapeDataString("startswith(displayName,$l) or startswith(userPrincipalName,$l) or startswith(mail,$l)"))&`$select=$us&`$top=$Top" }
        'group|id'     { return "/groups/$k`?`$select=$gs" }
        'group|prefix' { $l = & $lit $k; return "/groups?`$filter=$([uri]::EscapeDataString("startswith(displayName,$l)"))&`$select=$gs&`$top=$Top" }
    }
    return ''
}

function ConvertTo-PimDirectoryPrincipalRecord {
    # PURE. A Graph user / group -> the record Save-PimDirectoryPrincipals stores.
    param([Parameter(Mandatory)][string]$Kind, $Object, [string]$Source = 'graph')
    if ($null -eq $Object) { return $null }
    $g = { param($n) if ($Object -is [System.Collections.IDictionary]) { $Object[$n] } elseif ($Object.PSObject.Properties[$n]) { $Object.$n } else { $null } }
    $id = "$(& $g 'id')".Trim().ToLowerInvariant()
    if ($id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $null }
    $bn = { param($n) $x = & $g $n; if ($null -eq $x -or "$x" -eq '') { $null } else { [bool]$x } }
    # a group's kind (as the picker shows it) when the answer carries it; $null keeps the stored one
    $det = $null
    if ($Kind -eq 'group' -and ($null -ne (& $g 'groupTypes') -or $null -ne (& $g 'securityEnabled'))) {
        $det = @{ kind = $(if (@(& $g 'groupTypes') -contains 'Unified') { 'Microsoft 365' } elseif ([bool](& $g 'securityEnabled')) { 'security' } else { 'distribution' }) }
    }
    return [ordered]@{ k = $Kind; i = $id; n = "$(& $g 'displayName')".Trim(); u = "$(& $g 'userPrincipalName')".Trim(); m = "$(& $g 'mail')".Trim()
        s = $(if ($Kind -eq 'user') { & $bn 'onPremisesSyncEnabled' } else { $null }); e = $(if ($Kind -eq 'user') { & $bn 'accountEnabled' } else { $null }); d = $det; src = $Source }
}

function Save-PimDirectoryPrincipals {
    <# ENGINE. Upsert -Records (ConvertTo-PimDirectoryPrincipalRecord) by Kind + ObjectId; a value the record does not carry
       ($null) keeps the stored one. Returns the count. -Exec seam (param($cs, $sql, $params)). #>
    param([string]$ConnectionString, [object[]]$Records = @(), [scriptblock]$Exec)
    $recs = @($Records | Where-Object { $_ })
    if (-not $recs.Count) { return 0 }
    if (-not $Exec) { $Exec = { param($cs, $sql, $prm) [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql -Parameters $prm -CommandTimeoutSec 120) } }
    $sql = @'
SET NOCOUNT ON;
MERGE pim.DirectoryPrincipal AS t
USING (SELECT DISTINCT k, i, n, u, m, s, e, d, src FROM OPENJSON(@j) WITH (k NVARCHAR(10) '$.k', i NVARCHAR(64) '$.i', n NVARCHAR(400) '$.n', u NVARCHAR(400) '$.u',
       m NVARCHAR(400) '$.m', s BIT '$.s', e BIT '$.e', d NVARCHAR(MAX) '$.d' AS JSON, src NVARCHAR(40) '$.src')) AS x
   ON t.Kind = x.k AND t.ObjectId = x.i
WHEN MATCHED THEN UPDATE SET DisplayName = COALESCE(NULLIF(x.n, N''), t.DisplayName), UserPrincipalName = COALESCE(NULLIF(x.u, N''), t.UserPrincipalName),
     Mail = COALESCE(NULLIF(x.m, N''), t.Mail), OnPremisesSyncEnabled = COALESCE(x.s, t.OnPremisesSyncEnabled), AccountEnabled = COALESCE(x.e, t.AccountEnabled),
     DetailJson = COALESCE(x.d, t.DetailJson), Source = x.src, CollectedUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Kind, ObjectId, DisplayName, UserPrincipalName, Mail, OnPremisesSyncEnabled, AccountEnabled, DetailJson, Source)
     VALUES (x.k, x.i, NULLIF(x.n, N''), NULLIF(x.u, N''), NULLIF(x.m, N''), x.s, x.e, x.d, x.src);
-- a UPN is unique in a tenant: another stored user under the same UPN is a deleted (re-created) account -- dropped
DELETE p FROM pim.DirectoryPrincipal AS p
  JOIN OPENJSON(@j) WITH (k NVARCHAR(10) '$.k', i NVARCHAR(64) '$.i', u NVARCHAR(400) '$.u') AS x
    ON p.Kind = N'user' AND x.k = N'user' AND x.u IS NOT NULL AND x.u <> N'' AND p.UserPrincipalName = x.u AND p.ObjectId <> x.i;
'@
    $n = 0
    for ($i = 0; $i -lt $recs.Count; $i += 500) {
        $chunk = @($recs[$i..([Math]::Min($i + 499, $recs.Count - 1))])
        & $Exec $ConnectionString $sql @{ j = (ConvertTo-Json -InputObject @($chunk) -Compress -Depth 6) }
        $n += $chunk.Count
    }
    return $n
}

function Invoke-PimDirectoryLookupQueue {
    <#
      ENGINE. The targeted collects the web asked for: the oldest -Max pending requests, each RE-VALIDATED (Test-PimDirectoryLookupKey
      -- a row that fails is 'refused', nothing read), read with the path THIS function builds (Get-PimDirectoryLookupGraphPath),
      stored, and marked done / notfound / error. A request pending for a day is 'expired'; answered rows older than 7 days
      are removed. Seams: -Graph { param($path) -> Graph answer }, -Query / -Exec, -AppRoles { param($id) -> @(roles) }.
      Returns @{ processed; found; notFound; errors; refused }.
    #>
    param([string]$ConnectionString, [int]$Max = 40, [scriptblock]$Graph, [scriptblock]$Query, [scriptblock]$Exec, [scriptblock]$AppRoles)
    if (-not $Graph) { $Graph = { param($p) Invoke-PimGraph -Path $p } }
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    if (-not $Exec)  { $Exec  = { param($cs, $sql, $prm) [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql -Parameters $prm) } }
    $out = [ordered]@{ processed = 0; found = 0; notFound = 0; errors = 0; refused = 0 }
    & $Exec $ConnectionString "UPDATE pim.DirectoryLookupRequest SET Status = N'expired', DoneUtc = SYSUTCDATETIME() WHERE Status = N'pending' AND RequestedUtc < DATEADD(DAY, -1, SYSUTCDATETIME()); DELETE FROM pim.DirectoryLookupRequest WHERE Status <> N'pending' AND RequestedUtc < DATEADD(DAY, -7, SYSUTCDATETIME());" @{}
    $rows = @(& $Query $ConnectionString 'SELECT TOP (@n) Id, Kind, KeyType, KeyValue FROM pim.DirectoryLookupRequest WHERE Status = N''pending'' ORDER BY Id' @{ n = [Math]::Max(1, [Math]::Min(200, $Max)) })
    $mark = { param($id, $st, $found, $detail) $d = "$detail"; if ($d.Length -gt 400) { $d = $d.Substring(0, 400) }
              & $Exec $ConnectionString 'UPDATE pim.DirectoryLookupRequest SET Status = @s, DoneUtc = SYSUTCDATETIME(), Found = @f, Detail = @d WHERE Id = @id' @{ id = $id; s = $st; f = $found; d = $d } }
    foreach ($r in $rows) {
        $out.processed++
        $v = Test-PimDirectoryLookupKey -Kind "$($r.Kind)" -KeyType "$($r.KeyType)" -Key "$($r.KeyValue)"
        if (-not $v.ok) { $out.refused++; & $mark $r.Id 'refused' 0 $v.reason; continue }
        try {
            $recs = @()
            if ($v.kind -eq 'approles') {
                if (-not $AppRoles) { throw 'the app-role reader (the entra-approle connector) is not loaded in this engine run' }
                $roles = @(& $AppRoles $v.key)
                $recs = @([ordered]@{ k = 'approles'; i = $v.key; n = ''; u = ''; m = ''; s = $null; e = $null; d = @{ roles = @($roles); readUtc = [datetime]::UtcNow.ToString('o') }; src = 'lookup' })
            } else {
                $path = Get-PimDirectoryLookupGraphPath -Key $v
                $ans = $null; $missing = $false
                try { $ans = & $Graph $path }
                catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|Request_ResourceNotFound|ResourceNotFound|does not exist') { $missing = $true } else { throw } }
                if (-not $missing) {
                    $items = if ($null -ne $ans -and $ans.PSObject.Properties['value']) { @($ans.value) } else { @($ans) }
                    $recs = @($items | Where-Object { $_ } | ForEach-Object { ConvertTo-PimDirectoryPrincipalRecord -Kind $v.kind -Object $_ -Source 'lookup' } | Where-Object { $_ })
                }
            }
            if ($recs.Count) { [void](Save-PimDirectoryPrincipals -ConnectionString $ConnectionString -Records $recs -Exec $Exec); $out.found++; & $mark $r.Id 'done' $recs.Count '' }
            else { $out.notFound++; & $mark $r.Id 'notfound' 0 '' }
        } catch { $out.errors++; & $mark $r.Id 'error' 0 ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
    return [pscustomobject]$out
}

function Get-PimDirectoryNamedAddresses {
    <# PURE. Every distinct name@domain string inside -Texts (PIM's rows / settings JSON), lower-case, at most -Max. #>
    param([string[]]$Texts = @(), [int]$Max = 5000)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in $Texts) {
        foreach ($m in [regex]::Matches("$t", "[A-Za-z0-9._%+'#-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}")) {
            $a = $m.Value.Trim('.').ToLowerInvariant()
            if ((Test-PimDirectoryLookupKey -Kind 'user' -KeyType 'upn' -Key $a).ok -and $seen.Add($a)) { $out.Add($a); if ($out.Count -ge $Max) { return @($out.ToArray()) } }
        }
    }
    return @($out.ToArray())
}

function Invoke-PimDirectoryPrincipalCollect {
    <#
      ENGINE. The SCOPED collect (never a whole-directory crawl):
        1. the principals the active-assignment snapshot already holds (members / holders of PIM's groups and roles) -- SQL only;
        2. PIM's groups (the 'pim-groups' tenant list the same job just read) -- no extra Graph read;
        3. every account NAMED in PIM's rows and settings that is not stored (or older than 7 days) -- read from Graph in
           batches of 15 (userPrincipalName in (...), then mail in (...)), at most -MaxResolve per run.
      Returns @{ snapshot; groups; named; resolved }. Seams: -Graph, -Query, -Exec, -PimGroups { -> items }.
    #>
    param([string]$ConnectionString, [int]$MaxResolve = 1000, [scriptblock]$Graph, [scriptblock]$Query, [scriptblock]$Exec, [scriptblock]$PimGroups)
    if (-not $Graph) { $Graph = { param($p) Invoke-PimGraph -Path $p } }
    if (-not $Query) { $Query = { param($cs, $sql, $prm) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters $prm } }
    if (-not $Exec)  { $Exec  = { param($cs, $sql, $prm) [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql -Parameters $prm -CommandTimeoutSec 120) } }
    $out = [ordered]@{ snapshot = 0; groups = 0; named = 0; resolved = 0 }
    # 1. the snapshot (SQL -> SQL)
    $snap = @(& $Query $ConnectionString @'
IF OBJECT_ID('pim.ActiveAssignmentRows') IS NULL OR OBJECT_ID('pim.ActiveAssignmentSnapshots') IS NULL BEGIN SELECT TOP (0) CAST(NULL AS NVARCHAR(10)) AS k, CAST(NULL AS NVARCHAR(100)) AS i, CAST(NULL AS NVARCHAR(400)) AS n, CAST(NULL AS NVARCHAR(400)) AS u; RETURN; END
DECLARE @s BIGINT = (SELECT TOP (1) SnapshotId FROM pim.ActiveAssignmentSnapshots WHERE State = N'complete' ORDER BY SnapshotId DESC);
SELECT DISTINCT TOP (50000) CASE WHEN PrincipalKind = N'group' THEN N'group' ELSE N'user' END AS k, LOWER(PrincipalId) AS i, Principal AS n, PrincipalUpn AS u
  FROM pim.ActiveAssignmentRows
 WHERE SnapshotId = @s AND TRY_CONVERT(UNIQUEIDENTIFIER, PrincipalId) IS NOT NULL
   AND (PrincipalKind = N'group' OR PrincipalUpn LIKE N'%_@_%');
'@ @{})
    $recs = @(foreach ($s in $snap) { if ($s.i) { [ordered]@{ k = "$($s.k)"; i = "$($s.i)"; n = "$(if ($s.n -is [DBNull]) { '' } else { $s.n })"; u = "$(if ($s.u -is [DBNull]) { '' } else { $s.u })"; m = ''; s = $null; e = $null; d = $null; src = 'snapshot' } } })
    $out.snapshot = Save-PimDirectoryPrincipals -ConnectionString $ConnectionString -Records $recs -Exec $Exec
    # 2. PIM's groups
    $pg = @()
    if ($PimGroups) { $pg = @(& $PimGroups) } elseif (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) { try { $c = Get-PimTenantCacheEntry -Kind 'pim-groups'; if ($c) { $pg = @($c.items) } } catch { $pg = @() } }
    $out.groups = Save-PimDirectoryPrincipals -ConnectionString $ConnectionString -Exec $Exec -Records @($pg | ForEach-Object { ConvertTo-PimDirectoryPrincipalRecord -Kind 'group' -Object $_ -Source 'pim-groups' })
    # 3. the accounts named in PIM's rows / settings that are not stored (or stale)
    $texts = @(& $Query $ConnectionString "SELECT DataJson AS t FROM pim.Rows WHERE DataJson LIKE N'%@%' UNION ALL SELECT ValueJson AS t FROM pim.Settings WHERE ValueJson LIKE N'%@%' AND Name NOT LIKE N'%Secret%' AND Name NOT LIKE N'%Key%'" @{} | ForEach-Object { "$($_.t)" })
    $named = @(Get-PimDirectoryNamedAddresses -Texts $texts)
    $out.named = $named.Count
    if (-not $named.Count) { return [pscustomobject]$out }
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @(& $Query $ConnectionString "SELECT LOWER(UserPrincipalName) AS u, LOWER(Mail) AS m FROM pim.DirectoryPrincipal WHERE Kind = N'user' AND CollectedUtc > DATEADD(DAY, -7, SYSUTCDATETIME())" @{})) {
        if ($r.u -and $r.u -isnot [DBNull]) { [void]$known.Add("$($r.u)") }; if ($r.m -and $r.m -isnot [DBNull]) { [void]$known.Add("$($r.m)") } }
    $todo = @($named | Where-Object { -not $known.Contains($_) } | Select-Object -First $MaxResolve)
    $us = Get-PimDirectoryUserSelect
    $lit = { param($s) "'" + ("$s" -replace "'", "''") + "'" }
    foreach ($prop in 'userPrincipalName', 'mail') {
        $left = @($todo | Where-Object { -not $known.Contains($_) })
        for ($i = 0; $i -lt $left.Count; $i += 15) {
            $chunk = @($left[$i..([Math]::Min($i + 14, $left.Count - 1))])
            $f = "$prop in ($((@($chunk | ForEach-Object { & $lit $_ })) -join ','))"
            try {
                $ans = & $Graph "/users?`$filter=$([uri]::EscapeDataString($f))&`$select=$us&`$top=999"
                $items = if ($null -ne $ans -and $ans.PSObject.Properties['value']) { @($ans.value) } else { @($ans) }
                $rr = @($items | Where-Object { $_ } | ForEach-Object { ConvertTo-PimDirectoryPrincipalRecord -Kind 'user' -Object $_ -Source 'named' } | Where-Object { $_ })
                $out.resolved += Save-PimDirectoryPrincipals -ConnectionString $ConnectionString -Records $rr -Exec $Exec
                foreach ($x in $rr) { if ($x.u) { [void]$known.Add($x.u) }; if ($x.m) { [void]$known.Add($x.m) } }
            } catch { Write-Verbose "directory collect ($prop): $($_.Exception.Message)" }
        }
    }
    return [pscustomobject]$out
}
