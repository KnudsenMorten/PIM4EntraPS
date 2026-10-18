<#
  Framework §12.11f item 2 (CR8, ONE WAY + SIGNED REQUESTS) / PIM 100.144a -- PIM step 2, FIRST STAGE: OBSERVE-ONLY.

  Owner 2026-10-14 (CR8): "Yes, in steps" -- step 2 = a commit journal carrying the user's signed Entra token; the engine
  applies only verified commits. Build approved 2026-10-18. The per-change passkey was DROPPED by the owner.

  WHAT THIS FILE DOES
  * THE SIGNATURE STORE (pim.SignedRequests, append-only): for every Manager write that leads to an outside change, the
    signed-in user's Entra token AS THE MANAGER RECEIVED IT (Easy Auth's X-MS-TOKEN-AAD-ID-TOKEN; on /mcp the verified
    bearer), the key id it names, the time the Manager received + checked it (CapturedUtc) and the Manager's own check of
    it. Keyed by the change journal's commit id (pim.CommitJournal.CommitId). Requester and approver each their own row.
      - a Review & Save commit (grid, departments, workloads, undo) and a backup restore: written IN THE COMMIT'S OWN
        TRANSACTION by the journal writer (Add-PimCommitJournalRowTx -> Add-PimSignedRequestRowsTx), from the journal
        context's .signatures -- the committer's token, plus the token each colleague captured when they STAGED a change
        the commit carries (CommitId 'stage:<entity>'), plus a maker/checker approver's (CommitId 'approval:<id>');
      - a change-queue entry: the requester's token when it is enqueued, the approver's when it is committed -- under the
        commit id the engine's drain journals it with (the queue id without dashes).
    The insert is guarded (IF OBJECT_ID + TRY/CATCH): a store without the table, or a refused insert, NEVER fails the
    commit -- the engine then reports "no signed token was captured".
  * THE ENGINE CHECK (Test-PimEngineSignedRequest, called by the orchestrator right before a handler acts): the commit that
    asked for the change (Resolve-PimEngineChangeCommit) is verified -- signature against the tenant's PUBLISHED signing
    keys (fetched over REST from the OpenID metadata; the key id kept; a token whose key is no longer published fails
    closed), issuer (this tenant), audience (pim.Settings SignedRequests.audiences), iat <= captured <= exp, the user (the
    token's user IS the person the journal names) and the role (Admin / SuperAdmin -- Delegated may initiate -- from PIM's
    own role store, pim.Settings ManagerAccess). Requester and approver each need their own verified token.
  * THE MODE (pim.Settings 'SignedRequests'.mode): off | observe | enforce, DEFAULT OFF.
      off      nothing is captured, nothing is checked, nothing is read beyond the already-hydrated settings -- no
               behaviour change for any install;
      observe  captured + checked; the change is APPLIED AS TODAY and "would have refused: <reason>" is written to the
               engine log (the run's log on Jobs > Engine logs & errors), to the change's audit row, and counted
               (pim.Settings 'SignedRequestStats', the heartbeat's SignedRequests field) -- never a failed run;
      enforce  built, reached ONLY when the setting says exactly 'enforce': a change whose commit does not verify is NOT
               applied (held as a skipped item, the reason logged). Enforce refuses exactly what observe reports -- the
               same verdict function decides both.
    An unknown value is OBSERVE (reported, never refused): a typo must neither switch protection off silently nor start
    refusing changes nobody chose to refuse.
  * ADOPTION OF EXISTING DESIRED STATE: one SuperAdmin-signed adoption record (Role 'adoption') carries a manifest of every
    stored row's SHA-256 (computed in SQL, HASHBYTES over pim.Rows.DataJson) at the moment of adoption. A change whose row
    still hashes exactly as adopted (or a removal of a row already gone when adopted, by a commit made before it) is
    covered by the adoption; anything changed afterwards needs its own signed commit.

  🔒 HONEST LIMIT (framework §12.11f item 2, recorded): an ID token is NOT bound to one request. A signature proves that
  the named person was signed in within the token's life; anyone who can write the store during that life (a compromised
  web app holding a captured token) can attach it to a change of its own. Signing narrows forgery to users signed in within
  the token's life -- it does not stop a live session from being abused. The customer's own Entra sign-in design (MFA /
  Conditional Access) applies. The web app can also still write pim.Settings (this mode) and pim.SignedRequests (insert)
  until the per-component views of framework §12.23 step D.

  PS 5.1 + 7: no ?. / ?? / ternary. REST / .NET only (System.Security.Cryptography via PIM-HostedAuth.ps1's verifier).
  Tests: tests/Test-PimSignedRequests.ps1 (a locally generated RSA key + a self-built JWKS; no tenant, no network).
#>

Set-StrictMode -Off

# The JWT parser + RS256 verifier + claim checks live in ONE place (PIM-HostedAuth.ps1, SEC-01); the engine loads it here.
if (-not (Get-Command Test-PimJwtSignature -ErrorAction SilentlyContinue)) {
    $__srAuth = Join-Path $PSScriptRoot 'PIM-HostedAuth.ps1'
    if (Test-Path -LiteralPath $__srAuth) { . $__srAuth }
}

# =====================================================================================================================
# THE STORE
# =====================================================================================================================

function Get-PimSignedRequestDdl {
    @"
IF OBJECT_ID('pim.SignedRequests') IS NULL
CREATE TABLE pim.SignedRequests (
    Id            BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_pim_SignedRequests PRIMARY KEY,
    CommitId      NVARCHAR(100) NOT NULL,
    Role          NVARCHAR(20)  NOT NULL,
    [Identity]    NVARCHAR(200) NOT NULL,
    TokenKind     NVARCHAR(10)  NOT NULL,
    Token         NVARCHAR(MAX) NOT NULL,
    Kid           NVARCHAR(200) NULL,
    CapturedUtc   DATETIME2     NOT NULL,
    ManagerCheck  NVARCHAR(400) NULL,
    Route         NVARCHAR(200) NULL,
    Manifest      NVARCHAR(MAX) NULL,
    Reason        NVARCHAR(400) NULL,
    WrittenUtc    DATETIME2     NOT NULL CONSTRAINT DF_SignedRequests_Ts DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_SignedRequests_Commit')
CREATE INDEX IX_pim_SignedRequests_Commit ON pim.SignedRequests (CommitId, Role);
"@
}

function Get-PimSignedRequestTriggerSql {
    @"
CREATE OR ALTER TRIGGER pim.TR_SignedRequests_AppendOnly ON pim.SignedRequests
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 51011, 'pim.SignedRequests is append-only: a captured signature is never changed or deleted (framework 12.11f).', 1;
END
"@
}

function Initialize-PimSignedRequestStore {
    <# The schema step (Initialize-PimSqlStore, run by the updater / setup) only. Never throws: a store without the table
       still opens; the Manager then captures nothing and the engine reports every change as unsigned (observe) or holds
       it (enforce). Returns @{ ok; detail }. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimSignedRequestDdl))
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimSignedRequestTriggerSql))
        return [pscustomobject]@{ ok = $true; detail = 'signed-request store + append-only trigger in place' }
    } catch {
        Write-Warning "[signed-requests] pim.SignedRequests could not be created -- no signature is captured until it exists: $($_.Exception.Message)"
        return [pscustomobject]@{ ok = $false; detail = "signed-request store NOT in place: $($_.Exception.Message)" }
    }
}

# =====================================================================================================================
# THE MODE
# =====================================================================================================================

function ConvertTo-PimSignedRequestMode {
    <# PURE. off | observe | enforce. Empty / absent = off (the default). 'enforce' only when spelled exactly so (any case).
       Anything else = observe, with .unknown set (reported, never refused). Returns @{ mode; unknown; raw }. #>
    param([AllowNull()][object]$Value)
    $raw = "$Value".Trim()
    $v = $raw.ToLowerInvariant()
    if (-not $v -or $v -in @('off', 'none', 'disabled', '0', 'false')) { return @{ mode = 'off'; unknown = $false; raw = $raw } }
    if ($v -eq 'observe') { return @{ mode = 'observe'; unknown = $false; raw = $raw } }
    if ($v -eq 'enforce') { return @{ mode = 'enforce'; unknown = $false; raw = $raw } }
    return @{ mode = 'observe'; unknown = $true; raw = $raw }
}

function Get-PimSignedRequestConfig {
    <#
      PURE given -Value: pim.Settings['SignedRequests'] ({ mode; audiences[]; tenantId } -- a JSON string or the parsed object;
      $null = absent) -> @{ mode; unknown; audiences; tenantId; raw }. Audiences: the setting's list + the extra list (env).
    #>
    param([AllowNull()][object]$Value, [string[]]$ExtraAudiences = @())
    $o = $Value
    if ($o -is [string]) { if ("$o".Trim()) { try { $o = $o | ConvertFrom-Json } catch { $o = [pscustomobject]@{ mode = 'observe-unreadable' } } } else { $o = $null } }
    $get = { param($n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $m = ConvertTo-PimSignedRequestMode -Value (& $get 'mode')
    $aud = New-Object System.Collections.Generic.List[string]
    foreach ($a in @(@(& $get 'audiences') + @($ExtraAudiences))) { foreach ($p in @("$a" -split '[,;]+')) { $t = $p.Trim(); if ($t -and -not $aud.Contains($t)) { $aud.Add($t) } } }
    return @{ mode = $m.mode; unknown = $m.unknown; raw = $m.raw; audiences = @($aud.ToArray()); tenantId = "$(& $get 'tenantId')".Trim() }
}

function New-PimSignedRequestSettingValue {
    <#
      PURE. The new pim.Settings 'SignedRequests' record a SuperAdmin asked for: -Mode off | observe | enforce (nothing else is
      stored), a reason of >= 10 characters, and for ENFORCE an explicit -ConfirmEnforce (enforce holds every change whose
      commit does not verify -- it is never reached by accident). -Audiences: the Manager's own sign-in audiences (Easy Auth
      client id, the MCP API); empty keeps the stored ones. Returns @{ ok; status; error; value }.
    #>
    param([AllowNull()][object]$Previous, [string]$Mode = '', [string[]]$Audiences = @(), [string]$TenantId = '', [string]$By = '',
          [string]$Reason = '', [bool]$ConfirmEnforce = $false, [datetime]$NowUtc = ([datetime]::UtcNow))
    $m = "$Mode".Trim().ToLowerInvariant()
    if ($m -notin @('off', 'observe', 'enforce')) { return @{ ok = $false; status = 400; error = "mode must be off, observe or enforce (got '$Mode')"; value = $null } }
    if ("$Reason".Trim().Length -lt 10) { return @{ ok = $false; status = 400; error = 'a reason of at least 10 characters is required'; value = $null } }
    if ($m -eq 'enforce' -and -not $ConfirmEnforce) { return @{ ok = $false; status = 400; error = 'enforce holds every change whose signed request does not verify -- send confirmEnforce: true to switch it on'; value = $null } }
    $prev = Get-PimSignedRequestConfig -Value $Previous
    $aud = @(@($Audiences) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $aud.Count) { $aud = @($prev.audiences) }
    $tid = "$TenantId".Trim(); if (-not $tid) { $tid = "$($prev.tenantId)" }
    return @{ ok = $true; status = 200; error = ''; value = [ordered]@{ mode = $m; audiences = @($aud); tenantId = $tid; setBy = "$By"; setUtc = $NowUtc.ToString('o')
                                                                       reason = "$Reason".Trim(); previousMode = "$($prev.mode)" } }
}

function Get-PimSignedRequestSettingValue {
    <# The stored 'SignedRequests' setting, from the already-hydrated settings ($global:PIM_NamingConventions -- no SQL read),
       else ONE read when a store is given and nothing was hydrated. Never throws ($null = off). #>
    param([string]$ConnectionString = '', [string]$Name = 'SignedRequests')
    if ($global:PIM_SignedRequestSettingSeam -is [hashtable]) { return $global:PIM_SignedRequestSettingSeam[$Name] }
    if ($global:PIM_NamingConventions -is [hashtable]) {
        if ($global:PIM_NamingConventions.ContainsKey($Name)) { return $global:PIM_NamingConventions[$Name] }
        if ($global:PIM_NamingConventions.Count -gt 0) { return $null }
    }
    if ("$ConnectionString".Trim() -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlSetting -ConnectionString $ConnectionString -Name $Name) } catch { Write-Warning "[signed-requests] the '$Name' setting could not be read (treated as off): $($_.Exception.Message)" }
    }
    return $null
}

# =====================================================================================================================
# CAPTURE (the Manager side)
# =====================================================================================================================

function Get-PimSignedRequestTokenKid {
    <# PURE. The key id a token's header names ('' when unreadable). #>
    param([string]$Token)
    if (-not "$Token".Trim() -or -not (Get-Command Get-PimJwtParts -ErrorAction SilentlyContinue)) { return '' }
    $j = Get-PimJwtParts -Token $Token
    if ($null -eq $j) { return '' }
    return "$($j.header.kid)".Trim()
}

function New-PimSignedRequestCapture {
    <#
      PURE. One captured signature: @{ role; identity; tokenKind (id | access); token; kid; capturedUtc; managerCheck; route }.
      $null when there is no token (nothing to keep -- the engine reports the change as unsigned).
    #>
    param([string]$Token = '', [string]$Identity = '', [string]$Role = '', [ValidateSet('id', 'access')][string]$TokenKind = 'id',
          [string]$Route = '', [string]$ManagerCheck = '', [datetime]$NowUtc = ([datetime]::UtcNow))
    $t = "$Token".Trim()
    if (-not $t) { return $null }
    $cut = { param($s, $n) $x = "$s".Trim(); if ($x.Length -gt $n) { $x.Substring(0, $n) } else { $x } }
    return [pscustomobject]@{
        role = (& $cut $Role 20); identity = (& $cut $Identity 200); tokenKind = $TokenKind; token = $t
        kid = (& $cut (Get-PimSignedRequestTokenKid -Token $t) 200)
        capturedUtc = [datetime]::SpecifyKind($NowUtc.ToUniversalTime(), [DateTimeKind]::Utc)
        managerCheck = (& $cut $ManagerCheck 400); route = (& $cut $Route 200)
    }
}

function Copy-PimSignedRequestCapture {
    <# PURE. The same capture under another role (a capture is reused as committer / requester / approver). #>
    param([AllowNull()][object]$Capture, [string]$Role)
    if ($null -eq $Capture) { return $null }
    $c = [pscustomobject]@{}
    foreach ($p in $Capture.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
    $c | Add-Member -NotePropertyName role -NotePropertyValue "$Role" -Force
    return $c
}

function Get-PimSignedRequestAmbient {
    <# The signature the Manager captured for the request it is serving now ($null outside a signed-in write, or mode off). #>
    return $global:PIM_SignedRequestCapture
}

$script:PimSignedRequestInsertSql = @"
DECLARE @sx NVARCHAR(4000) = NULL;
IF OBJECT_ID(N'pim.SignedRequests') IS NOT NULL
BEGIN
    BEGIN TRY
        INSERT INTO pim.SignedRequests (CommitId, Role, [Identity], TokenKind, Token, Kid, CapturedUtc, ManagerCheck, Route, Manifest, Reason)
        SELECT @sc, @sr, @si, @sk, @st, @sd, @su, @sm, @sp, @sf, @sn
        WHERE NOT EXISTS (SELECT 1 FROM pim.SignedRequests WHERE CommitId = @sc AND Role = @sr AND [Identity] = @si AND CapturedUtc = @su);
    END TRY
    BEGIN CATCH
        SET @sx = ERROR_MESSAGE();
    END CATCH
END
ELSE SET @sx = N'pim.SignedRequests does not exist (the updater creates it)';
SELECT @sx;
"@

function Get-PimSignedRequestInsertParameters {
    <# PURE. The parameter map of one insert (values cut to the column sizes, so a long value never fails a commit). #>
    param([Parameter(Mandatory)][string]$CommitId, [Parameter(Mandatory)][object]$Signature)
    $cut = { param($s, $n) $x = "$s"; if ($x.Length -gt $n) { $x.Substring(0, $n) } else { $x } }
    $nul = { param($s) if ("$s".Trim()) { "$s" } else { $null } }
    $cap = $Signature.capturedUtc
    if (-not ($cap -is [datetime])) { $cap = [datetime]::UtcNow }
    $mf = $null; if ($Signature.PSObject.Properties['manifest'] -and $null -ne $Signature.manifest) { $mf = "$($Signature.manifest)" }
    $rs = $null; if ($Signature.PSObject.Properties['reason'] -and "$($Signature.reason)".Trim()) { $rs = (& $cut "$($Signature.reason)" 400) }
    return [ordered]@{
        sc = (& $cut $CommitId 100); sr = (& $cut "$($Signature.role)" 20); si = (& $cut "$($Signature.identity)" 200)
        sk = $(if ("$($Signature.tokenKind)" -eq 'access') { 'access' } else { 'id' }); st = "$($Signature.token)"
        sd = (& $nul (& $cut "$($Signature.kid)" 200)); su = $cap; sm = (& $nul (& $cut "$($Signature.managerCheck)" 400))
        sp = (& $nul (& $cut "$($Signature.route)" 200)); sf = $mf; sn = $rs
    }
}

function Add-PimSignedRequestRowsTx {
    <#
      Writes the given signatures for one commit on the CALLER's connection + transaction (the journal writer's), so they
      commit with the change. NEVER throws: the insert is guarded in SQL (IF OBJECT_ID + TRY/CATCH) and a client-side error
      is reported, not raised -- a signature must never fail the commit it describes. Returns the number attempted.
    #>
    param([Parameter(Mandatory)][object]$Connection, [AllowNull()][object]$Transaction, [Parameter(Mandatory)][string]$CommitId, [object[]]$Signatures = @())
    $n = 0
    foreach ($s in @($Signatures)) {
        if ($null -eq $s -or -not "$($s.token)".Trim()) { continue }
        try {
            $cmd = $Connection.CreateCommand(); if ($Transaction) { $cmd.Transaction = $Transaction }
            $cmd.CommandText = $script:PimSignedRequestInsertSql
            $p = Get-PimSignedRequestInsertParameters -CommitId $CommitId -Signature $s
            foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) }
            $err = $cmd.ExecuteScalar()
            $n++
            if ($null -ne $err -and -not ($err -is [DBNull]) -and "$err".Trim()) { Write-Warning "[signed-requests] the signature of $($s.identity) on commit $CommitId was NOT kept: $err" }
        } catch { Write-Warning "[signed-requests] the signature of $($s.identity) on commit $CommitId was NOT kept: $($_.Exception.Message)" }
    }
    return $n
}

function Add-PimSignedRequestRowsForJournalTx {
    <#
      Called by Add-PimCommitJournalRowTx after each journal row: the journal context's .signatures are written ONCE per
      transaction (a commit written in several transactions writes them in each; the insert de-duplicates).
    #>
    param([Parameter(Mandatory)][object]$Connection, [AllowNull()][object]$Transaction, [AllowNull()][object]$Context)
    if ($null -eq $Context -or -not $Context.PSObject.Properties['signatures']) { return }
    $sigs = @(@($Context.signatures) | Where-Object { $null -ne $_ })
    if (-not $sigs.Count) { return }
    $marker = if ($Context.PSObject.Properties['__signedTx']) { $Context.__signedTx } else { $null }
    if ($null -ne $marker -and [object]::ReferenceEquals($marker, $Transaction)) { return }
    if ($null -ne $Transaction) { $Context | Add-Member -NotePropertyName '__signedTx' -NotePropertyValue $Transaction -Force }
    if ($global:PIM_SignedRequestStore -is [System.Collections.Generic.List[object]]) {
        foreach ($s in $sigs) { Add-PimSignedRequestToSeam -CommitId "$($Context.commitId)" -Signature $s }
        return
    }
    [void](Add-PimSignedRequestRowsTx -Connection $Connection -Transaction $Transaction -CommitId "$($Context.commitId)" -Signatures $sigs)
}

function Add-PimSignedRequestToSeam {
    # Test seam: $global:PIM_SignedRequestStore (a List[object]) holds the rows in the stored shape.
    param([string]$CommitId, [object]$Signature)
    $p = Get-PimSignedRequestInsertParameters -CommitId $CommitId -Signature $Signature
    foreach ($r in $global:PIM_SignedRequestStore) { if ("$($r.CommitId)" -eq $p.sc -and "$($r.Role)" -eq $p.sr -and "$($r.Identity)" -eq $p.si -and $r.CapturedUtc -eq $p.su) { return } }
    $global:PIM_SignedRequestStore.Add([pscustomobject]@{ Id = $global:PIM_SignedRequestStore.Count + 1; CommitId = $p.sc; Role = $p.sr; Identity = $p.si; TokenKind = $p.sk; Token = $p.st
        Kid = $p.sd; CapturedUtc = $p.su; ManagerCheck = $p.sm; Route = $p.sp; Manifest = $p.sf; Reason = $p.sn })
}

function Save-PimSignedRequestRows {
    <#
      Writes signatures for one commit on their OWN connection (a change-queue entry, a staged change, an approval, an
      adoption -- writes that are not a journaled commit). Best-effort: NEVER throws; returns @{ ok; written; error }.
    #>
    param([string]$ConnectionString = '', [Parameter(Mandatory)][string]$CommitId, [object[]]$Signatures = @())
    $sigs = @(@($Signatures) | Where-Object { $null -ne $_ -and "$($_.token)".Trim() })
    if (-not $sigs.Count) { return @{ ok = $true; written = 0; error = '' } }
    if ($global:PIM_SignedRequestStore -is [System.Collections.Generic.List[object]]) {
        foreach ($s in $sigs) { Add-PimSignedRequestToSeam -CommitId $CommitId -Signature $s }
        return @{ ok = $true; written = $sigs.Count; error = '' }
    }
    if (-not "$ConnectionString".Trim() -or -not (Get-Command New-PimSqlConnection -ErrorAction SilentlyContinue)) { return @{ ok = $false; written = 0; error = 'no SQL store' } }
    $c = $null
    try {
        $c = New-PimSqlConnection -ConnectionString $ConnectionString
        $c.Open()
        $n = Add-PimSignedRequestRowsTx -Connection $c -Transaction $null -CommitId $CommitId -Signatures $sigs
        return @{ ok = $true; written = $n; error = '' }
    } catch {
        Write-Warning "[signed-requests] the signature(s) for $CommitId were NOT kept: $($_.Exception.Message)"
        return @{ ok = $false; written = 0; error = "$($_.Exception.Message)" }
    } finally { if ($c) { try { $c.Close(); $c.Dispose() } catch { } } }
}

function Save-PimSignedRequestForQueue {
    <#
      A change-queue entry: the request's ambient signature, kept under the commit id the engine's drain journals the
      entry with (Invoke-PimSqlCommit: the queue id without dashes). -Role requester (enqueue) | approver (commit).
      No ambient signature (mode off, an engine job, the downlink) = nothing written. Never throws.
    #>
    param([string]$ConnectionString = '', [Parameter(Mandatory)][string]$QueueId, [ValidateSet('requester', 'approver')][string]$Role = 'requester')
    $amb = Get-PimSignedRequestAmbient
    if ($null -eq $amb) { return $null }
    $cid = "$QueueId".Trim().Replace('-', '')
    if (-not $cid) { return $null }
    return (Save-PimSignedRequestRows -ConnectionString $ConnectionString -CommitId $cid -Signatures @(Copy-PimSignedRequestCapture -Capture $amb -Role $Role))
}

function Get-PimSignedRequestRows {
    <#
      The stored signatures of the given commit ids: 'commitId' -> rows (oldest first). Test seam: $global:PIM_SignedRequestStore.
      THROWS when the store cannot be read (the caller decides: the engine treats it as "not verifiable").
    #>
    param([string]$ConnectionString = '', [string[]]$CommitIds = @())
    $want = @{}; foreach ($i in @($CommitIds)) { if ("$i".Trim()) { $want["$i".Trim()] = $true } }
    $out = @{}
    if (-not $want.Count) { return $out }
    $rows = @()
    if ($global:PIM_SignedRequestStore -is [System.Collections.Generic.List[object]]) {
        $rows = @($global:PIM_SignedRequestStore | Where-Object { $want.ContainsKey("$($_.CommitId)") })
    } else {
        if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the signatures from' }
        $json = ConvertTo-Json -InputObject @($want.Keys) -Compress
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ j = $json } -Sql @"
IF OBJECT_ID('pim.SignedRequests') IS NOT NULL
SELECT Id, CommitId, Role, [Identity], TokenKind, Token, Kid, CapturedUtc, ManagerCheck, Route, Reason FROM pim.SignedRequests
WHERE CommitId IN (SELECT [value] FROM OPENJSON(@j)) ORDER BY Id
"@)
    }
    foreach ($r in $rows) {
        $k = "$($r.CommitId)"
        if (-not $out.ContainsKey($k)) { $out[$k] = New-Object System.Collections.Generic.List[object] }
        $out[$k].Add($r)
    }
    $res = @{}; foreach ($k in @($out.Keys)) { $res[$k] = @($out[$k].ToArray()) }
    return $res
}

function Get-PimSignedRequestLatestFor {
    <#
      The newest signature per identity kept under ONE commit id (a staged change 'stage:<entity>', an approval
      'approval:<id>'), for the given identities: identity(lower) -> row. Never throws (empty on a read failure).
    #>
    param([string]$ConnectionString = '', [Parameter(Mandatory)][string]$CommitId, [string[]]$Identities = @())
    $want = @{}; foreach ($i in @($Identities)) { if ("$i".Trim()) { $want["$i".Trim().ToLowerInvariant()] = $true } }
    $out = @{}
    if (-not $want.Count) { return $out }
    try {
        $m = Get-PimSignedRequestRows -ConnectionString $ConnectionString -CommitIds @($CommitId)
        foreach ($r in @($m[$CommitId])) {
            $k = "$($r.Identity)".Trim().ToLowerInvariant()
            if ($want.ContainsKey($k)) { $out[$k] = $r }
        }
    } catch { Write-Warning "[signed-requests] the signatures kept under $CommitId could not be read: $($_.Exception.Message)" }
    return $out
}

function ConvertFrom-PimSignedRequestRow {
    <# PURE. A stored row -> a capture object (to copy a staged / approval signature onto the commit that carries it). #>
    param([AllowNull()][object]$Row, [string]$Role)
    if ($null -eq $Row -or -not "$($Row.Token)".Trim()) { return $null }
    $cap = $Row.CapturedUtc
    if ($cap -is [datetime]) { $cap = [datetime]::SpecifyKind($cap, [DateTimeKind]::Utc) } else { $cap = [datetime]::UtcNow }
    return [pscustomobject]@{ role = "$Role"; identity = "$($Row.Identity)"; tokenKind = $(if ("$($Row.TokenKind)" -eq 'access') { 'access' } else { 'id' })
                              token = "$($Row.Token)"; kid = "$($Row.Kid)"; capturedUtc = $cap
                              managerCheck = "$($Row.ManagerCheck)"; route = "carried from $($Row.CommitId)" }
}

# =====================================================================================================================
# VERIFICATION (pure given the key set, the pins and the role map)
# =====================================================================================================================

function Get-PimOpenIdSigningKeys {
    <#
      The tenant's PUBLISHED signing keys, over REST from its OpenID metadata: GET
      https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration -> jwks_uri -> GET the key set.
      -Fetch: param($uri) -> the parsed JSON (test seam; default Invoke-RestMethod). Never throws: @{ ok; jwks; jwksUri; error }.
      🔒 Fails closed: no key set = no token verifies.
    #>
    param([string]$TenantId = '', [scriptblock]$Fetch = $null)
    $t = "$TenantId".Trim()
    if (-not $t) { return @{ ok = $false; jwks = $null; jwksUri = ''; error = 'no tenant id -- the signing keys cannot be fetched' } }
    if ($null -eq $Fetch -and $global:PIM_SignedRequestKeyFetchSeam -is [scriptblock]) { $Fetch = $global:PIM_SignedRequestKeyFetchSeam }   # tests
    if ($null -eq $Fetch) { $Fetch = { param($u) Invoke-RestMethod -Method GET -Uri $u -TimeoutSec 20 -ErrorAction Stop } }
    $meta = "https://login.microsoftonline.com/$t/v2.0/.well-known/openid-configuration"
    try {
        $m = & $Fetch $meta
        $ju = "$($m.jwks_uri)".Trim()
        if (-not $ju) { return @{ ok = $false; jwks = $null; jwksUri = ''; error = "the OpenID metadata ($meta) names no jwks_uri" } }
        if ($ju -notmatch '^https://login\.microsoftonline\.com/') { return @{ ok = $false; jwks = $null; jwksUri = $ju; error = "the OpenID metadata names a key set outside login.microsoftonline.com ($ju) -- refused" } }
        $k = & $Fetch $ju
        if ($null -eq $k -or -not $k.keys -or @($k.keys).Count -eq 0) { return @{ ok = $false; jwks = $null; jwksUri = $ju; error = "the key set at $ju is empty" } }
        return @{ ok = $true; jwks = $k; jwksUri = $ju; error = '' }
    } catch { return @{ ok = $false; jwks = $null; jwksUri = ''; error = "the signing keys could not be fetched: $($_.Exception.Message)" } }
}

function Get-PimSignedRequestRoleMap {
    <#
      PURE. PIM's own role store as a lookup: identity(lower) -> Reader | Delegated | Admin | SuperAdmin. Source: pim.Settings
      ManagerAccess ({managerAccess:[{identity,role}]} or a bare list; a JSON string is parsed), then the env lists given
      (a name already in ManagerAccess keeps its stored role -- the Manager's order). Unknown role words = Reader.
    #>
    param([AllowNull()][object]$ManagerAccess, [string]$EnvSuperAdmins = '', [string]$EnvAdmins = '', [string]$EnvDelegated = '')
    $map = @{}
    $v = $ManagerAccess
    if ($v -is [string]) { if ("$v".Trim()) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } } else { $v = $null } }
    if ($null -ne $v -and -not ($v -is [array]) -and $v.PSObject.Properties['managerAccess']) { $v = $v.managerAccess }
    foreach ($e in @($v)) {
        if ($null -eq $e) { continue }
        $id = "$($e.identity)".Trim().ToLowerInvariant(); if (-not $id) { continue }
        $r = "$($e.role)".Trim(); if ($r -notin @('Reader', 'Admin', 'SuperAdmin', 'Delegated')) { $r = 'Reader' }
        if (-not $map.ContainsKey($id)) { $map[$id] = $r }
    }
    foreach ($pair in @(@{ l = $EnvSuperAdmins; r = 'SuperAdmin' }, @{ l = $EnvAdmins; r = 'Admin' }, @{ l = $EnvDelegated; r = 'Delegated' })) {
        foreach ($x in @("$($pair.l)" -split '[,;]+')) { $id = $x.Trim().ToLowerInvariant(); if ($id -and -not $map.ContainsKey($id)) { $map[$id] = $pair.r } }
    }
    return $map
}

function Get-PimSignedRequestTokenUser {
    <# PURE. The user a parsed token names (preferred_username, upn, unique_name, email). #>
    param([AllowNull()][object]$Payload)
    if ($null -eq $Payload) { return '' }
    foreach ($c in @('preferred_username', 'upn', 'unique_name', 'email')) { $v = "$($Payload.$c)".Trim(); if ($v) { return $v } }
    return ''
}

function Test-PimSignedRequestToken {
    <#
      PURE. Verifies ONE captured signature for ONE person in ONE position. Checks, in order (the first failure is the reason):
        a token; well-formed; the key set is there; the key id is PUBLISHED (a request older than the published keys fails
        closed); the RS256 signature; issuer + audience pinned and matching; iat <= captured <= exp (clock skew); the token's
        user IS -ExpectedUser; that user's role in -RoleMap is one of -AllowedRoles.
      Returns @{ ok; reason; user; kid; role }.
    #>
    param([AllowNull()][object]$Signature, [AllowNull()][object]$Jwks, [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(),
          [string]$ExpectedUser = '', [string[]]$AllowedRoles = @('Admin', 'SuperAdmin'), [hashtable]$RoleMap = @{}, [int]$ClockSkewSeconds = 300)
    $no = { param($r, $u = '', $k = '') return @{ ok = $false; reason = $r; user = $u; kid = $k; role = '' } }
    if ($null -eq $Signature -or -not "$($Signature.Token)".Trim()) { return (& $no 'no signed token was captured') }
    $jwt = Get-PimJwtParts -Token "$($Signature.Token)"
    if ($null -eq $jwt) { return (& $no 'the captured token is not a well-formed JWT') }
    $kid = "$($jwt.header.kid)".Trim()
    if ($null -eq $Jwks -or -not $Jwks.keys -or @($Jwks.keys).Count -eq 0) { return (& $no "the tenant's published signing keys are not available -- nothing can be verified (fail closed)" '' $kid) }
    if (-not $kid) { return (& $no 'the token names no key id' '' '') }
    $published = @(@($Jwks.keys) | Where-Object { $_ -and "$($_.kid)".Trim() -eq $kid })
    if (-not $published.Count) { return (& $no "the signing key '$kid' is not (any longer) published by the tenant -- a request older than the published keys fails closed" '' $kid) }
    $sig = Test-PimJwtSignature -Jwt $jwt -Jwks $Jwks
    if (-not $sig.valid) { return (& $no "signature: $($sig.reason)" '' $kid) }
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $iss.Count) { return (& $no 'no issuer is pinned (the tenant id is unknown to the engine)' '' $kid) }
    if (-not $aud.Count) { return (& $no "no audience is pinned (pim.Settings 'SignedRequests'.audiences is empty)" '' $kid) }
    # the time line: iat <= captured <= exp
    $cap = $Signature.CapturedUtc
    if (-not ($cap -is [datetime])) { $tmp = [datetime]::MinValue; if ([datetime]::TryParse("$cap", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$tmp)) { $cap = $tmp } else { return (& $no 'the capture time is unreadable' '' $kid) } }
    $cap = [datetime]::SpecifyKind($cap, [DateTimeKind]::Utc)
    $iatRaw = "$($jwt.payload.iat)".Trim(); $expRaw = "$($jwt.payload.exp)".Trim()
    if ($iatRaw -notmatch '^\d+$') { return (& $no 'the token carries no issued-at (iat)' '' $kid) }
    if ($expRaw -notmatch '^\d+$') { return (& $no 'the token carries no expiry (exp)' '' $kid) }
    $iat = ([datetimeoffset]::FromUnixTimeSeconds([int64]$iatRaw)).UtcDateTime
    $exp = ([datetimeoffset]::FromUnixTimeSeconds([int64]$expRaw)).UtcDateTime
    if ($cap -lt $iat.AddSeconds(-$ClockSkewSeconds)) { return (& $no ("captured {0:o}, before the token was issued ({1:o})" -f $cap, $iat) '' $kid) }
    if ($cap -gt $exp.AddSeconds($ClockSkewSeconds)) { return (& $no ("captured {0:o}, after the token expired ({1:o})" -f $cap, $exp) '' $kid) }
    $cl = Test-PimJwtClaims -Payload $jwt.payload -ExpectedIssuers $iss -ExpectedAudiences $aud -NowUtc $cap -ClockSkewSeconds $ClockSkewSeconds
    if (-not $cl.valid) { return (& $no "claims: $($cl.reason)" '' $kid) }
    $user = Get-PimSignedRequestTokenUser -Payload $jwt.payload
    if (-not $user) { return (& $no 'the token names no user' '' $kid) }
    if ("$ExpectedUser".Trim() -and $user.ToLowerInvariant() -ne "$ExpectedUser".Trim().ToLowerInvariant()) {
        return (& $no "the token is for '$user', the change names '$("$ExpectedUser".Trim())'" $user $kid)
    }
    $role = ''
    if ($RoleMap -and $RoleMap.ContainsKey($user.ToLowerInvariant())) { $role = "$($RoleMap[$user.ToLowerInvariant()])" }
    if ($AllowedRoles -notcontains $role) {
        $has = if ($role) { "holds '$role'" } else { 'holds no role' }
        return @{ ok = $false; reason = ("'$user' $has in PIM's role store; this needs " + (@($AllowedRoles) -join ' / ')); user = $user; kid = $kid; role = $role }
    }
    return @{ ok = $true; reason = 'verified'; user = $user; kid = $kid; role = $role }
}

function Test-PimSignedRequestPerson {
    <# PURE. Is this journal actor a PERSON (a sign-in name) -- not a job ('system:...', 'engine', 'msp-downlink')? #>
    param([string]$Actor)
    $a = "$Actor".Trim()
    return [bool]($a -and $a -match '@' -and $a -notmatch '^(?i)system')
}

function Get-PimSignedRequestRolesFor {
    <# PURE. Who may hold which position: an initiator Delegated / Admin / SuperAdmin, an approver Admin / SuperAdmin, an
       adoption SuperAdmin only. #>
    param([ValidateSet('requester', 'approver', 'adoption')][string]$Position)
    switch ($Position) {
        'requester' { return @('Delegated', 'Admin', 'SuperAdmin') }
        'approver'  { return @('Admin', 'SuperAdmin') }
        default     { return @('SuperAdmin') }
    }
}

function Get-PimSignedRequestCommitVerdict {
    <#
      PURE given -Verify. Does this commit carry a verified token for EVERY person it names? -Commit: { CommitId; InitiatedBy;
      ApprovedBy } (the journal row the engine resolved). -Signatures: the commit's stored rows. -Verify: param($sig, $user,
      $position) -> Test-PimSignedRequestToken's result.
        the initiator (when a person) needs a verified token as requester; the approver (when named and a person) needs one
        as approver; a commit naming NO person (a job's proposal nobody approved) is refused -- nothing was signed.
      Returns @{ ok; reason; signedBy = @(users) }.
    #>
    param([Parameter(Mandatory)][object]$Commit, [object[]]$Signatures = @(), [Parameter(Mandatory)][scriptblock]$Verify)
    $sigs = @(@($Signatures) | Where-Object { $null -ne $_ })
    $need = New-Object System.Collections.Generic.List[object]
    $ini = "$($Commit.InitiatedBy)".Trim(); $apv = "$($Commit.ApprovedBy)".Trim()
    if (Test-PimSignedRequestPerson -Actor $ini) { $need.Add(@{ user = $ini; position = 'requester' }) }
    if ($apv -and (Test-PimSignedRequestPerson -Actor $apv) -and $apv.ToLowerInvariant() -ne $ini.ToLowerInvariant()) { $need.Add(@{ user = $apv; position = 'approver' }) }
    if (-not $need.Count) { return @{ ok = $false; reason = "no person is named on commit $($Commit.CommitId) (initiator '$ini') -- nothing was signed"; signedBy = @() } }
    $signed = New-Object System.Collections.Generic.List[string]
    foreach ($n in $need) {
        if (-not $sigs.Count) { return @{ ok = $false; reason = "no signed token was captured for commit $($Commit.CommitId) ($($n.position) $($n.user))"; signedBy = @($signed.ToArray()) } }
        # the person's own captures first (the token decides who it is, the stored name only orders the tries)
        $mine = @($sigs | Where-Object { "$($_.Identity)".Trim().ToLowerInvariant() -eq "$($n.user)".ToLowerInvariant() })
        $others = @($sigs | Where-Object { "$($_.Identity)".Trim().ToLowerInvariant() -ne "$($n.user)".ToLowerInvariant() })
        $first = $null; $okOne = $null
        foreach ($s in @($mine + $others)) {
            $v = & $Verify $s "$($n.user)" "$($n.position)"
            if ($v.ok) { $okOne = $v; break }
            if ($null -eq $first) { $first = $v }
        }
        if ($null -eq $okOne) {
            $why = if ($first) { "$($first.reason)" } else { 'no signed token' }
            if (-not $mine.Count) { $why = "no signed token was captured for the $($n.position) $($n.user)" + $(if ($first) { " (the token kept: $($first.reason))" } else { '' }) }
            return @{ ok = $false; reason = "$($n.position) $($n.user): $why"; signedBy = @($signed.ToArray()) }
        }
        $signed.Add("$($okOne.user)")
    }
    return @{ ok = $true; reason = 'verified'; signedBy = @($signed.ToArray()) }
}

function ConvertTo-PimSignedRequestRowRef {
    # PURE. 'entity|key' (lower) -- the manifest key of one stored row.
    param([string]$Entity, [string]$Key)
    return ("{0}|{1}" -f "$Entity".Trim(), "$Key".Trim()).ToLowerInvariant()
}

function Test-PimSignedRequestAdoptionCovers {
    <#
      PURE. Does a VERIFIED adoption cover this change? -Adoption: { adoptedUtc; manifest = @{ 'entity|key' = hash } }.
      -Refs: the stored rows the item maps to (@{ entity; key }). -RowHashes: the CURRENT hash per 'entity|key'.
        covered when one ref's current hash equals its adopted hash (the row is exactly as adopted), or -- for a Remove -- the
        ref is gone now, was not in the adopted state either, and the commit that removed it is not newer than the adoption.
      Returns @{ ok; reason }.
    #>
    param([AllowNull()][object]$Adoption, [string]$Op = '', [object[]]$Refs = @(), [hashtable]$RowHashes = @{}, [AllowNull()][object]$Commit = $null)
    if ($null -eq $Adoption) { return @{ ok = $false; reason = 'no verified adoption of the existing desired state' } }
    $mf = $Adoption.manifest
    $refs = @(@($Refs) | Where-Object { $_ })
    if (-not $refs.Count) { return @{ ok = $false; reason = 'the change maps to no stored row, so the adoption cannot cover it' } }
    foreach ($r in $refs) {
        $k = ConvertTo-PimSignedRequestRowRef -Entity "$($r.entity)" -Key "$($r.key)"
        $cur = if ($RowHashes.ContainsKey($k)) { "$($RowHashes[$k])" } else { '' }
        $was = if ($mf -is [hashtable] -and $mf.ContainsKey($k)) { "$($mf[$k])" } else { '' }
        if ($cur -and $was -and $cur -eq $was) { return @{ ok = $true; reason = 'the row is exactly as adopted' } }
        if ("$Op" -match '^(?i)remove$' -and -not $cur -and -not $was) {
            $cu = $null; if ($Commit -and $Commit.CommittedUtc -is [datetime]) { $cu = [datetime]::SpecifyKind($Commit.CommittedUtc, [DateTimeKind]::Utc) }
            if ($null -eq $Commit -or ($cu -and $cu -le $Adoption.adoptedUtc)) { return @{ ok = $true; reason = 'removed before the adoption' } }
        }
    }
    return @{ ok = $false; reason = 'the row changed after the adoption (or was never adopted) and no signed commit names it' }
}

function ConvertFrom-PimSignedRequestManifest {
    <# PURE. The stored manifest text ({ 'entity|key': hash }) -> hashtable (keys lower). Empty on anything unreadable. #>
    param([AllowNull()][string]$Text)
    $h = @{}
    if (-not "$Text".Trim()) { return $h }
    try {
        $o = $Text | ConvertFrom-Json
        foreach ($p in $o.PSObject.Properties) { $h["$($p.Name)".ToLowerInvariant()] = "$($p.Value)" }
    } catch { }
    return $h
}

function Get-PimSignedRequestRowHashSql {
    # The ONE definition of a row's hash -- used by the adoption (the manifest) and by the engine (the current state).
    return "SELECT Entity, [Key], CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', ISNULL(DataJson, N'')), 2) AS H FROM pim.Rows"
}

function Get-PimSignedRequestRowHashes {
    <# The current hash of every stored row: 'entity|key' (lower) -> hash. Test seam: $global:PIM_SignedRequestRowHashSeam
       (the same hashtable). THROWS on a read failure. #>
    param([string]$ConnectionString = '')
    if ($global:PIM_SignedRequestRowHashSeam -is [hashtable]) { return $global:PIM_SignedRequestRowHashSeam }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the row hashes from' }
    $h = @{}
    foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql (Get-PimSignedRequestRowHashSql))) { $h[(ConvertTo-PimSignedRequestRowRef -Entity "$($r.Entity)" -Key "$($r.Key)")] = "$($r.H)" }
    return $h
}

function Get-PimSignedRequestAdoptionRows {
    <# Every adoption record (newest first). Test seam: $global:PIM_SignedRequestStore. THROWS on a read failure. #>
    param([string]$ConnectionString = '')
    if ($global:PIM_SignedRequestStore -is [System.Collections.Generic.List[object]]) {
        return @(@($global:PIM_SignedRequestStore | Where-Object { "$($_.Role)" -eq 'adoption' }) | Sort-Object { [long]$_.Id } -Descending)
    }
    if (-not "$ConnectionString".Trim()) { throw 'no SQL store to read the adoption from' }
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql @"
IF OBJECT_ID('pim.SignedRequests') IS NOT NULL
SELECT Id, CommitId, Role, [Identity], TokenKind, Token, Kid, CapturedUtc, ManagerCheck, Route, Manifest, Reason FROM pim.SignedRequests
WHERE Role = 'adoption' ORDER BY Id DESC
"@)
}

function New-PimSignedRequestAdoption {
    <#
      The adoption of the EXISTING desired state (a SuperAdmin, signed in, from the Manager): one record under
      'adoption:<guid>' holding the SuperAdmin's captured token and the manifest of every stored row's hash NOW.
      -Capture: the SuperAdmin's capture. -Hashes: param() -> the row-hash map (test seam; default the store read).
      Returns @{ ok; commitId; rows; error }. Never throws.
    #>
    param([string]$ConnectionString = '', [AllowNull()][object]$Capture, [string]$Reason = '', [scriptblock]$Hashes = $null)
    if ($null -eq $Capture -or -not "$($Capture.token)".Trim()) { return @{ ok = $false; commitId = ''; rows = 0; error = 'no signed token on this request -- an adoption must be signed (turn the token store on, sign in again)' } }
    if ("$Reason".Trim().Length -lt 10) { return @{ ok = $false; commitId = ''; rows = 0; error = 'a reason of at least 10 characters is required' } }
    try {
        $h = if ($Hashes) { & $Hashes } else { Get-PimSignedRequestRowHashes -ConnectionString $ConnectionString }
        $ordered = [ordered]@{}; foreach ($k in @($h.Keys | Sort-Object)) { $ordered[$k] = "$($h[$k])" }
        $id = 'adoption:' + [guid]::NewGuid().ToString('N')
        $sig = Copy-PimSignedRequestCapture -Capture $Capture -Role 'adoption'
        $sig | Add-Member -NotePropertyName manifest -NotePropertyValue (ConvertTo-Json -InputObject $ordered -Compress -Depth 3) -Force
        $sig | Add-Member -NotePropertyName reason -NotePropertyValue "$Reason".Trim() -Force
        $w = Save-PimSignedRequestRows -ConnectionString $ConnectionString -CommitId $id -Signatures @($sig)
        if (-not $w.ok) { return @{ ok = $false; commitId = $id; rows = 0; error = "$($w.error)" } }
        return @{ ok = $true; commitId = $id; rows = $ordered.Count; error = '' }
    } catch { return @{ ok = $false; commitId = ''; rows = 0; error = "$($_.Exception.Message)" } }
}

# =====================================================================================================================
# THE ENGINE CHECK
# =====================================================================================================================

function Get-PimSignedRequestStoreCs {
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { return "$(Get-PimSqlSettingsConnectionString)" } catch { } }
    return ''
}

function Initialize-PimSignedRequestRun {
    <#
      Once per engine run (keyed by the job's correlation id): the mode; when not off, the pins, the published keys, the role
      map and the verified adoption. Mode off returns at once -- nothing fetched, nothing read beyond the hydrated settings.
      -Fetch: the key fetch seam (Get-PimOpenIdSigningKeys). Returns the run state (also kept in $global:PIM_SignedRequestRun).
    #>
    param([scriptblock]$Fetch = $null, [switch]$Force)
    $corr = "$($global:PIM_JobCorrelationId)"
    $st = $global:PIM_SignedRequestRun
    if (-not $Force -and $st -is [hashtable] -and "$($st.run)" -eq $corr) { return $st }
    $cs = Get-PimSignedRequestStoreCs
    $extra = @("$env:PIM_SIGNED_REQUEST_AUDIENCE" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $cfg = Get-PimSignedRequestConfig -Value (Get-PimSignedRequestSettingValue -ConnectionString $cs) -ExtraAudiences $extra
    $st = @{ run = $corr; mode = $cfg.mode; unknown = $cfg.unknown; raw = $cfg.raw; audiences = @($cfg.audiences); issuers = @(); jwks = $null; keysError = ''
             roleMap = @{}; sigs = @{}; verdicts = @{}; tokenChecks = @{}; adoption = $null; adoptionNote = ''; rowHashes = $null
             counts = @{ checked = 0; verified = 0; wouldRefuse = 0; refused = 0; adopted = 0 }; reasons = @{}
             runCounts = @{ checked = 0; verified = 0; wouldRefuse = 0; refused = 0; adopted = 0 }; lines = (New-Object System.Collections.Generic.List[string]) }
    $global:PIM_SignedRequestRun = $st
    if ($st.mode -eq 'off') { return $st }
    if ($st.unknown) { $st.lines.Add("signed requests: the mode '$($cfg.raw)' is not off / observe / enforce -- treated as OBSERVE (nothing is refused)") }
    $tid = $cfg.tenantId
    if (-not $tid) { $tid = "$($global:PIM_TenantId)".Trim() }
    if (-not $tid) { $tid = "$env:PIM_TenantId".Trim() }
    if (-not $tid) { $tid = "$env:PIM_HOSTED_AUTH_TENANT".Trim() }
    if ($tid -and (Get-Command Get-PimHostedDefaultIssuers -ErrorAction SilentlyContinue)) { $st.issuers = @(Get-PimHostedDefaultIssuers -TenantId $tid) }
    $k = Get-PimOpenIdSigningKeys -TenantId $tid -Fetch $Fetch
    $st.jwks = $k.jwks; $st.keysError = "$($k.error)"
    $st.roleMap = Get-PimSignedRequestRoleMap -ManagerAccess (Get-PimSignedRequestSettingValue -ConnectionString $cs -Name 'ManagerAccess') `
                    -EnvSuperAdmins "$env:PIM_SuperAdmins" -EnvAdmins "$env:PIM_Admins" -EnvDelegated "$env:PIM_DelegatedAdmins"
    # the newest adoption that VERIFIES (a SuperAdmin's token) -- an older one stays a fallback, a forged one covers nothing
    try {
        foreach ($a in @(Get-PimSignedRequestAdoptionRows -ConnectionString $cs)) {
            $v = Test-PimSignedRequestToken -Signature $a -Jwks $st.jwks -ExpectedIssuers $st.issuers -ExpectedAudiences $st.audiences `
                    -ExpectedUser "$($a.Identity)" -AllowedRoles (Get-PimSignedRequestRolesFor -Position adoption) -RoleMap $st.roleMap
            if ($v.ok) {
                $au = $a.CapturedUtc; if ($au -is [datetime]) { $au = [datetime]::SpecifyKind($au, [DateTimeKind]::Utc) } else { $au = [datetime]::MinValue }
                $st.adoption = @{ commitId = "$($a.CommitId)"; by = "$($v.user)"; adoptedUtc = $au; manifest = (ConvertFrom-PimSignedRequestManifest -Text "$($a.Manifest)") }
                break
            }
            if (-not $st.adoptionNote) { $st.adoptionNote = "adoption $($a.CommitId) by $($a.Identity) does not verify: $($v.reason)" }
        }
    } catch { $st.adoptionNote = "the adoption could not be read: $($_.Exception.Message)" }
    if ($st.adoptionNote) { $st.lines.Add("signed requests: $($st.adoptionNote)") }
    if ($st.keysError) { $st.lines.Add("signed requests: $($st.keysError) -- every change is unverifiable this run") }
    return $st
}

function Get-PimSignedRequestRunSignatures {
    # The run's signature cache for one commit (one read per commit per run). A read failure = no signatures (unverifiable).
    param([hashtable]$State, [string]$CommitId)
    if ($State.sigs.ContainsKey($CommitId)) { return @($State.sigs[$CommitId]) }
    $rows = @()
    try { $m = Get-PimSignedRequestRows -ConnectionString (Get-PimSignedRequestStoreCs) -CommitIds @($CommitId); if ($m.ContainsKey($CommitId)) { $rows = @($m[$CommitId]) } }
    catch { Write-Warning "[signed-requests] the signatures of commit $CommitId could not be read (treated as unsigned): $($_.Exception.Message)" }
    $State.sigs[$CommitId] = $rows
    return $rows
}

function Test-PimEngineSignedRequest {
    <#
      THE ENGINE CHECK for one change, right before its handler acts. -Commit: Resolve-PimEngineChangeCommit's answer (or
      $null); -Refs: Get-PimEngineItemStoreRefs. Returns @{ mode; ok; refuse; reason; commitId; via }:
        mode off              -> ok, nothing checked (and nothing counted);
        observe / unknown     -> ok = the verdict; refuse = $false ALWAYS (applied as today, reported when not ok);
        enforce               -> refuse = -not ok.
      Never throws: a fault in the check itself is a verdict "the check could not run: ..." (refused only in enforce).
    #>
    param([AllowNull()][object]$Commit, [object[]]$Refs = @(), [string]$Op = '', [hashtable]$State = $null)
    if ($null -eq $State) { $State = Initialize-PimSignedRequestRun }
    if ($State.mode -eq 'off') { return @{ mode = 'off'; ok = $true; refuse = $false; reason = ''; commitId = ''; via = '' } }
    $ok = $false; $reason = ''; $cid = ''; $via = ''
    try {
        $verify = {
            param($sig, $user, $position)
            $ck = "{0}|{1}|{2}" -f "$($sig.Id)", "$user".ToLowerInvariant(), $position
            if ($State.tokenChecks.ContainsKey($ck)) { return $State.tokenChecks[$ck] }
            $r = Test-PimSignedRequestToken -Signature $sig -Jwks $State.jwks -ExpectedIssuers $State.issuers -ExpectedAudiences $State.audiences `
                    -ExpectedUser $user -AllowedRoles (Get-PimSignedRequestRolesFor -Position $position) -RoleMap $State.roleMap
            $State.tokenChecks[$ck] = $r
            return $r
        }.GetNewClosure()
        $journal = ($Commit -and "$($Commit.CommitId)".Trim() -and "$($Commit.via)" -ne 'attribution')
        if ($journal) {
            $cid = "$($Commit.CommitId)".Trim()
            $vk = "{0}|{1}|{2}" -f $cid, "$($Commit.InitiatedBy)".ToLowerInvariant(), "$($Commit.ApprovedBy)".ToLowerInvariant()
            if ($State.verdicts.ContainsKey($vk)) { $cv = $State.verdicts[$vk] }
            else { $cv = Get-PimSignedRequestCommitVerdict -Commit $Commit -Signatures @(Get-PimSignedRequestRunSignatures -State $State -CommitId $cid) -Verify $verify; $State.verdicts[$vk] = $cv }
            if ($cv.ok) { $ok = $true; $via = 'signed commit'; $reason = "signed by $(@($cv.signedBy) -join ', ')" }
            else { $reason = "$($cv.reason)" }
        } else { $reason = 'no commit names this change' }
        if (-not $ok) {
            # the adoption of the existing desired state may cover it
            if ($null -ne $State.adoption) {
                if ($null -eq $State.rowHashes) {
                    try { $State.rowHashes = Get-PimSignedRequestRowHashes -ConnectionString (Get-PimSignedRequestStoreCs) }
                    catch { $State.rowHashes = @{}; $State.lines.Add("signed requests: the stored rows' hashes could not be read -- the adoption covers nothing this run: $($_.Exception.Message)") }
                }
                $ad = Test-PimSignedRequestAdoptionCovers -Adoption $State.adoption -Op $Op -Refs @($Refs) -RowHashes $State.rowHashes -Commit $(if ($journal) { $Commit } else { $null })
                if ($ad.ok) { $ok = $true; $via = 'adoption'; $reason = "$($ad.reason) (adoption $($State.adoption.commitId) by $($State.adoption.by))" }
                else { $reason = "$reason; $($ad.reason)" }
            } else { $reason = "$reason; no verified adoption of the existing desired state" }
        }
    } catch { $ok = $false; $reason = "the check could not run: $($_.Exception.Message)" }
    return @{ mode = $State.mode; ok = $ok; refuse = ($State.mode -eq 'enforce' -and -not $ok); reason = $reason; commitId = $cid; via = $via }
}

function Get-PimSignedRequestReasonClass {
    # PURE. A short class of a reason, for the counts (never the user names).
    param([string]$Reason)
    $r = "$Reason"
    # "nothing captured for this person" first: its text may quote why ANOTHER person's token did not fit
    if ($r -match 'no signed token was captured') { return 'not-captured' }
    if ($r -match 'not \(any longer\) published') { return 'key-not-published' }
    if ($r -match 'signing keys are not available') { return 'keys-unavailable' }
    if ($r -match 'signature:') { return 'bad-signature' }
    if ($r -match 'no audience is pinned') { return 'no-audience' }
    if ($r -match 'no issuer is pinned') { return 'no-issuer' }
    if ($r -match 'claims: issuer') { return 'wrong-issuer' }
    if ($r -match 'claims: audience') { return 'wrong-audience' }
    if ($r -match 'after the token expired') { return 'captured-after-exp' }
    if ($r -match 'before the token was issued') { return 'captured-before-iat' }
    if ($r -match 'the token is for') { return 'wrong-user' }
    if ($r -match "in PIM's role store") { return 'wrong-role' }
    if ($r -match 'no signed token was captured') { return 'not-captured' }
    if ($r -match 'no person is named') { return 'no-person' }
    if ($r -match 'no commit names this change') { return 'no-commit' }
    if ($r -match 'could not run') { return 'check-error' }
    return 'other'
}

function Add-PimSignedRequestObservation {
    <#
      Records one checked change in the run state: the counts, the reason class and -- for a change that does not verify --
      ONE log line ("would have refused" in observe, "REFUSED" in enforce) that the engine prints and the run log carries.
      Returns the line ('' for a verified change).
    #>
    param([Parameter(Mandatory)][hashtable]$Verdict, [string]$Scope = '', [string]$Op = '', [string]$Key = '', [hashtable]$State = $null)
    if ($null -eq $State) { $State = $global:PIM_SignedRequestRun }
    if ($null -eq $State -or "$($Verdict.mode)" -eq 'off') { return '' }
    # .counts = not yet saved (Save-PimSignedRequestStats empties it); .runCounts = this run, for its log line
    $bump = { param($n) foreach ($c in @($State.counts, $State.runCounts)) { if ($c -is [hashtable]) { $c[$n] = 1 + [int]$c[$n] } } }
    & $bump 'checked'
    if ($Verdict.ok) { & $bump 'verified'; if ("$($Verdict.via)" -eq 'adoption') { & $bump 'adopted' }; return '' }
    $cls = Get-PimSignedRequestReasonClass -Reason "$($Verdict.reason)"
    $State.reasons[$cls] = 1 + [int]$State.reasons[$cls]
    if ($Verdict.refuse) { & $bump 'refused'; $word = 'REFUSED (not applied)' } else { & $bump 'wouldRefuse'; $word = 'would have refused' }
    $line = ("signed request {0}: {1} {2} {3}{4} -- {5}" -f $word, $Scope, $Op, $Key, $(if ("$($Verdict.commitId)") { " (commit $($Verdict.commitId))" } else { '' }), "$($Verdict.reason)")
    if ($State.lines.Count -lt 200) { $State.lines.Add($line) } elseif ($State.lines.Count -eq 200) { $State.lines.Add('signed requests: more changes did not verify -- see the counts') }
    return $line
}

function Get-PimSignedRequestRunLogLines {
    <# The run's signed-request lines + a count line, for the run log (Jobs > Engine logs & errors); CONSUMED (cleared). #>
    $st = $global:PIM_SignedRequestRun
    if (-not ($st -is [hashtable]) -or "$($st.mode)" -eq 'off') { return @() }
    $c = $st.runCounts
    if ([int]$c.checked -eq 0 -and $st.lines.Count -eq 0) { return @() }
    $out = @(("signed requests ({0}): {1} change(s) checked, {2} verified ({3} by the adoption), {4} would have been refused, {5} refused" -f $st.mode, [int]$c.checked, [int]$c.verified, [int]$c.adopted, [int]$c.wouldRefuse, [int]$c.refused))
    $out += @($st.lines.ToArray())
    $st.lines.Clear()
    foreach ($k in @($c.Keys)) { $c[$k] = 0 }
    return $out
}

function Merge-PimSignedRequestStats {
    <# PURE. The stored totals ('SignedRequestStats') + this run's counts -> the new record. #>
    param([AllowNull()][object]$Previous, [Parameter(Mandatory)][hashtable]$State, [datetime]$NowUtc = ([datetime]::UtcNow))
    $num = { param($o, $n) if ($null -eq $o) { 0 } elseif ($o -is [System.Collections.IDictionary]) { [int]$o[$n] } elseif ($o.PSObject.Properties[$n]) { [int]$o.$n } else { 0 } }
    $p = $Previous; if ($p -is [string]) { try { $p = $p | ConvertFrom-Json } catch { $p = $null } }
    if ($p -is [System.Collections.IDictionary]) { try { $p = $p | ConvertTo-Json -Depth 6 | ConvertFrom-Json } catch { $p = $null } }
    $pt = $null; if ($p -and $p.PSObject.Properties['totals']) { $pt = $p.totals }
    $since = if ($p -and "$($p.sinceUtc)".Trim() -and "$($p.mode)" -eq "$($State.mode)") { "$($p.sinceUtc)" } else { $NowUtc.ToString('o') }
    if ($p -and "$($p.mode)" -ne "$($State.mode)") { $pt = $null }
    $reasons = [ordered]@{}
    if ($p -and $p.PSObject.Properties['reasons'] -and "$($p.mode)" -eq "$($State.mode)") { foreach ($q in $p.reasons.PSObject.Properties) { $reasons[$q.Name] = [int]$q.Value } }
    foreach ($k in @($State.reasons.Keys)) { $reasons[$k] = [int]$reasons[$k] + [int]$State.reasons[$k] }
    $c = $State.counts
    return [ordered]@{
        mode = "$($State.mode)"; sinceUtc = $since; updatedUtc = $NowUtc.ToString('o')
        lastRun = [ordered]@{ run = "$($State.run)"; checked = [int]$c.checked; verified = [int]$c.verified; adopted = [int]$c.adopted; wouldRefuse = [int]$c.wouldRefuse; refused = [int]$c.refused }
        totals = [ordered]@{ checked = (& $num $pt 'checked') + [int]$c.checked; verified = (& $num $pt 'verified') + [int]$c.verified; wouldRefuse = (& $num $pt 'wouldRefuse') + [int]$c.wouldRefuse; refused = (& $num $pt 'refused') + [int]$c.refused }
        reasons = $reasons
    }
}

function Save-PimSignedRequestStats {
    <# The counts of this run added to pim.Settings 'SignedRequestStats' (the telemetry source). Mode off / nothing checked =
       nothing written. Never throws. Test seam: $global:PIM_SignedRequestSettingSeam (the record is kept there). #>
    param([hashtable]$State = $null)
    if ($null -eq $State) { $State = $global:PIM_SignedRequestRun }
    if (-not ($State -is [hashtable]) -or "$($State.mode)" -eq 'off' -or [int]$State.counts.checked -eq 0) { return $false }
    try {
        if ($global:PIM_SignedRequestSettingSeam -is [hashtable]) {
            $global:PIM_SignedRequestSettingSeam['SignedRequestStats'] = (Merge-PimSignedRequestStats -Previous $global:PIM_SignedRequestSettingSeam['SignedRequestStats'] -State $State)
        } else {
            $cs = Get-PimSignedRequestStoreCs
            if (-not $cs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { return $false }
            $prev = Get-PimSqlSetting -ConnectionString $cs -Name 'SignedRequestStats'
            Set-PimSqlSetting -ConnectionString $cs -Name 'SignedRequestStats' -Value (Merge-PimSignedRequestStats -Previous $prev -State $State)
        }
        # counted once: the next pass of the same run adds only what it checks itself
        foreach ($k in @($State.counts.Keys)) { $State.counts[$k] = 0 }
        $State.reasons = @{}
        return $true
    } catch { Write-Warning "[signed-requests] the counts were not saved: $($_.Exception.Message)"; return $false }
}

function Get-PimSignedRequestHeartbeatValue {
    <# PURE. The heartbeat's SignedRequests field: { mode; checked; wouldRefuse; refused; sinceUtc } -- $null when off (the
       field is then left out, so an install that never switched it on sends exactly what it sent before). #>
    param([AllowNull()][object]$Setting, [AllowNull()][object]$Stats)
    $cfg = Get-PimSignedRequestConfig -Value $Setting
    if ($cfg.mode -eq 'off') { return $null }
    $s = $Stats; if ($s -is [string]) { try { $s = $s | ConvertFrom-Json } catch { $s = $null } }
    if ($s -is [System.Collections.IDictionary]) { try { $s = $s | ConvertTo-Json -Depth 6 | ConvertFrom-Json } catch { $s = $null } }
    $t = $null; if ($s -and $s.PSObject.Properties['totals'] -and "$($s.mode)" -eq $cfg.mode) { $t = $s.totals }
    $n = { param($n) if ($t -and $t.PSObject.Properties[$n]) { [int]$t.$n } else { 0 } }
    return [pscustomobject][ordered]@{ mode = $cfg.mode; checked = (& $n 'checked'); wouldRefuse = (& $n 'wouldRefuse'); refused = (& $n 'refused')
                                       sinceUtc = $(if ($t) { "$($s.sinceUtc)" } else { '' }) }
}
