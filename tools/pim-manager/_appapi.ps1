<#
  _appapi.ps1 -- PIM Manager: what an API APPLICATION does beyond the page's own handlers (functions only, dot-sourced by
  Open-PimManager.ps1; a missing file stops the Manager -- fail closed).

    SETTINGS-API-1   (framework 12.31, owner 2026-11-16 "it should be possible to manage settings using code, not only gui")
                     Invoke-PimManagerAppSettingsExport / -Import   the settings as ONE JSON (no secret value; person-only
                                                                    settings read-only, refused on import with the list)
                     Invoke-PimManagerAppCommit                     a tier-1 commit through the SAME commit path and guards
    PEOPLE-API-APPROVAL-1 (owner 2026-11-16 "customer ask me to adjust people and roles", "Code + approver")
                     Invoke-PimManagerAppSubmit                     an Admin app PROPOSES a tier-2 change -> the approval queue
                     Test-PimManagerAppChangeApprover / Invoke-PimManagerAppChangeExecute   a PERSON approves; it runs
                                                                    through the normal commit path as that person
    SUPPORT-FIX-API-1 (framework 12.30) + SUPPORT-DIRECT-GRANT-1 (owner 2026-11-16 "Support applies directly")
                     Invoke-PimManagerSupportRoute                  POST /api/support/fix | /api/support/change, Support role
                                                                    only, on a SUP-YYYY-NNNNN ticket, mailed + rate limited
  The tier decisions are the PURE literal map in engine/_shared/PIM-ManagerApiApps.ps1 (Get-PimManagerAppTierMap). Every
  application call is audited api.app.call by the server loop; the functions here add what changed (api.app.* / support.*).
  PS 5.1-safe. ASCII only.
#>
Set-StrictMode -Off

function Get-PimManagerAppBodyProp {
    param($Body, [string]$Name)
    if ($null -eq $Body) { return $null }
    if ($Body -is [System.Collections.IDictionary]) { if ($Body.Contains($Name)) { return $Body[$Name] }; return $null }
    $p = $Body.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimManagerAppDictEntries {
    # the name / value pairs of an ordered dictionary OR an object (PSObject.Properties does not list dictionary keys)
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IDictionary]) { return @($Value.Keys | ForEach-Object { [pscustomobject]@{ Name = "$_"; Value = $Value[$_] } }) }
    return @($Value.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
}

function Get-PimManagerAppActor {
    $a = $script:CurrentRequestApp
    if (-not $a) { return [ordered]@{ appId = ''; name = ''; role = '' } }
    return [ordered]@{ appId = "$($a.appId)"; name = "$($a.name)"; role = "$($a.role)" }
}

# ---- SETTINGS-API-1: export / import ------------------------------------------------------------------------------------
function Invoke-PimManagerAppSettingsExport {
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Response)
    if (-not (Get-Command New-PimSettingsExport -ErrorAction SilentlyContinue)) { Write-JsonResponse -Response $Response -Status 501 -Body @{ error = 'the settings library is not loaded in this Manager' }; return 501 }
    $script:lastHeartbeat = Get-Date
    $reader = { param($n) Get-PimManagerSetting -Name $n }
    try {
        $doc = New-PimSettingsExport -Sections @() -Reader $reader -ProductVersion "$(Get-PimSolutionVersion)" -Source "$($script:PimInstanceName)"
        $po = Get-PimManagerAppPersonOnlySettings
        $secs = [ordered]@{}; $poIn = New-Object System.Collections.Generic.List[string]
        foreach ($sp in @(Get-PimManagerAppDictEntries $doc.sections)) {
            $vals = [ordered]@{}
            foreach ($np in @(Get-PimManagerAppDictEntries $sp.Value)) {
                $vals[$np.Name] = ConvertTo-PimManagerAppRedactedValue -Value $np.Value
                if ($po.Contains($np.Name)) { $poIn.Add($np.Name) }
            }
            $secs[$sp.Name] = [pscustomobject]$vals
        }
        $ro = [ordered]@{}
        foreach ($n in @(Get-PimManagerAppExportReadOnlyNames)) {
            $v = $null; try { $v = & $reader $n } catch { $v = $null }
            if ($null -eq $v) { continue }
            $ro[$n] = [ordered]@{ value = (ConvertTo-PimManagerAppRedactedValue -Value (ConvertTo-PimSettingsTransferValue -Value $v)); readOnly = $true
                                  personOnly = [bool]$po.Contains($n); reason = $(if ($po.Contains($n)) { "person only: $($po[$n])" } else { 'shown for reference; change it with its own route' }) }
        }
        $out = [ordered]@{
            format = "$($doc.format)"; formatVersion = $doc.formatVersion; productVersion = "$($doc.productVersion)"; source = "$($doc.source)"; exportedUtc = "$($doc.exportedUtc)"
            sections = [pscustomobject]$secs; readOnly = [pscustomobject]$ro
            personOnly = @($poIn.ToArray() | Select-Object -Unique); secretsWithheld = (Get-PimManagerAppSecretMarker)
            note = 'Every setting is here; secret values are withheld. Person-only settings are listed under personOnly / readOnly and an import refuses to change them.'
        }
        Write-PimManagerAuditEvent -Action 'settings.export' -Target 'settings' -After ([ordered]@{ via = 'api-app'; app = (Get-PimManagerAppActor); sections = @($secs.Keys) }) -Result 'ok'
        Write-JsonResponse -Response $Response -Status 200 -Body $out
        return 200
    } catch { Write-JsonResponse -Response $Response -Status 500 -Body @{ error = "settings export failed: $($_.Exception.Message)" }; return 500 }
}

function Get-PimManagerAppImportItems {
    # The import plan with each secret marker put back to the stored value and the state worked out again.
    param([object[]]$Items = @())
    @(@($Items) | Where-Object { $_ } | ForEach-Object {
        $val = Restore-PimManagerAppRedactedValue -Incoming $_.value -Current $_.current
        $diff = @(Get-PimSettingsTransferDiff -Current $_.current -Incoming $val)
        $state = if ($null -eq $_.current) { 'new' } elseif ($diff.Count) { 'changed' } else { 'same' }
        [pscustomobject]@{ section = "$($_.section)"; name = "$($_.name)"; state = $state; changedKeys = $diff; current = $_.current; value = $val }
    })
}

function Invoke-PimManagerAppSettingsImport {
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Response)
    if (-not (Get-Command Get-PimSettingsImportPlan -ErrorAction SilentlyContinue)) { Write-JsonResponse -Response $Response -Status 501 -Body @{ error = 'the settings library is not loaded in this Manager' }; return 501 }
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $Response -Status 403 -Body @{ error = 'An Admin application imports settings.' }; return 403 }
    $script:lastHeartbeat = Get-Date
    $body = $null; try { $body = Read-RequestJson -Request $Request } catch { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'the request is not JSON' }; return 400 }
    $docIn = Get-PimManagerAppBodyProp $body 'document'; if ($null -eq $docIn -and (Get-PimManagerAppBodyProp $body 'format')) { $docIn = $body }
    $preview = ("$($Request.QueryString['preview'])" -in @('1', 'true')) -or ((Get-PimManagerAppBodyProp $body 'dryRun') -eq $true)
    $reader = { param($n) Get-PimManagerSetting -Name $n }
    $plan = Get-PimSettingsImportPlan -Document $docIn -Reader $reader
    if (-not $plan.ok) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "$($plan.error)" }; return 400 }
    $items = @(Get-PimManagerAppImportItems -Items @($plan.items))
    $ro = if ($docIn) { Get-PimManagerAppBodyProp $docIn 'readOnly' } else { $null }
    $ref = Get-PimManagerAppImportRefusal -Items $items -ReadOnlyIncoming $ro -Reader $reader
    $apply = @(Get-PimManagerAppBodyProp $body 'apply' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
    $po = Get-PimManagerAppPersonOnlySettings
    # the direction rule per setting (owner 2026-11-16): a weakening of a tier-1 setting is HELD for a SuperAdmin
    $heldMap = @{}
    foreach ($it in @($items | Where-Object { $_.state -ne 'same' -and -not $po.Contains($_.name) })) {
        $dv = Test-PimManagerAppSettingDirection -Body $it.value -Current $it.current -Entry (Get-PimManagerAppSettingDirectionEntryBySetting -Name $it.name)
        if ($dv.held) { $heldMap[$it.name] = @($dv.reasons) }
    }
    $diffOut = @($items | ForEach-Object { [ordered]@{ section = $_.section; name = $_.name; state = $_.state; changedKeys = @($_.changedKeys); personOnly = [bool]$po.Contains($_.name); held = @($(if ($heldMap.ContainsKey($_.name)) { $heldMap[$_.name] } else { @() }))
        current = (ConvertTo-PimManagerAppRedactedValue -Value $_.current); incoming = (ConvertTo-PimManagerAppRedactedValue -Value $_.value) } })
    if ($preview) {
        Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; preview = $true; items = $diffOut; refused = @($ref.refused)
            note = $(if ($ref.any) { 'The person-only settings listed under refused would make the import fail: leave them as they are.' } else { 'Nothing was written.' }) })
        return 200
    }
    if ($ref.any) {
        Write-PimManagerAuditEvent -Action 'settings.import' -Target 'settings' -After ([ordered]@{ via = 'api-app'; app = (Get-PimManagerAppActor); refused = @($ref.refused | ForEach-Object { $_.name }) }) -Result 'denied'
        Write-JsonResponse -Response $Response -Status 403 -Body ([ordered]@{ ok = $false; error = 'The import changes person-only settings -- an application cannot change them. Nothing was written.'; personOnly = @($ref.refused) })
        return 403
    }
    $heldApply = @($heldMap.Keys | Where-Object { -not $apply.Count -or $_ -in $apply })
    if ($heldApply.Count) {
        Write-PimManagerAuditEvent -Action 'settings.import' -Target 'settings' -After ([ordered]@{ via = 'api-app'; app = (Get-PimManagerAppActor); held = @($heldApply) }) -Result 'held'
        Write-JsonResponse -Response $Response -Status 409 -Body ([ordered]@{ ok = $false; gate = 'weakening-held'; superAdminRequired = $true
            error = 'Held: the import weakens a protection in the settings listed, so a SuperAdmin makes those changes in PIM Manager. Nothing was written.'
            held = @($heldApply | ForEach-Object { [ordered]@{ name = $_; reasons = @($heldMap[$_]) } }) })
        return 409
    }
    $written = New-Object System.Collections.Generic.List[string]; $errors = New-Object System.Collections.Generic.List[string]
    foreach ($it in @($items | Where-Object { $_.state -ne 'same' -and (-not $apply.Count -or $_.name -in $apply) })) {
        try {
            Set-PimManagerSetting -Name $it.name -Value $it.value
            if ($it.name -eq 'NamingConventions' -and $global:PIM_NamingConventions -is [hashtable] -and $it.value) {
                foreach ($p in $it.value.PSObject.Properties) { $global:PIM_NamingConventions[$p.Name] = $p.Value }
            }
            Write-PimManagerAuditEvent -Action 'settings.import' -Target "settings:$($it.name)" -Before @{ value = (ConvertTo-PimManagerAppRedactedValue -Value $it.current) } -After @{ value = (ConvertTo-PimManagerAppRedactedValue -Value $it.value); via = 'api-app'; app = (Get-PimManagerAppActor); source = "$($plan.source)" } -Result 'ok'
            $written.Add($it.name)
        } catch { $errors.Add("$($it.name): $($_.Exception.Message)") }
    }
    $st = if ($errors.Count) { 500 } else { 200 }
    Write-JsonResponse -Response $Response -Status $st -Body ([ordered]@{ ok = (-not $errors.Count); written = $written.ToArray(); errors = $errors.ToArray(); items = $diffOut })
    return $st
}

# ---- SETTINGS-API-1: a tier-1 commit by an Admin application ------------------------------------------------------------
function Invoke-PimManagerAppCommit {
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)]$Spec, [Parameter(Mandatory)]$Response, $Body)
    $actor = Get-PimManagerAppActor
    $t = Get-PimManagerAppEntityTier -Entity $Base
    if ($t.tier -ne 1 -or "$($actor.role)" -cne 'Admin') { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = "An application commits only a tier-1 entity; $Base is not one (propose it through /api/app/approvals/app-submit/$Base)." }; return 403 }
    foreach ($k in @('guardApproval', 'source', 'restoreFrom')) {
        if ($null -ne (Get-PimManagerAppBodyProp $Body $k)) { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = "An application can never approve what a guard stops or claim a restore ('$k'). Nothing was saved." }; return 403 }
    }
    if (-not "$(Get-PimManagerAppBodyProp $Body 'baseRowsHash')".Trim()) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "An application commit carries baseRowsHash (the rowsHash of GET /api/app/csv/$Base). Nothing was saved." }; return 400 }
    $st = Invoke-PimManagerCsvPut -base $Base -spec $Spec -resp $Response -PutBody $Body
    try { Write-PimManagerAuditEvent -Action 'api.app.commit' -Target $Base -Result $(if ([int]$st -ge 200 -and [int]$st -lt 300) { 'ok' } elseif ([int]$st -in @(202, 409)) { 'held' } else { 'denied' }) -After ([ordered]@{ app = $actor; base = $Base; status = [int]$st; committedBy = "app:$($actor.appId)" }) } catch { }
    return [int]$st
}

# ---- PEOPLE-API-APPROVAL-1: an Admin application proposes, a person approves ---------------------------------------------
function Get-PimManagerAppRowKeyOf {
    # the entity's natural key (Get-PimStoreRowKey). Built as text (no GetNewClosure: a closure runs in its own module and
    # would not see the Manager's functions); the name is a known entity name ([\w.-] only), quoted.
    param([Parameter(Mandatory)][string]$Base)
    if ($Base -notmatch '^[\w\.-]+$') { throw "not an entity name: $Base" }
    return [scriptblock]::Create("param(`$r) Get-PimStoreRowKey -Base '$Base' -Row `$r")
}

function Invoke-PimManagerAppSubmit {
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Response)
    $actor = Get-PimManagerAppActor
    if (-not $script:CurrentRequestApp -or "$($actor.role)" -cne 'Admin') { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = 'Only an Admin application proposes a change here.' }; return 403 }
    $t = Get-PimManagerAppEntityTier -Entity $Base
    if ($t.tier -ne 2 -or -not (Get-PimCsvSpec -BaseName $Base)) { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = "$Base cannot be proposed by an application." }; return 403 }
    # owner 2026-11-16 "Queue always on for app proposals": NOT behind the Governance preview Approvals switch (that switch keeps
    # governing people's own requests); a person sees and decides it under /api/app-proposals.
    if (-not (Get-Command Add-PimApprovalRequest -ErrorAction SilentlyContinue)) { Write-JsonResponse -Response $Response -Status 500 -Body @{ error = 'approval-gate library not loaded' }; return 500 }
    $body = $null; try { $body = Read-RequestJson -Request $Request } catch { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'the request is not JSON' }; return 400 }
    # an empty list is a list (a pipeline return would unroll it to nothing): presence is read from the body itself
    $hasRows = [bool](Get-PimManagerAppDictEntries $body | Where-Object { $_.Name -ceq 'rows' })
    $rows = @(Get-PimManagerAppBodyProp $body 'rows')
    $just = "$(Get-PimManagerAppBodyProp $body 'justification')".Trim(); $ticket = "$(Get-PimManagerAppBodyProp $body 'ticket')".Trim()
    $bh = "$(Get-PimManagerAppBodyProp $body 'baseRowsHash')".Trim().ToLowerInvariant()
    if (-not $hasRows) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "send { rows: [the whole set of $Base as it should be], baseRowsHash, justification }" }; return 400 }
    if (-not $just) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'a justification is required -- the approver reads it' }; return 400 }
    if (-not $bh) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "baseRowsHash is required (the rowsHash of GET /api/app/csv/$Base)" }; return 400 }
    $cur = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $Base)
    if ($bh -ne (Get-PimRowsHash -Rows $cur)) { Write-JsonResponse -Response $Response -Status 409 -Body @{ ok = $false; gate = 'concurrency'; error = "$Base changed since it was read -- read it again and propose again. Nothing was proposed." }; return 409 }
    $ch = Get-PimManagerAppRowChanges -Before $cur -After @(@($rows) | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $null -ne $_ }) -KeyOf (Get-PimManagerAppRowKeyOf -Base $Base)
    if (-not $ch.ok) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "$($ch.reason)" }; return 400 }
    if (-not @($ch.changes).Count) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'the rows are the rows already saved -- there is nothing to approve' }; return 400 }
    if (@($ch.changes).Count -gt 200) { Write-JsonResponse -Response $Response -Status 413 -Body @{ ok = $false; error = 'at most 200 changed rows per proposal' }; return 413 }
    $lines = @(Get-PimManagerAppChangeLines -Changes @($ch.changes) -Base $Base)
    $detail = [ordered]@{ kind = 'app-commit'; base = $Base; changes = @($ch.changes); items = $lines; itemCount = $lines.Count; maker = $actor; tier = 2 }
    try {
        $rec = Add-PimApprovalRequest -Requestor "app:$($actor.appId)" -Action 'authoring' -Target ("app-change:{0}:{1}" -f $Base, [guid]::NewGuid().ToString('N').Substring(0, 12)) -Justification $just -Ticket $ticket -Detail $detail
        Write-PimManagerAuditEvent -Action 'api.app.change.submitted' -Target $Base -After ([ordered]@{ id = "$($rec.id)"; maker = $actor; changes = @($ch.changes).Count; items = $lines }) -Result 'ok'
        Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; id = "$($rec.id)"; status = "$($rec.status)"; changes = @($ch.changes).Count
            note = 'Proposed (Pending). Nothing was changed: a person approves it in PIM Manager (Approvals), and it is then saved through the normal commit and its guards.' })
        return 200
    } catch { Write-JsonResponse -Response $Response -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500 }
}

function Test-PimManagerAppChangeRequest {
    # PURE. Is this approval request an application's proposed change (PEOPLE-API-APPROVAL-1)?
    param([AllowNull()][object]$Request)
    if ($null -eq $Request -or $null -eq $Request.detail) { return $false }
    $k = $null; try { $k = $Request.detail.kind } catch { $k = $null }
    return ("$k" -in @('app-commit', 'support-defender-role') -and "$($Request.requestor)" -like 'app:*')
}

function Test-PimManagerAppChangeApprover {
    <#
      PURE. Who may approve / execute an application's proposed change: a signed-in PERSON (never an application), Admin or
      SuperAdmin, never the maker (an application is never its own approver; self-approval never applies here).
      -> @{ allowed; status; reason }.
    #>
    param([AllowNull()][object]$Request, [string]$Identity = '', [string]$Role = '', [bool]$IsApp = $false)
    $no = { param($s, $w) [pscustomobject]@{ allowed = $false; status = $s; reason = $w } }
    if ($IsApp -or "$Identity" -like 'app:*') { return (& $no 403 'An application can never approve or execute a request.') }
    if (-not "$Identity".Trim() -or "$Identity" -eq '<unauthenticated>') { return (& $no 403 'Only a signed-in person approves this.') }
    if ("$Role" -notin @('Admin', 'SuperAdmin')) { return (& $no 403 'An Admin or a SuperAdmin approves a proposed change.') }
    if ($Request -and "$($Request.requestor)".Trim().ToLowerInvariant() -eq "$Identity".Trim().ToLowerInvariant()) { return (& $no 403 'The maker of a request never approves it.') }
    return [pscustomobject]@{ allowed = $true; status = 200; reason = '' }
}

function Invoke-PimManagerAppChangeExecute {
    <#
      Runs an APPROVED application proposal through the normal commit path (Invoke-PimManagerCsvPut) as the signed-in
      person, every guard included (-GuardApproval = that person's own SuperAdmin answer to a guard, as in the page). The stored
      changes are applied to the CURRENT rows; a row changed since the proposal = stale (409), nothing saved. Executed once
      (Set-PimApprovalRequestExecuted). -> @{ status; bodyText }.
    #>
    param([Parameter(Mandatory)][string]$Id, [AllowNull()][object]$GuardApproval)
    $mk = { param($s, $o) [pscustomobject]@{ status = [int]$s; bodyText = (ConvertTo-Json -InputObject $o -Depth 8 -Compress) } }
    $req = @(@(Get-PimApprovalRequests) | Where-Object { "$($_.id)" -eq $Id }) | Select-Object -First 1
    if (-not $req -or -not (Test-PimManagerAppChangeRequest -Request $req)) { return (& $mk 404 @{ ok = $false; error = "no proposed change '$Id'" }) }
    if ("$($req.status)" -ne 'Approved') { return (& $mk 409 @{ ok = $false; error = "the proposed change is $($req.status), not Approved -- nothing was saved" }) }
    if ((Get-Command Test-PimApprovalApprovedFor -ErrorAction SilentlyContinue) -and -not (Test-PimApprovalApprovedFor -Requests @($req) -Action 'authoring' -Target "$($req.target)")) {
        return (& $mk 409 @{ ok = $false; error = 'the approval is too old to be used -- the application proposes again; nothing was saved' })
    }
    $me = Get-PimManagerRole
    $chk = Test-PimManagerAppChangeApprover -Request $req -Identity "$($me.identity)" -Role "$($me.role)" -IsApp ([bool]$script:CurrentRequestApp)
    if (-not $chk.allowed) { return (& $mk $chk.status @{ ok = $false; error = $chk.reason }) }
    if ("$($req.detail.kind)" -eq 'support-defender-role') {
        # an approved Support proposal to create a Defender XDR role: the ENGINE action is queued now (its own identity)
        $qd = Add-PimManagerDefenderRoleCreateAction -Payload $req.detail.payload
        if (-not $qd.ok) { return (& $mk 500 @{ ok = $false; error = "the engine action could not be queued: $($qd.reason)" }) }
        try { [void](Set-PimApprovalRequestExecuted -Id $Id) } catch { }
        try { Write-PimManagerAuditEvent -Action 'api.app.change.executed' -Target 'DefenderXdrRoles' -Result 'ok' -After ([ordered]@{ id = $Id; maker = "$($req.requestor)"; approver = "$($me.identity)"; ticket = "$($req.ticket)"; queueId = "$($qd.id)" }) } catch { }
        return (& $mk 202 @{ ok = $true; queued = $true; queueId = "$($qd.id)"; note = 'approved: the engine creates the role now' })
    }
    $base = "$($req.detail.base)"
    $spec = Get-PimCsvSpec -BaseName $base
    if (-not $spec -or (Get-PimManagerAppEntityTier -Entity $base).tier -ge 3) { return (& $mk 409 @{ ok = $false; error = "$base is not an entity a proposed change applies to" }) }
    $cur = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base)
    $m = Merge-PimManagerAppRowChanges -Current $cur -Changes @($req.detail.changes) -KeyOf (Get-PimManagerAppRowKeyOf -Base $base)
    if (-not $m.ok) { return (& $mk 409 @{ ok = $false; gate = 'stale'; stale = @($m.stale); error = "rows of $base changed since the change was proposed ($(@($m.stale) -join ', ')) -- nothing was saved; the application proposes again" }) }
    # no clientCommitId: a held commit (409) must be retryable; a second apply is stale by construction (Merge-PimManagerAppRowChanges)
    $body = [pscustomobject]@{ rows = @($m.rows); baseRowsHash = (Get-PimRowsHash -Rows $cur)
                               justification = "approved proposal $Id from $($req.requestor): $($req.justification)"; ticket = "$($req.ticket)" }
    if ($null -ne $GuardApproval) { $body | Add-Member -NotePropertyName guardApproval -NotePropertyValue $GuardApproval }
    $cap = New-PimManagerResponseCapture
    $st = 500
    try { $st = Invoke-PimManagerCsvPut -base $base -spec $spec -resp $cap -PutBody $body } catch { Write-JsonResponse -Response $cap -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; $st = 500 }
    $txt = [System.Text.Encoding]::UTF8.GetString($cap.OutputStream.ToArray())
    if ([int]$st -ge 200 -and [int]$st -lt 300 -and [int]$st -ne 202) { try { [void](Set-PimApprovalRequestExecuted -Id $Id) } catch { } }
    try { Write-PimManagerAuditEvent -Action 'api.app.change.executed' -Target $base -Result $(if ([int]$st -eq 200) { 'ok' } elseif ([int]$st -in @(202, 409)) { 'held' } else { 'denied' }) -After ([ordered]@{ id = $Id; maker = "$($req.requestor)"; makerApp = $req.detail.maker; approver = "$($me.identity)"; status = [int]$st }) } catch { }
    return [pscustomobject]@{ status = [int]$st; bodyText = $txt }
}

# ---- SUPPORT-FIX-API-1 + SUPPORT-DIRECT-GRANT-1: the Support role ------------------------------------------------------
function Get-PimManagerSupportLedgerName { 'SupportChangeLedger' }

function Get-PimManagerSupportFixMode {
    # owner 2026-11-16 ("On by default" / "maybe 1 will enforce approve"): pim.Settings SupportFixMode = 'auto' (default) | 'approve'.
    # Person only (tier 3: "who may act without approval"). An unreadable value is 'approve' (fail closed: a person decides).
    try {
        $v = Get-PimManagerSetting -Name 'SupportFixMode'
        if ($null -eq $v) { return 'auto' }
        $s = if ($v -is [string]) { $v } elseif ($v.PSObject.Properties['mode']) { "$($v.mode)" } else { "$v" }
        $s = "$s".Trim().Trim('"').ToLowerInvariant()
        if ($s -in @('', 'auto')) { return 'auto' }
        return 'approve'
    } catch { return 'approve' }
}

function Get-PimManagerSupportLedger {
    $ledger = @()
    try { $lv = Get-PimManagerSetting -Name (Get-PimManagerSupportLedgerName); if ($lv) { $tmp = if ($lv -is [string]) { $lv | ConvertFrom-Json } else { $lv }; $ledger = @($tmp) } } catch { $ledger = @() }
    return @($ledger | Where-Object { $_ })
}

function Add-PimManagerSupportLedgerEntry {
    # The Support role's ledger: the hourly rate (tier-2 rows) and the idempotency keys (ticket + fix), kept 30 days.
    param([object[]]$Ledger = @(), [int]$Rows = 0, [int]$Tier = 2, [string]$Ticket = '', [string]$Base = '', [string]$Key = '')
    $now = [datetime]::UtcNow
    $keep = @(@($Ledger) | Where-Object { $_ -and "$(ConvertTo-PimManagerApiAppUtcText $_.atUtc)" -and ([datetime]::Parse((ConvertTo-PimManagerApiAppUtcText $_.atUtc), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() -gt $now.AddDays(-30)) })
    $keep += [pscustomobject]@{ atUtc = $now.ToString('o'); rows = $Rows; tier = $Tier; ticket = $Ticket; base = $Base; key = $Key }
    try { Set-PimManagerSetting -Name (Get-PimManagerSupportLedgerName) -Value (ConvertTo-Json -InputObject @($keep) -Depth 4 -Compress) } catch { Write-Warning "[support] the ledger was not written: $($_.Exception.Message)" }
}

function Send-PimManagerSupportChangeMail {
    <#
      SUPPORT-DIRECT-GRANT-1 (a): every Support change is mailed to the install's alert recipients -- ONE queued notify request
      ('alert-notice', the engine sends it). A compensating control: no event switch or per-person opt-out applies. Never throws.
      -Waiting: the change is waiting for the install's approval (SupportFixMode = approve).
    #>
    param([string]$Base, [string]$Ticket, [string[]]$Lines = @(), [int]$Count = 0, [string]$Mode = '', [switch]$Waiting)
    try {
        $cfg = Get-PimAlertingConfig
        $rc = @(@($cfg.recipients) | Where-Object { "$_".Trim() })
        if (-not $rc.Count) { return [pscustomobject]@{ queued = $false; recipients = 0; reason = 'no alert recipients are configured (Settings > Alerting) -- the change is in the audit trail' } }
        $tc = try { Get-PimManagerTenantContext } catch { @{ tenantName = '' } }
        $tokens = @{
            AlertTitle = $(if ($Waiting) { "Invardia support asks to change $Base (ticket $Ticket) -- waiting for your approval" } else { "Invardia support changed $Base (ticket $Ticket)" })
            AlertEvent = 'support-change'; AlertDetail = (@($Lines) -join "`n"); AlertTab = $(if ($Waiting) { 'approvals' } else { 'audit' })
            TenantName = "$($tc.tenantName)"; Instance = "$($script:PimInstanceName)"
            AlertHeadline = $(if ($Waiting) { "Invardia support proposed the change asked for on support ticket $Ticket. It is waiting for your approval." } else { "Invardia support made the change asked for on support ticket $Ticket." })
            AlertAction = $(if ($Waiting) { 'Open PIM Manager > Approvals (Proposals from applications) to approve or reject it.' } else { 'Open PIM Manager > Audit to see every row that changed. Reply to the support ticket if this change was not asked for.' })
            WhenUtc = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
            AlertWho = 'Invardia support'; AlertStatus = $(if ($Waiting) { 'Needs customer''s action' } else { 'Changed' })
            AlertProblem = "$Count row(s) of $Base ($Mode) on ticket $Ticket"; AlertTodo = $(if ($Waiting) { 'Approve or reject it.' } else { 'Nothing, if you asked for it.' }); AlertFindings = @()
        }
        $q = Add-PimManagerNotifyRequest -MailType 'alert-notice' -Tokens $tokens -Recipients $rc -Event 'support-change'
        return [pscustomobject]@{ queued = [bool]$q.queued; recipients = $rc.Count; reason = "$($q.reason)"; waiting = [bool]$Waiting }
    } catch { return [pscustomobject]@{ queued = $false; recipients = 0; reason = "$($_.Exception.Message)" } }
}

function New-PimManagerSupportProposal {
    <#
      SupportFixMode = approve: the Support call lands in the approval queue as a proposal (maker = the Support app, the ticket on
      it); an Admin / SuperAdmin person of this install approves (POST /api/app-proposals/decide). Mailed "waiting for approval".
    #>
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][object]$Detail, [Parameter(Mandatory)][string]$Ticket, [string]$Reason = '', [string[]]$Lines = @(), [int]$Count = 0, [string]$Mode = '', [Parameter(Mandatory)]$Response)
    $actor = Get-PimManagerAppActor
    $rec = Add-PimApprovalRequest -Requestor "app:$($actor.appId)" -Action 'authoring' -Target ("support-change:{0}:{1}" -f $Base, [guid]::NewGuid().ToString('N').Substring(0, 12)) -Justification "support ticket $Ticket -- $Reason" -Ticket $Ticket -Detail $Detail
    $mail = Send-PimManagerSupportChangeMail -Base $Base -Ticket $Ticket -Lines $Lines -Count $Count -Mode $Mode -Waiting
    Write-PimManagerAuditEvent -Action 'support.change.queued' -Target $Base -After ([ordered]@{ app = $actor; ticket = $Ticket; id = "$($rec.id)"; mode = $Mode; rows = $Count; items = @($Lines); fixMode = 'approve' }) -Result 'ok'
    Write-JsonResponse -Response $Response -Status 202 -Body ([ordered]@{ ok = $true; queued = $true; id = "$($rec.id)"; ticket = $Ticket; adminMail = $mail
        note = 'queued for your approval (SupportFixMode = approve): an Admin or SuperAdmin of this install approves it in PIM Manager.' })
    return 202
}

function Invoke-PimManagerSupportCommit {
    <#
      The Support role's write: -AfterRows of -Base through the normal commit path (Invoke-PimManagerCsvPut) with the Support app
      ranked Admin for THIS commit only (never SuperAdmin: a guard holds a mass / weakening change for a SuperAdmin). Tier 3 is
      refused; the same ticket + fix again = "already applied" (nothing written); SupportFixMode = approve = a proposal in the
      queue; a tier-2 change counts against the hourly rate limit (over it = held); a saved change is mailed and audited.
    #>
    param([Parameter(Mandatory)][string]$Base, [object[]]$AfterRows = @(), [object[]]$Current = @(), [Parameter(Mandatory)][string]$Ticket, [string]$Reason = '',
          [string]$Mode = 'change', [string]$FixId = '', [string]$IdemKey = '', [Parameter(Mandatory)]$Response)
    $actor = Get-PimManagerAppActor
    $spec = Get-PimCsvSpec -BaseName $Base
    $tier = (Get-PimManagerAppEntityTier -Entity $Base).tier
    if (-not $spec -or $tier -ge 3) { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = "$Base is person only -- support cannot change it." }; return 403 }
    $ledger = @(Get-PimManagerSupportLedger)
    if ($IdemKey -and @($ledger | Where-Object { "$($_.key)" -ceq $IdemKey }).Count) {
        Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; alreadyApplied = $true; ticket = $Ticket; note = 'already applied -- nothing was written' }); return 200
    }
    $ch = Get-PimManagerAppRowChanges -Before $Current -After $AfterRows -KeyOf (Get-PimManagerAppRowKeyOf -Base $Base)
    if (-not $ch.ok) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "$($ch.reason)" }; return 400 }
    $n = @($ch.changes).Count
    if (-not $n) { Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; alreadyApplied = $true; ticket = $Ticket; note = 'already applied -- the rows are already as asked; nothing was written' }); return 200 }
    $lines = @(Get-PimManagerAppChangeLines -Changes @($ch.changes) -Base $Base)
    if ((Get-PimManagerSupportFixMode) -eq 'approve') {
        $detail = [ordered]@{ kind = 'app-commit'; base = $Base; changes = @($ch.changes); items = $lines; itemCount = $lines.Count; maker = $actor; tier = $tier; support = $true; ticket = $Ticket; idemKey = $IdemKey }
        return (New-PimManagerSupportProposal -Base $Base -Detail $detail -Ticket $Ticket -Reason $Reason -Lines $lines -Count $n -Mode $Mode -Response $Response)
    }
    if ($tier -eq 2) {
        $rate = Test-PimManagerAppSupportRate -Ledger $ledger -Rows $n
        if (-not $rate.allowed) {
            Write-PimManagerAuditEvent -Action 'support.change.held' -Target $Base -After ([ordered]@{ app = $actor; ticket = $Ticket; rows = $n; used = $rate.used; limit = $rate.limit }) -Result 'held'
            Write-JsonResponse -Response $Response -Status 409 -Body ([ordered]@{ ok = $false; gate = 'support-rate-limit'; superAdminRequired = $true; used = $rate.used; limit = $rate.limit; rows = $n
                error = "Held: support may change at most $($rate.limit) access rows per hour on this install ($($rate.used) used). A SuperAdmin makes this change in PIM Manager. Nothing was saved." })
            return 409
        }
    }
    $body = [pscustomobject]@{ rows = @($AfterRows); baseRowsHash = (Get-PimRowsHash -Rows $Current); justification = "support ticket $Ticket -- $Reason"; ticket = $Ticket }
    $cap = New-PimManagerResponseCapture
    $st = 500
    $script:CurrentRequestApp.supportCommit = $true
    try { $st = Invoke-PimManagerCsvPut -base $Base -spec $spec -resp $cap -PutBody $body }
    catch { Write-JsonResponse -Response $cap -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; $st = 500 }
    finally { $script:CurrentRequestApp.supportCommit = $false }
    $txt = [System.Text.Encoding]::UTF8.GetString($cap.OutputStream.ToArray())
    $saved = ([int]$st -eq 200)
    $mail = $null
    if ($saved) {
        Add-PimManagerSupportLedgerEntry -Ledger $ledger -Rows $n -Tier $tier -Ticket $Ticket -Base $Base -Key $IdemKey
        $mail = Send-PimManagerSupportChangeMail -Base $Base -Ticket $Ticket -Lines $lines -Count $n -Mode $Mode
    }
    try { Write-PimManagerAuditEvent -Action 'support.change' -Target $Base -Result $(if ($saved) { 'ok' } elseif ([int]$st -in @(202, 409)) { 'held' } else { 'denied' }) -After ([ordered]@{ app = $actor; ticket = $Ticket; reason = $Reason; mode = $Mode; fixId = $FixId; tier = $tier; rows = $n; items = $lines; status = [int]$st; mailQueued = $(if ($mail) { [bool]$mail.queued } else { $false }) }) } catch { }
    $out = $null; try { $out = $txt | ConvertFrom-Json } catch { $out = $null }
    if ($null -eq $out) { $out = [pscustomobject]@{ ok = $saved } }
    $out | Add-Member -NotePropertyName ticket -NotePropertyValue $Ticket -Force
    $out | Add-Member -NotePropertyName supportMode -NotePropertyValue $Mode -Force
    if ($mail) { $out | Add-Member -NotePropertyName adminMail -NotePropertyValue $mail -Force }
    Write-JsonResponse -Response $Response -Status ([int]$st) -Body $out
    return [int]$st
}

function Invoke-PimManagerSupportDefenderRole {
    <#
      owner 2026-11-16 "Support creates them on a ticket": the ONE Support exception to "PIM never creates a Defender role" (the
      engine's own runs never do). The role PIM's DEFINITION lists for a DEFENDER-ROLE-MISSING failure -- exactly its name and its
      permissions (Resolve-PimManagerAppDefenderRoleFix) -- is created by the ENGINE identity through ONE queued engine action
      ('defender-role-create', Invoke-PimQueueDefenderRoleCreate), never with the Support app's token. Counted in the hourly limit
      (1 row), mailed, audited; SupportFixMode = approve = a proposal; the same ticket + failure again = "already applied".
    #>
    param([Parameter(Mandatory)][object]$Spec, [Parameter(Mandatory)][string]$Ticket, [string]$Reason = '', [string]$IdemKey = '', [Parameter(Mandatory)]$Response)
    $actor = Get-PimManagerAppActor
    $ledger = @(Get-PimManagerSupportLedger)
    if ($IdemKey -and @($ledger | Where-Object { "$($_.key)" -ceq $IdemKey }).Count) {
        Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; alreadyApplied = $true; ticket = $Ticket; note = 'already applied -- nothing was written' }); return 200
    }
    $payload = New-PimManagerDefenderRoleCreatePayload -Name "$($Spec.name)" -Actions @($Spec.actions) -Ticket $Ticket -RequestedBy "app:$($actor.appId)"
    $line = "create Defender XDR role '$($Spec.name)' with [$(@($Spec.actions) -join '; ')]"
    if ((Get-PimManagerSupportFixMode) -eq 'approve') {
        $detail = [ordered]@{ kind = 'support-defender-role'; base = 'DefenderXdrRoles'; payload = $payload; items = @($line); itemCount = 1; maker = $actor; tier = 2; support = $true; ticket = $Ticket; idemKey = $IdemKey }
        return (New-PimManagerSupportProposal -Base 'Defender XDR roles' -Detail $detail -Ticket $Ticket -Reason $Reason -Lines @($line) -Count 1 -Mode 'fix create-defender-role' -Response $Response)
    }
    $rate = Test-PimManagerAppSupportRate -Ledger $ledger -Rows 1
    if (-not $rate.allowed) {
        Write-PimManagerAuditEvent -Action 'support.change.held' -Target 'DefenderXdrRoles' -After ([ordered]@{ app = $actor; ticket = $Ticket; rows = 1; used = $rate.used; limit = $rate.limit }) -Result 'held'
        Write-JsonResponse -Response $Response -Status 409 -Body ([ordered]@{ ok = $false; gate = 'support-rate-limit'; superAdminRequired = $true; used = $rate.used; limit = $rate.limit
            error = "Held: support may change at most $($rate.limit) access rows per hour on this install ($($rate.used) used). Nothing was created." })
        return 409
    }
    $q = Add-PimManagerDefenderRoleCreateAction -Payload $payload
    if (-not $q.ok) { Write-JsonResponse -Response $Response -Status 500 -Body @{ ok = $false; error = "the engine action could not be queued: $($q.reason) -- nothing was created" }; return 500 }
    Add-PimManagerSupportLedgerEntry -Ledger $ledger -Rows 1 -Tier 2 -Ticket $Ticket -Base 'DefenderXdrRoles' -Key $IdemKey
    $mail = Send-PimManagerSupportChangeMail -Base 'Defender XDR roles' -Ticket $Ticket -Lines @($line) -Count 1 -Mode 'fix create-defender-role'
    Write-PimManagerAuditEvent -Action 'support.change' -Target 'DefenderXdrRoles' -After ([ordered]@{ app = $actor; ticket = $Ticket; reason = $Reason; mode = 'fix create-defender-role'; fixId = 'create-defender-role'; tier = 2; rows = 1; items = @($line); queueId = "$($q.id)"; mailQueued = [bool]$mail.queued }) -Result 'ok'
    Write-JsonResponse -Response $Response -Status 202 -Body ([ordered]@{ ok = $true; queued = $true; queueId = "$($q.id)"; ticket = $Ticket; role = "$($Spec.name)"; permissions = @($Spec.actions); adminMail = $mail
        note = 'The engine creates the role now (its own identity). If Defender XDR refuses a permission, nothing is created and the refusal is in the queue entry and the audit trail.' })
    return 202
}

function New-PimManagerDefenderRoleCreatePayload {
    # PURE. The engine action's payload: EXACTLY the name and the permissions, the managed-role marker, the ticket.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Actions, [string]$Ticket = '', [string]$RequestedBy = '')
    $marker = if (Get-Command Get-PimDefenderManagedRoleDescription -ErrorAction SilentlyContinue) { Get-PimDefenderManagedRoleDescription } else { 'Managed by PIM4EntraPS: the custom Defender XDR role of the permission group of the same name.' }
    return [ordered]@{ type = 'defender-role-create'; name = "$Name"; actions = @($Actions); description = $marker; ticket = "$Ticket"; requestedBy = "$RequestedBy" }
}

function Add-PimManagerDefenderRoleCreateAction {
    # Queue ONE engine action (pim.ChangeQueue, Kind Action) and start the tick -- the web app writes nothing to Defender itself.
    param([Parameter(Mandatory)][object]$Payload)
    try {
        $by = "$(try { Get-PimManagerActorName } catch { '' })"; if (-not $by.Trim()) { $by = 'Invardia support' }
        $qa = Add-PimManagerCommittedAction -Entity 'PIM-Action-DefenderRoleCreate' -Key ("defender-role-create|{0}" -f "$($Payload.name)".ToLowerInvariant()) -Payload ([pscustomobject]$Payload) -By $by -Justification ("support ticket {0}: create the Defender XDR role '{1}' PIM's definition lists" -f "$($Payload.ticket)", "$($Payload.name)")
        return [pscustomobject]@{ ok = $true; id = "$($qa.id)"; reason = '' }
    } catch { return [pscustomobject]@{ ok = $false; id = ''; reason = "$(("$($_.Exception.Message)" -split "`n")[0])" } }
}

function Invoke-PimManagerSupportRoute {
    <#
      POST /api/support/fix    { failureId | itemKey, fixId, reason }   SUPPORT-FIX-API-1 (12.30): a fix the failure catalog
                                                                       offers for THAT failure (Get-PimManagerAppSupportFixCatalog)
      POST /api/support/change { entity, rows, baseRowsHash, reason }  SUPPORT-DIRECT-GRANT-1: a tier-1 / tier-2 change
      The Support role only (the tag-discovered support app, enrolled by the updater). reason carries SUP-YYYY-NNNNN, else 400.
      SupportFixMode = approve: every call becomes a proposal a person of the install approves.
    #>
    param([Parameter(Mandatory)][ValidateSet('fix', 'change')][string]$Mode, [Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$Response)
    $a = $script:CurrentRequestApp
    if (-not $a -or "$($a.role)" -cne 'Support') { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = 'This route is for the support application only.' }; return 403 }
    $script:lastHeartbeat = Get-Date
    $body = $null; try { $body = Read-RequestJson -Request $Request } catch { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'the request is not JSON' }; return 400 }
    # framework 12.32 T30: a strict schema -- an unknown field is refused, never ignored
    $allowedKeys = @(Get-PimManagerAppSupportBodyKeys -Path ("/api/support/" + $Mode))
    $bodyKeys = @(Get-PimManagerAppDictEntries $body | ForEach-Object { $_.Name })
    if ($null -eq $body -or $body -is [string] -or $body -is [array] -or @($bodyKeys | Where-Object { $_ -cnotin $allowedKeys }).Count) {
        Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "the body may carry only: $($allowedKeys -join ', '). Nothing was changed." }; return 400
    }
    $reason = "$(Get-PimManagerAppBodyProp $body 'reason')".Trim()
    $ticket = Test-PimManagerAppSupportTicket -Reason $reason
    if (-not $ticket) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'reason must carry the support ticket id (SUP-YYYY-NNNNN). Nothing was changed.' }; return 400 }
    if (-not $script:PimSqlCs) { Write-JsonResponse -Response $Response -Status 409 -Body @{ ok = $false; error = 'no SQL store' }; return 409 }
    if ($Mode -eq 'fix') {
        $key = "$(Get-PimManagerAppBodyProp $body 'failureId')".Trim(); if (-not $key) { $key = "$(Get-PimManagerAppBodyProp $body 'itemKey')".Trim() }
        $fixId = "$(Get-PimManagerAppBodyProp $body 'fixId')".Trim()
        $fxCat = @(Get-PimManagerAppSupportFixCatalog | Where-Object { $_.fixId -ceq $fixId })[0]
        if (-not $fxCat) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "'$fixId' is not a fix this route applies (see the support fix catalog). Nothing was changed." }; return 400 }
        if (-not $key) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'failureId (the failure key from GET /api/app/engine-failures) is required' }; return 400 }
        $idem = "fix|$ticket|$key|$fixId"
        if (@(Get-PimManagerSupportLedger | Where-Object { "$($_.key)" -ceq $idem }).Count) {
            Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; alreadyApplied = $true; ticket = $ticket; note = 'already applied -- nothing was written' }); return 200
        }
        $item = @(@(Get-PimEngineItemFailures) | Where-Object { $_ -and "$($_.key)" -ceq $key }) | Select-Object -First 1
        if (-not $item) { Write-JsonResponse -Response $Response -Status 404 -Body @{ ok = $false; error = "no current failure '$key' -- nothing was changed" }; return 404 }
        $base = "$($item.entity)"
        $cur = @(); if ($base) { try { $cur = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base) } catch { $cur = @() } }
        if ("$($fxCat.kind)" -eq 'create-defender-role') {
            $dr = Resolve-PimManagerAppDefenderRoleFix -Item $item -FixId $fixId -Rows $cur
            if (-not $dr.ok) {
                Write-PimManagerAuditEvent -Action 'support.fix' -Target 'DefenderXdrRoles' -After ([ordered]@{ app = (Get-PimManagerAppActor); ticket = $ticket; failure = $key; fixId = $fixId; reason = "$($dr.reason)" }) -Result 'denied'
                Write-JsonResponse -Response $Response -Status ([int]$dr.status) -Body @{ ok = $false; error = "$($dr.reason) -- nothing was created" }; return [int]$dr.status
            }
            return (Invoke-PimManagerSupportDefenderRole -Spec $dr -Ticket $ticket -Reason $reason -IdemKey $idem -Response $Response)
        }
        $offered = @(); if (Get-Command Get-PimFailureCatalogFixes -ErrorAction SilentlyContinue) { $offered = @(Get-PimFailureCatalogFixes -Code "$($item.code)") }
        if (-not (Get-PimCsvSpec -BaseName $base)) { $cur = @() }
        $fx = Resolve-PimManagerAppSupportFix -Item $item -FixId $fixId -CatalogFixes $offered -Rows $cur
        if (-not $fx.ok) {
            Write-PimManagerAuditEvent -Action 'support.fix' -Target "$base" -After ([ordered]@{ app = (Get-PimManagerAppActor); ticket = $ticket; failure = $key; fixId = $fixId; reason = "$($fx.reason)" }) -Result 'denied'
            Write-JsonResponse -Response $Response -Status ([int]$fx.status) -Body @{ ok = $false; error = "$($fx.reason) -- nothing was changed" }
            return [int]$fx.status
        }
        return (Invoke-PimManagerSupportCommit -Base $base -AfterRows @($fx.afterRows) -Current $cur -Ticket $ticket -Reason $reason -Mode "fix $fixId ($($item.code))" -FixId $fixId -IdemKey $idem -Response $Response)
    }
    # /api/support/change
    $base = "$(Get-PimManagerAppBodyProp $body 'entity')".Trim()
    if ($base -and (-not (Get-PimCsvSpec -BaseName $base) -or (Get-PimManagerAppEntityTier -Entity $base).tier -ge 3)) { Write-JsonResponse -Response $Response -Status 403 -Body @{ ok = $false; error = "$base is person only -- support cannot change it." }; return 403 }
    $hasRows = [bool](Get-PimManagerAppDictEntries $body | Where-Object { $_.Name -ceq 'rows' })
    $rows = @(Get-PimManagerAppBodyProp $body 'rows')
    $bh = "$(Get-PimManagerAppBodyProp $body 'baseRowsHash')".Trim().ToLowerInvariant()
    if (-not $base -or -not $hasRows -or -not $bh) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = 'send { entity, rows (the whole set as it should be), baseRowsHash, reason }' }; return 400 }
    $cur = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base)
    $after = @(@($rows) | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $null -ne $_ })
    if ($bh -ne (Get-PimRowsHash -Rows $cur)) {
        # the same change sent again (Invardia's backend retrying a ticket): the rows are already as asked = already applied
        $same = Get-PimManagerAppRowChanges -Before $cur -After $after -KeyOf (Get-PimManagerAppRowKeyOf -Base $base)
        if ($same.ok -and -not @($same.changes).Count) { Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; alreadyApplied = $true; ticket = $ticket; note = 'already applied -- nothing was written' }); return 200 }
        Write-JsonResponse -Response $Response -Status 409 -Body @{ ok = $false; gate = 'concurrency'; error = "$base changed since it was read -- nothing was changed" }; return 409
    }
    return (Invoke-PimManagerSupportCommit -Base $base -AfterRows $after -Current $cur -Ticket $ticket -Reason $reason -Mode 'change' -Response $Response)
}

# ---- PEOPLE-API-APPROVAL-1 "Queue always on for app proposals": the PERSON's view of application proposals --------------
function Get-PimManagerAppProposalView {
    # PURE. One approval request -> the row the page shows ($null when it is not an application's proposal).
    param([AllowNull()][object]$Request)
    if (-not (Test-PimManagerAppChangeRequest -Request $Request)) { return $null }
    $d = $Request.detail
    return [ordered]@{ id = "$($Request.id)"; status = "$($Request.status)"; maker = "$($Request.requestor)"; makerName = "$(if ($d.maker) { $d.maker.name })"; kind = "$($d.kind)"
        base = "$($d.base)"; items = @($d.items); itemCount = [int]$d.itemCount; justification = "$($Request.justification)"; ticket = "$($Request.ticket)"
        requestedUtc = "$($Request.requestedUtc)"; approver = "$($Request.approver)"; decidedUtc = "$($Request.decidedUtc)"; support = [bool]$d.support }
}

function Invoke-PimManagerAppProposalsRoute {
    <#
      GET  /api/app-proposals              the proposals of applications (Reader+ sees them, an Admin / SuperAdmin decides)
      POST /api/app-proposals/decide       { id, decision = approve | deny, note }   a PERSON (never an application, never the maker)
      POST /api/app-proposals/execute      { id, guardApproval? }                    retry an approved one through the commit
      ALWAYS ON, whatever the Governance preview Approvals switch says (owner 2026-11-16 "Queue always on for app proposals");
      that switch keeps governing people's own requests. The decisions run the same checks as POST /api/approvals/decide.
    #>
    param([Parameter(Mandatory)][ValidateSet('list', 'decide', 'execute')][string]$Mode, $Request, [Parameter(Mandatory)]$Response)
    if ($script:CurrentRequestApp) { Write-JsonResponse -Response $Response -Status 403 -Body @{ error = 'An application can never list, approve or execute proposals.' }; return 403 }
    $script:lastHeartbeat = Get-Date
    if (-not (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue)) { Write-JsonResponse -Response $Response -Status 500 -Body @{ error = 'approval-gate library not loaded' }; return 500 }
    if ($Mode -eq 'list') {
        if (-not (Test-PimManagerRoleAtLeast -Minimum 'Reader')) { Write-JsonResponse -Response $Response -Status 403 -Body @{ error = 'A PIM Manager role is required.' }; return 403 }
        $rows = @(@(Get-PimApprovalRequests) | ForEach-Object { Get-PimManagerAppProposalView -Request $_ } | Where-Object { $_ })
        Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; proposals = @($rows); canDecide = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin') })
        return 200
    }
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) { Write-JsonResponse -Response $Response -Status 403 -Body @{ error = 'An Admin or SuperAdmin decides a proposal.' }; return 403 }
    $body = Read-RequestJson -Request $Request
    $id = "$(Get-PimManagerAppBodyProp $body 'id')".Trim()
    $req = @(@(Get-PimApprovalRequests) | Where-Object { "$($_.id)" -eq $id }) | Select-Object -First 1
    if (-not $req -or -not (Test-PimManagerAppChangeRequest -Request $req)) { Write-JsonResponse -Response $Response -Status 404 -Body @{ ok = $false; error = "no proposal '$id'" }; return 404 }
    $me = Get-PimManagerRole
    if ($Mode -eq 'execute') {
        $ga = Get-PimManagerAppBodyProp $body 'guardApproval'
        $ex = Invoke-PimManagerAppChangeExecute -Id $id -GuardApproval $ga
        Copy-PimManagerCapturedResponse -Response $Response -Status ([int]$ex.status) -BodyText "$($ex.bodyText)"
        return [int]$ex.status
    }
    $decision = "$(Get-PimManagerAppBodyProp $body 'decision')".Trim().ToLowerInvariant()
    if ($decision -notin @('approve', 'deny')) { Write-JsonResponse -Response $Response -Status 400 -Body @{ ok = $false; error = "decision must be 'approve' or 'deny'" }; return 400 }
    if ($decision -eq 'approve') {
        $chk = Test-PimManagerAppChangeApprover -Request $req -Identity "$($me.identity)" -Role "$($me.role)" -IsApp ([bool]$script:CurrentRequestApp)
        if (-not $chk.allowed) { Write-JsonResponse -Response $Response -Status ([int]$chk.status) -Body @{ ok = $false; error = "$($chk.reason)" }; return [int]$chk.status }
    }
    $res = Set-PimApprovalDecision -Id $id -Approver "$($me.identity)" -Decision $decision -Note "$(Get-PimManagerAppBodyProp $body 'note')" -AllowSelfApprove $false
    if (-not $res.ok) { Write-JsonResponse -Response $Response -Status 409 -Body @{ ok = $false; status = "$($res.status)"; error = "$($res.reason)" }; return 409 }
    Write-PimManagerAuditEvent -Action ("approval.request." + "$($res.status)".ToLowerInvariant()) -Target "$($req.target)" -After ([ordered]@{ id = $id; approver = "$($me.identity)"; maker = "$($req.requestor)"; action = 'app-change' })
    if ($decision -eq 'deny') { Write-JsonResponse -Response $Response -Status 200 -Body ([ordered]@{ ok = $true; id = $id; status = 'Denied' }); return 200 }
    $ex2 = Invoke-PimManagerAppChangeExecute -Id $id -GuardApproval $null
    $out = $null; try { $out = $ex2.bodyText | ConvertFrom-Json } catch { $out = $null }
    $okx = ([int]$ex2.status -ge 200 -and [int]$ex2.status -lt 300)
    Write-JsonResponse -Response $Response -Status $(if ($okx) { 200 } else { [int]$ex2.status }) -Body ([ordered]@{ ok = $okx; id = $id; status = $(if ($okx) { 'Executed' } else { 'Approved' }); commit = $out
        reason = $(if ($okx) { 'approved and carried out' } else { 'approved, but it was not carried out (see commit) -- answer the guard or retry' }) })
    return $(if ($okx) { 200 } else { [int]$ex2.status })
}
