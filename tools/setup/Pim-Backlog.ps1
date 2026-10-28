#Requires -Version 5.1
<#
    PIM Manager (vendor) -- PIM'S BACKLOG IN INVARDIA'S BACK OFFICE (framework DOCS/REQUIREMENTS.md 12.14 BACKLOG-1; owner
    2026-10-28 via Invardia: "does pim have a backlog that needs similar cleanup as si is doing so docs are upd" -> "lets do
    chapters": push the backlog AS IT IS now, clean it up chapter by chapter after).

    THE CONTRACT -- the same one SI pushes (Invardia packages/core/src/backlog.ts validateBacklogSnapshot), PORTED, not
    shared (isolation beats DRY):
      PUT <base>/api/backlog/pim-manager   Authorization: Bearer <PIM's publisher identity, app role
      Invardia.Publisher.pim-manager>; the WHOLE snapshot (full replace; Invardia keeps every change as history):
        { product: 'pim-manager', updatedUtc, groups: [ { id, title, items: [ { id, title, refs[], stage, tags?,
          missing?, where?, version?, waitingOn?, ownerQuote? } ] } ] }
      stage: not-built | on-branch | merged | ring-1 | ring-2 | ring-3 | proven-live; tags: testing | later | blocked;
      waitingOn: owner | si | pim | invardia | customer. Unknown fields are refused, every text is capped, plain text only.
      Limits: 2,000 items (Invardia 2026-10-28), groups capped at -MaxGroups (default 50, SI's limit).

    THE SOURCE IS PIM'S OWN docs/REQUIREMENTS.md, so the pushed list and the doc never disagree. An ITEM is a line that
    starts (after any "> " quote marks and an optional "- ") with the open mark (U+25FB) or the in-progress mark (U+1F7E1).
    Struck-through lines (~~) are not items. Nothing is guessed beyond what the line says:
      * group = the chapter (## heading) the line sits under; more chapters than -MaxGroups = the smallest are folded into
        one group "Other chapters";
      * id = pim-<the item's own ID token> (ACCESS-MAP-STALE, BUG-207, 100.164 ...), else pim-h<hash of chapter + title>;
        an id used twice gets -2, -3 ... (first one wins the plain id);
      * stage: open mark = not-built; in-progress = ring-2 when the line says ring 2, ring-1 when it says released /
        ring 1 / ring 0/1, merged when it says built in the tree / committed / merged / not released, else on-branch;
      * tags: blocked when it says blocked / awaiting / waits for; later when it says later / parked / deferred;
      * waitingOn: owner when it says the owner decides / approves / an owner decision / awaits the owner;
      * title = its bold lead (the ID label), else the first 120 characters; missing = the line, shortened.
    PURE except Send-PimBacklogSnapshot (its -Transport is the test seam). ASCII code; 5.1 + 7.
#>

$script:PimBacklog = @{
    Product = 'pim-manager'; IdPrefix = 'pim-'; MaxItems = 2000; MaxGroups = 50; MaxRefs = 12
    Stages = @('not-built', 'on-branch', 'merged', 'ring-1', 'ring-2', 'ring-3', 'proven-live'); Tags = @('testing', 'later', 'blocked')
    Waiting = @('owner', 'si', 'pim', 'invardia', 'customer')
    Len = @{ id = 64; title = 200; ref = 60; missing = 1000; where = 300; version = 50; ownerQuote = 500; groupTitle = 120 }
}
$script:PimBacklogMark = @{ Open = [string][char]0x25FB; Yellow = [char]::ConvertFromUtf32(0x1F7E1) }
$script:PimBacklogItemRx = '^\s*(?:>\s*)*(?:-\s+)?(' + [regex]::Escape($script:PimBacklogMark.Open) + '|' + [regex]::Escape($script:PimBacklogMark.Yellow) + ')'

function ConvertTo-PimBacklogText {
    <# PURE. Markdown to plain text on one line: no ** / backticks / ~~ / control characters, links to their text, capped. #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [int]$Max = 0)
    $t = "$Text" -replace '\[([^\]]*)\]\([^)]*\)', '$1' -replace '\*\*', '' -replace '`', '' -replace '~~', '' -replace '\\\|', '|'
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $t.ToCharArray()) { $n = [int]$ch; if ($n -lt 32 -or ($n -ge 127 -and $n -lt 160) -or $n -eq 0x2028 -or $n -eq 0x2029) { [void]$sb.Append(' ') } else { [void]$sb.Append($ch) } }
    $t = ($sb.ToString() -replace '\s+', ' ').Trim()
    $t = [regex]::Replace($t, '[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', '')
    if ($Max -gt 0 -and $t.Length -gt $Max) {
        $cut = $Max - 3
        if ($cut -gt 0 -and [char]::IsHighSurrogate($t[$cut - 1])) { $cut-- }
        $t = $t.Substring(0, $cut).TrimEnd() + '...'
    }
    $t
}

function Get-PimBacklogShortHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Text")) } finally { $sha.Dispose() }
    (($b | Select-Object -First 5) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function ConvertFrom-PimBacklogLine {
    <# PURE. One REQUIREMENTS line -> a backlog item (ordered dictionary), or $null when it is not an open / in-progress item. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Line, [string]$Chapter = '')
    if ($Line -match '^\s*(?:>\s*)*(?:-\s+)?~~') { return $null }
    $m = [regex]::Match($Line, $script:PimBacklogItemRx)
    if (-not $m.Success) { return $null }
    $mark = $m.Groups[1].Value
    $rest = $Line.Substring($m.Index + $m.Length)
    # the severity / extra marks right after the status mark are not text
    $rest = [regex]::Replace($rest, '^[\s\p{So}\p{Cs}\uFE0F]+', '')
    $plain = ConvertTo-PimBacklogText $rest
    if (-not $plain) { return $null }
    # title: the first bold lead; the ID: its first token that looks like an id
    $bm = [regex]::Match($rest, '\*\*(.+?)\*\*')
    $lead = if ($bm.Success) { ConvertTo-PimBacklogText $bm.Groups[1].Value } else { '' }
    $idTok = ''
    $im = [regex]::Match($lead, '^(?:\u00A7\s*)?([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+|\d{1,3}(?:\.\d{1,3}[a-z]?)+|[A-Z]{2,}-?\d+[a-z]?)\b')
    if ($im.Success) { $idTok = $im.Groups[1].Value }
    $title = if ($lead) { $lead } else { $plain }
    $title = ConvertTo-PimBacklogText $title $script:PimBacklog.Len.title
    if ($title.Length -gt 120 -and -not $lead) { $title = ConvertTo-PimBacklogText $plain 120 }
    # stage
    $stage = 'not-built'
    if ($mark -eq $script:PimBacklogMark.Yellow) {
        # "not released" names a merged item -- it is taken out before "released" is looked for
        $rel = $plain -replace '(?i)\bnot (yet )?released\b', ''
        if ($plain -match '(?i)\bring[ -]?2\b') { $stage = 'ring-2' }
        elseif ($rel -match '(?i)\breleased\b|\bring[ -]?1\b|\bring[ -]?0/1\b|\bring 0\b') { $stage = 'ring-1' }
        elseif ($plain -match '(?i)built in the tree|\bcommitted\b|\bmerged\b|not (yet )?released') { $stage = 'merged' }
        else { $stage = 'on-branch' }
    }
    $tags = New-Object System.Collections.Generic.List[string]
    if ($plain -match '(?i)\bblocked\b|\bawait(s|ing)?\b|\bwaits? (for|on)\b') { $tags.Add('blocked') }
    if ($plain -match '(?i)\blater\b|\bparked\b|\bdeferred\b') { $tags.Add('later') }
    # refs
    $refs = New-Object System.Collections.Generic.List[string]
    $chapNo = [regex]::Match("$Chapter", '^\s*(\d{1,3}(?:\.\d+)?)\.?\s')
    if ($chapNo.Success) { $refs.Add(('chapter {0}' -f $chapNo.Groups[1].Value)) }
    $om = [regex]::Match($plain, '(?i)\b(owner|operator)[^\d]{0,12}(20\d\d-\d\d-\d\d)')
    if ($om.Success) { $refs.Add(('{0} {1}' -f $om.Groups[1].Value.ToLowerInvariant(), $om.Groups[2].Value)) }
    foreach ($x in [regex]::Matches($plain, '\bSUP-20\d\d-\d{3,6}\b|\b(?:BUG|SEC|IMP|DOC|TEST)-\d+\b')) {
        if ($refs.Count -ge $script:PimBacklog.MaxRefs) { break }
        if (-not $refs.Contains($x.Value)) { $refs.Add($x.Value) }
    }
    $item = [ordered]@{ id = ''; title = $title; refs = $refs.ToArray(); stage = $stage }
    if ($tags.Count) { $item.tags = $tags.ToArray() }
    $item.missing = ConvertTo-PimBacklogText $plain 600
    $vm = [regex]::Match($plain, '\b2\.4\.\d{2,4}\b|\b3\.\d+\.\d+\b')
    if ($stage -ne 'not-built' -and $vm.Success) { $item.version = $vm.Value }
    if ($plain -match "(?i)owner (decides|decision|approves|approval|to decide|'s (ok|decision|approval|words))|awaits? the owner|needs? (an? )?(owner )?decision|ask(ed)? (the )?owner") { $item.waitingOn = 'owner' }
    $qm = [regex]::Match($rest, '\*"([^"]{2,600})"\*')
    if ($qm.Success) { $q = ConvertTo-PimBacklogText $qm.Groups[1].Value $script:PimBacklog.Len.ownerQuote; if ($q) { $item.ownerQuote = $q } }
    [pscustomobject]@{ IdToken = $idTok; Chapter = "$Chapter"; Item = $item }
}

function ConvertTo-PimBacklogId {
    <# PURE. pim-<token> made id-safe (A-Za-z0-9._:-, at most 64), else ''. #>
    param([string]$Token)
    $t = ("$Token" -replace '[^A-Za-z0-9._:-]', '-').Trim('-', '.', ':')
    if (-not $t) { return '' }
    $id = $script:PimBacklog.IdPrefix + $t
    if ($id.Length -gt 60) { $id = $id.Substring(0, 60).TrimEnd('-', '.', ':') }
    $id
}

function New-PimBacklogSnapshot {
    <#
        PURE. The snapshot from -RequirementsText. Returns @{ Snapshot; Items; Dropped; Counts; TagCounts; Groups; Folded;
        Warnings }. Dropped = items over -MaxItems (the last ones in the doc); Folded = chapters folded into "Other chapters".
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RequirementsText, $NowUtc, [int]$MaxGroups = 0, [int]$MaxItems = 0)
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    if ($MaxGroups -le 0) { $MaxGroups = $script:PimBacklog.MaxGroups }
    if ($MaxItems -le 0) { $MaxItems = $script:PimBacklog.MaxItems }
    $warn = New-Object System.Collections.Generic.List[string]
    $chapter = '(before the first chapter)'
    $rows = New-Object System.Collections.Generic.List[object]
    $inFence = $false
    $n = 0
    foreach ($line in ($RequirementsText -split "`r?`n")) {
        $n++
        if ($line -match '^\s*```') { $inFence = -not $inFence; continue }
        if ($inFence) { continue }
        if ($line -match '^##\s+(?!#)(.+)$') { $chapter = ConvertTo-PimBacklogText $Matches[1]; continue }
        $r = ConvertFrom-PimBacklogLine -Line $line -Chapter $chapter
        if ($r) { $r | Add-Member -NotePropertyName LineNo -NotePropertyValue $n; $rows.Add($r) }
    }
    $dropped = [Math]::Max(0, $rows.Count - $MaxItems)
    $kept = @($rows | Select-Object -First $MaxItems)
    # ids: the item's own token, else a hash; a repeat gets -2, -3 ...
    $used = @{}
    foreach ($r in $kept) {
        $base = ConvertTo-PimBacklogId $r.IdToken
        if (-not $base) { $base = $script:PimBacklog.IdPrefix + 'h' + (Get-PimBacklogShortHash ($r.Chapter + '|' + $r.Item.title)) }
        $id = $base; $k = 1
        while ($used.ContainsKey($id.ToLowerInvariant())) { $k++; $id = '{0}-{1}' -f $base, $k }
        $used[$id.ToLowerInvariant()] = $true
        $r.Item.id = $id
    }
    # groups = chapters in document order; more than MaxGroups -> the smallest folded into one "Other chapters" group
    $byChap = [ordered]@{}
    foreach ($r in $kept) { if (-not $byChap.Contains($r.Chapter)) { $byChap[$r.Chapter] = New-Object System.Collections.Generic.List[object] }; $byChap[$r.Chapter].Add($r) }
    $chaps = @($byChap.Keys)
    $fold = @{}
    if ($chaps.Count -gt $MaxGroups) {
        $keep = @($chaps | Sort-Object -Property @{ Expression = { $byChap[$_].Count }; Descending = $true } | Select-Object -First ($MaxGroups - 1))
        foreach ($c in $chaps) { if ($c -notin $keep) { $fold[$c] = $true } }
    }
    $groups = New-Object System.Collections.Generic.List[object]
    $gids = @{}
    $other = New-Object System.Collections.Generic.List[object]
    foreach ($c in $chaps) {
        if ($fold.ContainsKey($c)) { foreach ($r in $byChap[$c]) { $other.Add($r.Item) }; continue }
        $cn = [regex]::Match($c, '^\s*(\d{1,3}(?:\.\d+)?)\.?\s')
        $gid = if ($cn.Success) { 'ch-' + ($cn.Groups[1].Value -replace '\.', '-') } else { 'ch-h' + (Get-PimBacklogShortHash $c) }
        $g0 = $gid; $k = 1; while ($gids.ContainsKey($gid)) { $k++; $gid = '{0}-{1}' -f $g0, $k }; $gids[$gid] = $true
        $groups.Add([ordered]@{ id = $gid; title = (ConvertTo-PimBacklogText $c $script:PimBacklog.Len.groupTitle); items = @($byChap[$c] | ForEach-Object { $_.Item }) })
    }
    if ($other.Count) { $groups.Add([ordered]@{ id = 'ch-other'; title = ('Other chapters ({0})' -f $fold.Count); items = $other.ToArray() }) }
    $counts = [ordered]@{}; foreach ($s in $script:PimBacklog.Stages) { $counts[$s] = @($kept | Where-Object { $_.Item.stage -eq $s }).Count }
    $tagCounts = [ordered]@{}; foreach ($t in $script:PimBacklog.Tags) { $tagCounts[$t] = @($kept | Where-Object { $_.Item.Contains('tags') -and ($_.Item.tags -contains $t) }).Count }
    $tagCounts['waitingOn-owner'] = @($kept | Where-Object { $_.Item.Contains('waitingOn') -and $_.Item.waitingOn -eq 'owner' }).Count
    if ($dropped) { $warn.Add("$dropped item(s) over the $MaxItems-item limit left out (the last ones in the doc)") }
    if ($fold.Count) { $warn.Add("$($fold.Count) small chapter(s) folded into 'Other chapters' (more than $MaxGroups chapters)") }
    $hashIds = @($kept | Where-Object { $_.Item.id -match ('^' + [regex]::Escape($script:PimBacklog.IdPrefix) + 'h[0-9a-f]{10}') }).Count
    $snap = [ordered]@{ product = $script:PimBacklog.Product; updatedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); groups = $groups.ToArray() }
    [pscustomobject]@{ Snapshot = $snap; Items = $kept.Count; Dropped = $dropped; Counts = $counts; TagCounts = $tagCounts; Groups = $groups.Count
                       Folded = $fold.Count; HashIds = $hashIds; Warnings = $warn.ToArray() }
}

function Test-PimBacklogSnapshot {
    <# PURE. The problems Invardia's validateBacklogSnapshot would refuse the snapshot for ([] = fit to push). Ported from SI. #>
    param([Parameter(Mandatory)]$Snapshot, [int]$MaxGroups = 0, [int]$MaxItems = 0)
    $p = New-Object System.Collections.Generic.List[string]
    $c = $script:PimBacklog
    if ($MaxGroups -le 0) { $MaxGroups = $c.MaxGroups }
    if ($MaxItems -le 0) { $MaxItems = $c.MaxItems }
    $keys = { param($o) if ($o -is [System.Collections.IDictionary]) { @($o.Keys) } else { @($o.PSObject.Properties.Name) } }
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $bad = { param([string]$s, [bool]$multi) foreach ($ch in $s.ToCharArray()) { $n = [int]$ch; if ($n -eq 10 -and $multi) { continue }; if ($n -lt 32 -or ($n -ge 127 -and $n -lt 160) -or $n -eq 0x2028 -or $n -eq 0x2029) { return $true } }; return $false }
    $text = {
        param($v, [string]$at, [int]$max, [bool]$required, [bool]$multi = $false)
        if ($null -eq $v) { if ($required) { $p.Add("${at}: required") }; return }
        if ($v -isnot [string]) { $p.Add("${at}: must be a string"); return }
        $s = $v.Trim()
        if (-not $s) { if ($required) { $p.Add("${at}: required") }; return }
        if ($s.Length -gt $max) { $p.Add("${at}: longer than $max characters") }
        if (& $bad $s $multi) { $p.Add("${at}: control characters are not allowed (plain text only)") }
    }
    foreach ($k in (& $keys $Snapshot)) { if ($k -notin @('product', 'updatedUtc', 'criticalPath', 'groups')) { $p.Add("${k}: unknown field") } }
    if ((& $get $Snapshot 'product') -ne $c.Product) { $p.Add("product: must be `"$($c.Product)`"") }
    $u = "$(& $get $Snapshot 'updatedUtc')"
    $d = [datetime]::MinValue
    if (-not $u.Contains('T') -or -not [datetime]::TryParse($u, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { $p.Add('updatedUtc: required, an ISO 8601 date-time') }
    $groups = @(& $get $Snapshot 'groups')
    if ($groups.Count -gt $MaxGroups) { $p.Add("groups: more than $MaxGroups groups") }
    $total = 0; foreach ($g in $groups) { $total += @(& $get $g 'items').Count }
    if ($total -gt $MaxItems) { $p.Add("groups: more than $MaxItems items in all ($total)") }
    $gids = @{}; $iids = @{}
    $gi = 0
    foreach ($g in $groups) {
        $at = "groups[$gi]"
        foreach ($k in (& $keys $g)) { if ($k -notin @('id', 'title', 'items')) { $p.Add("$at.${k}: unknown field") } }
        $id = "$(& $get $g 'id')"
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$') { $p.Add("$at.id: not an id") } elseif ($gids.ContainsKey($id)) { $p.Add("$at.id: `"$id`" is used twice") } else { $gids[$id] = $true }
        & $text (& $get $g 'title') "$at.title" $c.Len.groupTitle $true
        $ii = 0
        foreach ($it in @(& $get $g 'items')) {
            $iat = "$at.items[$ii]"
            foreach ($k in (& $keys $it)) { if ($k -notin @('id', 'title', 'refs', 'stage', 'tags', 'missing', 'where', 'version', 'waitingOn', 'ownerQuote')) { $p.Add("$iat.${k}: unknown field") } }
            $iid = "$(& $get $it 'id')"
            if ($iid -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$') { $p.Add("$iat.id: not an id") } elseif ($iids.ContainsKey($iid)) { $p.Add("$iat.id: `"$iid`" is used twice") } else { $iids[$iid] = $true }
            & $text (& $get $it 'title') "$iat.title" $c.Len.title $true
            $refs = @(& $get $it 'refs')
            if ($refs.Count -gt $c.MaxRefs) { $p.Add("$iat.refs: more than $($c.MaxRefs) entries") }
            $ri = 0; foreach ($r in $refs) { & $text $r "$iat.refs[$ri]" $c.Len.ref $true; $ri++ }
            if ("$(& $get $it 'stage')" -notin $c.Stages) { $p.Add("$iat.stage: must be one of $($c.Stages -join ', ')") }
            foreach ($t in @(& $get $it 'tags')) { if ($null -ne $t -and "$t" -notin $c.Tags) { $p.Add("$iat.tags: must be one of $($c.Tags -join ', ')") } }
            & $text (& $get $it 'missing') "$iat.missing" $c.Len.missing $false $true
            & $text (& $get $it 'where') "$iat.where" $c.Len.where $false
            & $text (& $get $it 'version') "$iat.version" $c.Len.version $false
            & $text (& $get $it 'ownerQuote') "$iat.ownerQuote" $c.Len.ownerQuote $false $true
            $w = & $get $it 'waitingOn'; if ($null -ne $w -and "$w" -notin $c.Waiting) { $p.Add("$iat.waitingOn: must be one of $($c.Waiting -join ', ')") }
            $ii++
        }
        $gi++
    }
    $p.ToArray()
}

function Send-PimBacklogSnapshot {
    <#
        PUT <base>/api/backlog/pim-manager[?confirmRemovals=1] with the publisher's -Token. Returns @{ Ok; Status; Text;
        Answer }. Never throws. -Transport { param($Method, $Uri, $Headers, $Body) } -> @{ Status; Body } (test seam).
    #>
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$Token, [string]$BaseUrl = 'https://invardia.com', [switch]$ConfirmRemovals,
          [scriptblock]$Transport, [int]$TimeoutSec = 120)
    $out = { param($ok, $st, $txt, $ans) [pscustomobject]@{ Ok = [bool]$ok; Status = [int]$st; Text = $txt; Answer = $ans } }
    try {
        $base = "$BaseUrl".Trim().TrimEnd('/')
        if ($base -notmatch '^https://[^/\s]+') { return (& $out $false 0 ("the Invardia address must be https, not '{0}'" -f $base) $null) }
        if (-not $Transport) {
            $to = $TimeoutSec
            $Transport = {
                param($m, $u, $h, $b)
                try {
                    $r = Invoke-WebRequest -Method $m -Uri $u -Headers $h -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($b)) -UseBasicParsing -TimeoutSec $to -ErrorAction Stop
                    $c = $r.Content; if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
                    [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$c }
                } catch {
                    $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                    $eb = ''; if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $eb = [string]$_.ErrorDetails.Message }
                    [pscustomobject]@{ Status = $code; Body = $eb }
                }
            }.GetNewClosure()
        }
        $body = $Snapshot | ConvertTo-Json -Depth 8 -Compress
        $uri = '{0}/api/backlog/{1}' -f $base, $script:PimBacklog.Product
        if ($ConfirmRemovals) { $uri += '?confirmRemovals=1' }
        $r = & $Transport 'PUT' $uri @{ Authorization = "Bearer $Token"; Accept = 'application/json' } $body
        $code = [int]$r.Status
        $ans = $null; try { if ("$($r.Body)".Trim()) { $ans = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } } catch { }
        switch ($code) {
            { $_ -ge 200 -and $_ -lt 300 } {
                $txt = 'the backlog was pushed to Invardia'
                if ($ans -and $ans.PSObject.Properties['added']) { $txt += (": {0} added, {1} stage changes, {2} updated, {3} restored, {4} removed, {5} unchanged" -f $ans.added, $ans.stageChanges, $ans.updated, $ans.restored, $ans.removed, $ans.unchanged) }
                return (& $out $true $code $txt $ans)
            }
            401 { return (& $out $false $code 'Invardia refused the sign-in (401)' $ans) }
            403 { return (& $out $false $code 'the publisher has no Invardia.Publisher.pim-manager role (403)' $ans) }
            409 { return (& $out $false $code ("Invardia refused: the push would remove too many open items (409) -- re-run with -ConfirmRemovals if that is meant. {0}" -f "$($r.Body)") $ans) }
            422 { $pr = if ($ans -and $ans.PSObject.Properties['problems']) { (@($ans.problems) | Select-Object -First 10) -join '; ' } else { '' }; return (& $out $false $code ("Invardia refused the backlog (422): {0}" -f $pr) $ans) }
            0 { return (& $out $false 0 'Invardia could not be reached' $null) }
            default { return (& $out $false $code ("Invardia answered {0}: {1}" -f $code, "$($r.Body)") $ans) }
        }
    } catch { & $out $false 0 ("the backlog was not pushed: {0}" -f $_.Exception.Message) $null }
}
