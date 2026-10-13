#Requires -Version 5.1
<#
  _listmenu.ps1 -- PIM 100.120 (owner 2026-10-13): the SAVED LAYOUTS of the list menu that sits on every list view of
  PIM Manager. Dot-sourced by Open-PimManager.ps1; one route block there hands every /api/list-layouts request to
  Invoke-PimManagerListLayoutRequest below.

  A layout = which columns show, their order, the sort, the filters (with "does not contain"), the search text and the
  page size of ONE list view. It never holds a page number or a selection, and it never changes data: a layout only
  decides what a person SEES in that list.

  WHO SAVES WHAT (owner decision (5), 2026-10-13: "personal + shared"):
    * personal -- every signed-in person saves their own layouts; they are stored per identity and nobody else reads them;
    * shared ("for everyone") -- ONLY a SuperAdmin saves, changes or deletes one and marks one the default of a view.
      The check is HERE, on the server: an Admin's write is refused with 403 and the reason.

  WHERE: the SQL store, pim.Settings, through the Manager's normal settings write path (Set-PimManagerSettingObject):
    * 'ListLayoutsShared'               { v, views: { <view>: { default, layouts: [ { id, name, layout, by, atUtc } ] } } }
    * 'ListLayoutsUser.<hash of who>'   { v, identity, views: { <view>: { layouts: [ { id, name, layout, atUtc } ] } } }
  No file, no browser storage for a NAMED layout. (The page keeps a person's LAST set-up of each list in the browser.)

  Everything except Invoke-PimManagerListLayoutRequest is PURE over two script blocks (-ReadSetting { param($name) },
  -WriteSetting { param($name, $value) }), so tests\Test-PimListMenu.ps1 runs the real code with a store in memory.
  Literals come from functions: a $script: variable is $null in a child scope behind a load guard.
#>

function Get-PimListLayoutSharedSettingName { 'ListLayoutsShared' }
function Get-PimListLayoutUserSettingPrefix { 'ListLayoutsUser.' }
function Get-PimListLayoutLimits {
    # One place for every limit; the page shows the same numbers (GET /api/list-layouts -> limits).
    @{ nameMax = 80; perView = 30; views = 200; columns = 200; columnKeyMax = 120; filters = 20; values = 50; textMax = 200; layoutBytes = 16384 }
}
function Get-PimListLayoutOperators { @('contains', 'notContains', 'equals', 'startsWith', 'anyOf') }
function Get-PimListLayoutPageSizes { @(0, 25, 50, 100, 200) }

function Get-PimListLayoutUserSettingName {
    # PURE. The setting that holds ONE person's layouts. The name carries a hash, never the address itself; the
    # identity is stored INSIDE the value and checked on every read (Get-PimListLayoutDoc), so a hash collision can
    # never hand one person another person's layouts.
    param([string]$Identity)
    $who = "$Identity".Trim().ToLowerInvariant()
    if (-not $who) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($who)) } finally { $sha.Dispose() }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return (Get-PimListLayoutUserSettingPrefix) + $hex.Substring(0, 32)
}

function Test-PimListLayoutViewKey {
    # PURE. A view key as the page builds it: "<page>:<list>", lower case, e.g. "accounts:acct-grid".
    param([object]$View)
    if (-not ($View -is [string])) { return $false }
    return [bool]($View -cmatch '^[a-z0-9][a-z0-9:._-]{0,99}$')
}

function Get-PimListLayoutProp {
    # PURE. One property of a parsed JSON object or a hashtable; $null when it is not there.
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return , $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return , $p.Value }
    return $null
}
function Get-PimListLayoutPropNames {
    param([object]$Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { "$_" }) }
    return @($Object.PSObject.Properties | ForEach-Object { "$($_.Name)" })
}
function Test-PimListLayoutIsList {
    param([object]$Value)
    return [bool]($null -ne $Value -and -not ($Value -is [string]) -and -not ($Value -is [System.Collections.IDictionary]) -and ($Value -is [System.Collections.IEnumerable]))
}
function Test-PimListLayoutText {
    # PURE. A plain text value: a string, no control characters, at most $Max long. Empty allowed only with -AllowEmpty.
    param([object]$Value, [int]$Max, [switch]$AllowEmpty)
    if (-not ($Value -is [string])) { return $false }
    if ($Value.Length -gt $Max) { return $false }
    if (-not $AllowEmpty -and -not $Value.Trim()) { return $false }
    if ($Value -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') { return $false }
    return $true
}

function ConvertTo-PimListLayout {
    <#
      PURE. Checks one layout as the page sends it and returns the CLEAN copy that is stored -- built field by field, so
      nothing the check did not look at is ever written. A layout that is not exactly this shape is REFUSED (never
      repaired): @{ ok = $false; error = '<what is wrong>' }.
        { v: 1, columns: [key..], hidden: [key..], sort: null | { col, dir: 1 | -1 }, search: '',
          filters: [ { col, op: contains | notContains | equals | startsWith, value } | { col, op: anyOf, values: [..] } ],
          pageSize: 0 | 25 | 50 | 100 | 200 }
      col = a column key, or '*' in a filter = every column of the row.
    #>
    param([object]$Layout)
    $lim = Get-PimListLayoutLimits
    $bad = { param($m) return @{ ok = $false; error = "$m"; layout = $null } }
    if ($null -eq $Layout -or ($Layout -is [string]) -or ($Layout -is [ValueType]) -or (Test-PimListLayoutIsList -Value $Layout)) { return (& $bad 'layout must be an object') }
    $known = @('v', 'columns', 'hidden', 'sort', 'search', 'filters', 'pageSize')
    foreach ($n in @(Get-PimListLayoutPropNames -Object $Layout)) { if ($known -cnotcontains $n) { return (& $bad "layout has a field that is not part of a layout: $n") } }
    $v = Get-PimListLayoutProp -Object $Layout -Name 'v'
    if ("$v" -ne '1') { return (& $bad 'layout.v must be 1') }

    $lists = @{}
    foreach ($n in @('columns', 'hidden')) {
        $raw = Get-PimListLayoutProp -Object $Layout -Name $n
        $out = New-Object System.Collections.Generic.List[string]
        if ($null -ne $raw) {
            if (-not (Test-PimListLayoutIsList -Value $raw)) { return (& $bad "layout.$n must be a list of column keys") }
            foreach ($c in @($raw)) {
                if (-not (Test-PimListLayoutText -Value $c -Max $lim.columnKeyMax)) { return (& $bad "layout.$n holds a value that is not a column key") }
                if ($out.Contains($c)) { return (& $bad "layout.$n names the column '$c' twice") }
                $out.Add($c)
            }
            if ($out.Count -gt $lim.columns) { return (& $bad "layout.$n holds more than $($lim.columns) columns") }
        }
        $lists[$n] = $out
    }

    $sortOut = $null
    $sort = Get-PimListLayoutProp -Object $Layout -Name 'sort'
    if ($null -ne $sort) {
        if (($sort -is [string]) -or ($sort -is [ValueType]) -or (Test-PimListLayoutIsList -Value $sort)) { return (& $bad 'layout.sort must be null or { col, dir }') }
        foreach ($n in @(Get-PimListLayoutPropNames -Object $sort)) { if (@('col', 'dir') -cnotcontains $n) { return (& $bad "layout.sort has a field that is not part of a sort: $n") } }
        $sc = Get-PimListLayoutProp -Object $sort -Name 'col'
        $sd = Get-PimListLayoutProp -Object $sort -Name 'dir'
        if (-not (Test-PimListLayoutText -Value $sc -Max $lim.columnKeyMax)) { return (& $bad 'layout.sort.col must be a column key') }
        if (($sd -is [string]) -or ($sd -is [bool]) -or @('1', '-1') -notcontains "$sd") { return (& $bad 'layout.sort.dir must be 1 or -1') }
        $sortOut = [ordered]@{ col = $sc; dir = [int]"$sd" }
    }

    $search = Get-PimListLayoutProp -Object $Layout -Name 'search'
    if ($null -eq $search) { $search = '' }
    if (-not (Test-PimListLayoutText -Value $search -Max $lim.textMax -AllowEmpty)) { return (& $bad "layout.search must be text of at most $($lim.textMax) characters") }

    $filtersOut = New-Object System.Collections.Generic.List[object]
    $filters = Get-PimListLayoutProp -Object $Layout -Name 'filters'
    if ($null -ne $filters) {
        if (-not (Test-PimListLayoutIsList -Value $filters)) { return (& $bad 'layout.filters must be a list') }
        $ops = @(Get-PimListLayoutOperators)
        foreach ($f in @($filters)) {
            if ($null -eq $f -or ($f -is [string]) -or ($f -is [ValueType]) -or (Test-PimListLayoutIsList -Value $f)) { return (& $bad 'a filter must be an object { col, op, value }') }
            foreach ($n in @(Get-PimListLayoutPropNames -Object $f)) { if (@('col', 'op', 'value', 'values') -cnotcontains $n) { return (& $bad "a filter has a field that is not part of a filter: $n") } }
            $fc = Get-PimListLayoutProp -Object $f -Name 'col'
            $fo = Get-PimListLayoutProp -Object $f -Name 'op'
            if (-not (Test-PimListLayoutText -Value $fc -Max $lim.columnKeyMax)) { return (& $bad 'a filter names no column') }
            if (-not ($fo -is [string]) -or $ops -cnotcontains $fo) { return (& $bad "a filter's op must be one of: $($ops -join ', ')") }
            if ($fo -ceq 'anyOf') {
                $vals = Get-PimListLayoutProp -Object $f -Name 'values'
                if (-not (Test-PimListLayoutIsList -Value $vals)) { return (& $bad 'an "any of" filter needs values: a list of texts') }
                $vo = New-Object System.Collections.Generic.List[string]
                foreach ($x in @($vals)) {
                    if (-not (Test-PimListLayoutText -Value $x -Max $lim.textMax -AllowEmpty)) { return (& $bad 'an "any of" filter holds a value that is not text') }
                    if (-not $vo.Contains($x)) { $vo.Add($x) }
                }
                if ($vo.Count -lt 1 -or $vo.Count -gt $lim.values) { return (& $bad "an ""any of"" filter holds 1 to $($lim.values) values") }
                if ($null -ne (Get-PimListLayoutProp -Object $f -Name 'value')) { return (& $bad 'an "any of" filter has values, not a value') }
                $filtersOut.Add([ordered]@{ col = $fc; op = $fo; values = @($vo.ToArray()) })
            } else {
                $fv = Get-PimListLayoutProp -Object $f -Name 'value'
                if (-not (Test-PimListLayoutText -Value $fv -Max $lim.textMax)) { return (& $bad "a '$fo' filter needs a text of 1 to $($lim.textMax) characters") }
                if ($null -ne (Get-PimListLayoutProp -Object $f -Name 'values')) { return (& $bad "a '$fo' filter has a value, not values") }
                $filtersOut.Add([ordered]@{ col = $fc; op = $fo; value = $fv })
            }
        }
        if ($filtersOut.Count -gt $lim.filters) { return (& $bad "a layout holds at most $($lim.filters) filters") }
    }

    $ps = Get-PimListLayoutProp -Object $Layout -Name 'pageSize'
    if ($null -eq $ps) { $ps = 0 }
    if (($ps -is [string]) -or ($ps -is [bool]) -or (@(Get-PimListLayoutPageSizes | ForEach-Object { "$_" }) -notcontains "$ps")) { return (& $bad "layout.pageSize must be one of: $((Get-PimListLayoutPageSizes) -join ', ') (0 = all rows)") }

    $clean = [ordered]@{ v = 1; columns = @($lists['columns'].ToArray()); hidden = @($lists['hidden'].ToArray()); sort = $sortOut
        search = $search; filters = @($filtersOut.ToArray()); pageSize = [int]"$ps" }
    $size = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $clean -Depth 8 -Compress))
    if ($size -gt $lim.layoutBytes) { return (& $bad "the layout is too large ($size bytes; at most $($lim.layoutBytes))") }
    return @{ ok = $true; error = ''; layout = $clean }
}

function Get-PimListLayoutDoc {
    <#
      PURE over -ReadSetting. One stored document as @{ ok; error; identity; views = ordered { view -> @{ default; layouts =
      List of ordered { id, name, layout, by, atUtc } } } }. Absent = an empty document (ok). A read that THROWS, or a value
      that is not a layouts document, is ok = $false -- the caller then changes NOTHING (a store that cannot be read is
      never overwritten with an empty list).
      For a personal document -Identity is checked against the identity stored in it: a different one = not this person's.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$ReadSetting, [string]$Identity = '')
    $doc = @{ ok = $true; error = ''; identity = ''; views = [ordered]@{} }
    $raw = $null
    try { $raw = & $ReadSetting $Name } catch { $doc.ok = $false; $doc.error = "the saved layouts could not be read: $($_.Exception.Message)"; return $doc }
    if ($null -eq $raw) { return $doc }
    if ($raw -is [string]) {
        if (-not $raw.Trim()) { return $doc }
        try { $raw = $raw | ConvertFrom-Json } catch { $doc.ok = $false; $doc.error = "the saved layouts ('$Name') are not valid JSON; nothing was changed"; return $doc }
    }
    if (($raw -is [ValueType]) -or (Test-PimListLayoutIsList -Value $raw)) { $doc.ok = $false; $doc.error = "the saved layouts ('$Name') are not a layouts document; nothing was changed"; return $doc }
    $doc.identity = "$(Get-PimListLayoutProp -Object $raw -Name 'identity')"
    if ("$Identity".Trim() -and $doc.identity.Trim() -and ($doc.identity.Trim().ToLowerInvariant() -ne "$Identity".Trim().ToLowerInvariant())) {
        $doc.ok = $false; $doc.error = 'the stored layouts belong to a different identity; nothing was read or changed'; return $doc
    }
    $views = Get-PimListLayoutProp -Object $raw -Name 'views'
    foreach ($vk in @(Get-PimListLayoutPropNames -Object $views)) {
        if (-not (Test-PimListLayoutViewKey -View $vk)) { continue }
        $vv = Get-PimListLayoutProp -Object $views -Name $vk
        $list = New-Object System.Collections.Generic.List[object]
        # (into a variable first: the reader hands a list over as ONE object, and @( call ) would wrap it once more)
        $storedList = Get-PimListLayoutProp -Object $vv -Name 'layouts'
        foreach ($e in @($storedList)) {
            if ($null -eq $e) { continue }
            $id = "$(Get-PimListLayoutProp -Object $e -Name 'id')"
            if ($id -notmatch '^[0-9a-f]{32}$') { continue }
            # a stored layout is checked again on the way out: what the check does not accept is not served
            $chk = ConvertTo-PimListLayout -Layout (Get-PimListLayoutProp -Object $e -Name 'layout')
            if (-not $chk.ok) { continue }
            $list.Add([ordered]@{ id = $id; name = "$(Get-PimListLayoutProp -Object $e -Name 'name')"; layout = $chk.layout
                by = "$(Get-PimListLayoutProp -Object $e -Name 'by')"; atUtc = "$(Get-PimListLayoutProp -Object $e -Name 'atUtc')" })
        }
        $def = "$(Get-PimListLayoutProp -Object $vv -Name 'default')"
        if ($def -and -not @($list | Where-Object { $_.id -eq $def }).Count) { $def = '' }
        $doc.views[$vk] = @{ default = $def; layouts = $list }
    }
    return $doc
}

function ConvertTo-PimListLayoutStored {
    # PURE. The document as it is written: ordered, lists as lists (also with one or no entry), views without a layout left out.
    param([Parameter(Mandatory)][hashtable]$Doc, [string]$Identity = '', [switch]$Shared)
    $views = [ordered]@{}
    foreach ($vk in @($Doc.views.Keys)) {
        $v = $Doc.views[$vk]
        $items = @($v.layouts | ForEach-Object {
            if ($Shared) { [ordered]@{ id = $_.id; name = $_.name; layout = $_.layout; by = $_.by; atUtc = $_.atUtc } }
            else { [ordered]@{ id = $_.id; name = $_.name; layout = $_.layout; atUtc = $_.atUtc } }
        })
        if (-not $items.Count) { continue }
        if ($Shared) { $views[$vk] = [ordered]@{ default = "$($v.default)"; layouts = $items } }
        else { $views[$vk] = [ordered]@{ layouts = $items } }
    }
    if ($Shared) { return [ordered]@{ v = 1; views = $views } }
    return [ordered]@{ v = 1; identity = "$Identity".Trim().ToLowerInvariant(); views = $views }
}

function Get-PimListLayoutsBody {
    <#
      PURE over -ReadSetting. What GET /api/list-layouts answers: every view's shared layouts (with the default) and THIS
      person's own -- never anybody else's. A store that cannot be read answers ok = $false with the reason and no
      layouts (the page then shows the standard columns and says why saving is not possible).
    #>
    param([string]$Identity, [bool]$IsSuperAdmin, [Parameter(Mandatory)][scriptblock]$ReadSetting)
    $lim = Get-PimListLayoutLimits
    $body = [ordered]@{ ok = $true; identity = "$Identity"; canShare = [bool]$IsSuperAdmin; views = [ordered]@{}; error = ''
        limits = [ordered]@{ nameMax = $lim.nameMax; perView = $lim.perView; filters = $lim.filters; values = $lim.values; textMax = $lim.textMax }
        operators = @(Get-PimListLayoutOperators); pageSizes = @(Get-PimListLayoutPageSizes) }
    $shared = Get-PimListLayoutDoc -Name (Get-PimListLayoutSharedSettingName) -ReadSetting $ReadSetting
    $mine = $null
    $userName = Get-PimListLayoutUserSettingName -Identity $Identity
    if ($userName) { $mine = Get-PimListLayoutDoc -Name $userName -ReadSetting $ReadSetting -Identity $Identity }
    $errs = @()
    if (-not $shared.ok) { $errs += $shared.error }
    if ($mine -and -not $mine.ok) { $errs += $mine.error }
    if ($errs.Count) { $body.ok = $false; $body.error = ($errs -join ' ') }
    $keys = New-Object System.Collections.Generic.List[string]
    if ($shared.ok) { foreach ($k in @($shared.views.Keys)) { if (-not $keys.Contains("$k")) { $keys.Add("$k") } } }
    if ($mine -and $mine.ok) { foreach ($k in @($mine.views.Keys)) { if (-not $keys.Contains("$k")) { $keys.Add("$k") } } }
    foreach ($k in $keys) {
        $sv = if ($shared.ok -and $shared.views.Contains($k)) { $shared.views[$k] } else { $null }
        $mv = if ($mine -and $mine.ok -and $mine.views.Contains($k)) { $mine.views[$k] } else { $null }
        $sharedItems = @($(if ($sv) { $sv.layouts | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; layout = $_.layout; by = $_.by; atUtc = $_.atUtc } } }))
        $mineItems   = @($(if ($mv) { $mv.layouts | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; layout = $_.layout; atUtc = $_.atUtc } } }))
        if (($sharedItems.Count + $mineItems.Count) -eq 0) { continue }   # a list without a layout that can be served is not listed
        $body.views[$k] = [ordered]@{ default = "$(if ($sv) { $sv.default })"; shared = $sharedItems; mine = $mineItems }
    }
    return $body
}

function Get-PimListLayoutScope {
    # PURE. 'user' | 'shared' | '' (anything else).
    param([object]$Scope)
    if (-not ($Scope -is [string])) { return '' }
    if ($Scope -ceq 'user' -or $Scope -ceq 'shared') { return $Scope }
    return ''
}
function Get-PimListLayoutSharedRefusal {
    # The ONE sentence an Admin (or anyone below SuperAdmin) gets for a shared layout -- the page shows it as it is.
    'Only a SuperAdmin saves, changes or deletes a layout for everyone, or marks one as the default. Your own layout is saved with "Save as a layout".'
}

function Save-PimListLayout {
    <#
      PURE over the two script blocks. PUT /api/list-layouts { view, scope: user | shared, id?, name, layout }.
      No id = a new layout; an id = that layout is changed (name and / or content) -- in the SAME scope and view only.
      Returns @{ status; body; audit } (audit = $null, or @{ action; target; before; after } for a shared layout).
      Order of the checks: the body's shape (400), then the role for a shared layout (403), then the store.
    #>
    param([object]$Body, [string]$Identity, [bool]$IsSuperAdmin, [Parameter(Mandatory)][scriptblock]$ReadSetting, [Parameter(Mandatory)][scriptblock]$WriteSetting)
    $lim = Get-PimListLayoutLimits
    $r = { param($s, $m) return @{ status = [int]$s; body = [ordered]@{ ok = $false; error = "$m" }; audit = $null } }
    if ($null -eq $Body -or ($Body -is [string]) -or ($Body -is [ValueType]) -or (Test-PimListLayoutIsList -Value $Body)) { return (& $r 400 'send { view, scope, name, layout }') }
    $view = Get-PimListLayoutProp -Object $Body -Name 'view'
    if (-not (Test-PimListLayoutViewKey -View $view)) { return (& $r 400 'view must be the key of a list view') }
    $scope = Get-PimListLayoutScope -Scope (Get-PimListLayoutProp -Object $Body -Name 'scope')
    if (-not $scope) { return (& $r 400 'scope must be "user" (your own layout) or "shared" (for everyone)') }
    $name = Get-PimListLayoutProp -Object $Body -Name 'name'
    if (-not (Test-PimListLayoutText -Value $name -Max $lim.nameMax)) { return (& $r 400 "name must be a text of 1 to $($lim.nameMax) characters") }
    $name = $name.Trim()
    $id = Get-PimListLayoutProp -Object $Body -Name 'id'
    if ($null -ne $id -and "$id" -ne '' -and (-not ($id -is [string]) -or $id -notmatch '^[0-9a-f]{32}$')) { return (& $r 400 'id is not the id of a layout') }
    $id = "$id"
    $chk = ConvertTo-PimListLayout -Layout (Get-PimListLayoutProp -Object $Body -Name 'layout')
    if (-not $chk.ok) { return (& $r 400 "the layout was refused: $($chk.error)") }
    if ($scope -eq 'shared' -and -not $IsSuperAdmin) { return (& $r 403 (Get-PimListLayoutSharedRefusal)) }
    if (-not "$Identity".Trim()) { return (& $r 401 'no signed-in identity on this request; a layout is saved for a person') }

    $isShared = ($scope -eq 'shared')
    $setting = if ($isShared) { Get-PimListLayoutSharedSettingName } else { Get-PimListLayoutUserSettingName -Identity $Identity }
    $doc = if ($isShared) { Get-PimListLayoutDoc -Name $setting -ReadSetting $ReadSetting } else { Get-PimListLayoutDoc -Name $setting -ReadSetting $ReadSetting -Identity $Identity }
    if (-not $doc.ok) { return (& $r 503 $doc.error) }
    if (-not $doc.views.Contains($view)) {
        if ($doc.views.Count -ge $lim.views) { return (& $r 409 "layouts are saved for $($lim.views) list views already") }
        $doc.views[$view] = @{ default = ''; layouts = (New-Object System.Collections.Generic.List[object]) }
    }
    $list = $doc.views[$view].layouts
    $same = @($list | Where-Object { "$($_.name)".ToLowerInvariant() -eq $name.ToLowerInvariant() -and $_.id -ne $id })
    if ($same.Count) { return (& $r 409 "a layout named ""$name"" exists already in this list; choose another name") }
    $now = [datetime]::UtcNow.ToString('o')
    $before = $null; $entry = $null
    if ($id) {
        $entry = @($list | Where-Object { $_.id -eq $id })[0]
        if (-not $entry) { return (& $r 404 'that layout does not exist any more (it was deleted, or it is not in this list)') }
        $before = [ordered]@{ id = $entry.id; name = $entry.name; layout = $entry.layout }
        $entry.name = $name; $entry.layout = $chk.layout; $entry.by = "$Identity"; $entry.atUtc = $now
    } else {
        if ($list.Count -ge $lim.perView) { return (& $r 409 "this list has $($lim.perView) saved layouts already; delete one first") }
        $entry = [ordered]@{ id = [guid]::NewGuid().ToString('N'); name = $name; layout = $chk.layout; by = "$Identity"; atUtc = $now }
        $list.Add($entry)
    }
    $stored = if ($isShared) { ConvertTo-PimListLayoutStored -Doc $doc -Shared } else { ConvertTo-PimListLayoutStored -Doc $doc -Identity $Identity }
    try { & $WriteSetting $setting $stored } catch { return (& $r 500 "the layout was NOT saved: $($_.Exception.Message)") }
    $audit = $null
    if ($isShared) { $audit = @{ action = 'list-layout.shared.save'; target = "$view/$($entry.id)"; before = $before; after = [ordered]@{ id = $entry.id; name = $entry.name; layout = $entry.layout } } }
    return @{ status = 200; audit = $audit; body = [ordered]@{ ok = $true; view = $view; scope = $scope; id = $entry.id; name = $entry.name; layout = $entry.layout; atUtc = $now } }
}

function Remove-PimListLayout {
    # PURE over the two script blocks. DELETE /api/list-layouts?view=&scope=&id= . A shared layout: SuperAdmin only (403).
    # Deleting the default layout of a view also clears the default.
    param([object]$View, [object]$Scope, [object]$Id, [string]$Identity, [bool]$IsSuperAdmin, [Parameter(Mandatory)][scriptblock]$ReadSetting, [Parameter(Mandatory)][scriptblock]$WriteSetting)
    $r = { param($s, $m) return @{ status = [int]$s; body = [ordered]@{ ok = $false; error = "$m" }; audit = $null } }
    if (-not (Test-PimListLayoutViewKey -View $View)) { return (& $r 400 'view must be the key of a list view') }
    $sc = Get-PimListLayoutScope -Scope $Scope
    if (-not $sc) { return (& $r 400 'scope must be "user" or "shared"') }
    if (-not ($Id -is [string]) -or $Id -notmatch '^[0-9a-f]{32}$') { return (& $r 400 'id is not the id of a layout') }
    if ($sc -eq 'shared' -and -not $IsSuperAdmin) { return (& $r 403 (Get-PimListLayoutSharedRefusal)) }
    if (-not "$Identity".Trim()) { return (& $r 401 'no signed-in identity on this request') }
    $isShared = ($sc -eq 'shared')
    $setting = if ($isShared) { Get-PimListLayoutSharedSettingName } else { Get-PimListLayoutUserSettingName -Identity $Identity }
    $doc = if ($isShared) { Get-PimListLayoutDoc -Name $setting -ReadSetting $ReadSetting } else { Get-PimListLayoutDoc -Name $setting -ReadSetting $ReadSetting -Identity $Identity }
    if (-not $doc.ok) { return (& $r 503 $doc.error) }
    $entry = $null
    if ($doc.views.Contains($View)) { $entry = @($doc.views[$View].layouts | Where-Object { $_.id -eq $Id })[0] }
    if (-not $entry) { return (& $r 404 'that layout does not exist any more') }
    [void]$doc.views[$View].layouts.Remove($entry)
    $wasDefault = ($isShared -and "$($doc.views[$View].default)" -eq $Id)
    if ($wasDefault) { $doc.views[$View].default = '' }
    $stored = if ($isShared) { ConvertTo-PimListLayoutStored -Doc $doc -Shared } else { ConvertTo-PimListLayoutStored -Doc $doc -Identity $Identity }
    try { & $WriteSetting $setting $stored } catch { return (& $r 500 "the layout was NOT deleted: $($_.Exception.Message)") }
    $audit = $null
    if ($isShared) { $audit = @{ action = 'list-layout.shared.delete'; target = "$View/$Id"; before = [ordered]@{ id = $entry.id; name = $entry.name; wasDefault = [bool]$wasDefault }; after = $null } }
    return @{ status = 200; audit = $audit; body = [ordered]@{ ok = $true; view = $View; scope = $sc; id = $Id; clearedDefault = [bool]$wasDefault } }
}

function Set-PimListLayoutDefault {
    # PURE over the two script blocks. PUT /api/list-layouts/default { view, id } -- id = a SHARED layout of that view, or
    # '' = no default (the list's standard columns). SuperAdmin only (403), whoever asks.
    param([object]$Body, [string]$Identity, [bool]$IsSuperAdmin, [Parameter(Mandatory)][scriptblock]$ReadSetting, [Parameter(Mandatory)][scriptblock]$WriteSetting)
    $r = { param($s, $m) return @{ status = [int]$s; body = [ordered]@{ ok = $false; error = "$m" }; audit = $null } }
    if ($null -eq $Body -or ($Body -is [string]) -or ($Body -is [ValueType]) -or (Test-PimListLayoutIsList -Value $Body)) { return (& $r 400 'send { view, id }') }
    $view = Get-PimListLayoutProp -Object $Body -Name 'view'
    if (-not (Test-PimListLayoutViewKey -View $view)) { return (& $r 400 'view must be the key of a list view') }
    $id = Get-PimListLayoutProp -Object $Body -Name 'id'
    if ($null -eq $id) { $id = '' }
    if (-not ($id -is [string]) -or ($id -ne '' -and $id -notmatch '^[0-9a-f]{32}$')) { return (& $r 400 'id must be the id of a layout for everyone, or empty for no default') }
    if (-not $IsSuperAdmin) { return (& $r 403 (Get-PimListLayoutSharedRefusal)) }
    $setting = Get-PimListLayoutSharedSettingName
    $doc = Get-PimListLayoutDoc -Name $setting -ReadSetting $ReadSetting
    if (-not $doc.ok) { return (& $r 503 $doc.error) }
    if ($id -and (-not $doc.views.Contains($view) -or -not @($doc.views[$view].layouts | Where-Object { $_.id -eq $id }).Count)) { return (& $r 404 'that layout is not a layout for everyone of this list') }
    if (-not $doc.views.Contains($view)) { return @{ status = 200; audit = $null; body = [ordered]@{ ok = $true; view = $view; default = '' } } }
    $before = "$($doc.views[$view].default)"
    $doc.views[$view].default = $id
    try { & $WriteSetting $setting (ConvertTo-PimListLayoutStored -Doc $doc -Shared) } catch { return (& $r 500 "the default was NOT saved: $($_.Exception.Message)") }
    return @{ status = 200; body = [ordered]@{ ok = $true; view = $view; default = $id }
        audit = @{ action = 'list-layout.shared.default'; target = "$view"; before = [ordered]@{ default = $before }; after = [ordered]@{ default = $id } } }
}

function Invoke-PimManagerListLayoutRequest {
    <#
      THE GLUE (the only part that touches the running Manager): GET / PUT / DELETE /api/list-layouts and
      PUT /api/list-layouts/default. Returns the status it wrote, or $null when the path is not one of these.
      Who the caller is and whether they are a SuperAdmin come from the Manager's own role resolution for THIS request
      (Get-PimManagerRole / Test-PimManagerRoleAtLeast) -- never from the request body. The store is pim.Settings through
      Get-PimManagerSettingObject / Set-PimManagerSettingObject (SQL only; no file).
    #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][object]$Response)
    if ($Path -ne '/api/list-layouts' -and $Path -ne '/api/list-layouts/default') { return $null }
    $who = ''; try { $who = "$((Get-PimManagerRole).identity)" } catch { $who = '' }
    if ($who -eq '<unauthenticated>') { $who = '' }
    $super = $false; try { $super = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $super = $false }
    # (names of their own: a called function that names $read / $write would otherwise find THESE by dynamic scope)
    $llRead = { param($n) Get-PimManagerSettingObject -Name $n }
    $llWrite = { param($n, $v) Set-PimManagerSettingObject -Name $n -Value $v }
    $res = $null
    if ($Path -eq '/api/list-layouts' -and $Method -eq 'GET') {
        $b = Get-PimListLayoutsBody -Identity $who -IsSuperAdmin $super -ReadSetting $llRead
        Write-JsonResponse -Response $Response -Status 200 -Body $b
        return 200
    }
    elseif ($Path -eq '/api/list-layouts' -and $Method -eq 'PUT') {
        $body = $null; try { $body = Read-RequestJson -Request $Request } catch { $body = $null }
        $res = Save-PimListLayout -Body $body -Identity $who -IsSuperAdmin $super -ReadSetting $llRead -WriteSetting $llWrite
    }
    elseif ($Path -eq '/api/list-layouts' -and $Method -eq 'DELETE') {
        $qv = $null; $qs = $null; $qi = $null
        try { $qv = $Request.QueryString['view']; $qs = $Request.QueryString['scope']; $qi = $Request.QueryString['id'] } catch { }
        $res = Remove-PimListLayout -View $qv -Scope $qs -Id $qi -Identity $who -IsSuperAdmin $super -ReadSetting $llRead -WriteSetting $llWrite
    }
    elseif ($Path -eq '/api/list-layouts/default' -and $Method -eq 'PUT') {
        $body = $null; try { $body = Read-RequestJson -Request $Request } catch { $body = $null }
        $res = Set-PimListLayoutDefault -Body $body -Identity $who -IsSuperAdmin $super -ReadSetting $llRead -WriteSetting $llWrite
    }
    else {
        Write-JsonResponse -Response $Response -Status 405 -Body @{ ok = $false; error = "$Method is not supported on $Path" }
        return 405
    }
    if ($res.audit -and (Get-Command Write-PimManagerAuditEvent -ErrorAction SilentlyContinue)) {
        # a shared layout is everybody's view of a list: who changed it is in the audit trail. A personal one is not audited.
        try { Write-PimManagerAuditEvent -Action "$($res.audit.action)" -Target "$($res.audit.target)" -Before $res.audit.before -After $res.audit.after -Result 'ok' }
        catch { Write-Warning "[list-layouts] audit not written: $($_.Exception.Message)" }
    }
    Write-JsonResponse -Response $Response -Status ([int]$res.status) -Body $res.body
    return [int]$res.status
}

# =====================================================================================================================
# THE LIST QUERY (?lm=) -- the list menu's conditions, search and sort for a list the SERVER pages.
# Two lists are read page by page: Review current delegations (GET /api/active-assignments?page=) and Audit
# (GET /api/audit). A filter that worked on the page shown would not be a filter on the list, so the toolbar sends its
# conditions with the list request and the server applies them over the WHOLE list before it pages, and answers the
# number of matching rows.
#   lm = JSON  { "search": "text", "filters": [ { "col", "op", "value" } | { "col", "op": "anyOf", "values": [..] } ],
#                "sort": { "col", "dir": 1 | -1 } }
# RULES: a column is one of a CLOSED list per list (or "*" = every text column); an operator is one of the five; texts
# have a length limit. What is not exactly that is refused with 400 and the reason -- never repaired, never ignored.
# A value is always TEXT: for the SQL list it reaches the database as a parameter (engine/_shared/PIM-SqlStore.ps1,
# Get-PimActiveAssignmentsConditionSql), for the audit list it is compared in memory. No request without ?lm= is
# touched: its answer is what it was.
# =====================================================================================================================
function Get-PimListQueryLimits { @{ textMax = 4000; filters = 10; valueMax = 200; values = 50 } }

function Get-PimListQueryListForPath {
    # PURE. Which paged list a request path is ('' = none: ?lm= means nothing there).
    param([string]$Path)
    if ("$Path" -eq '/api/active-assignments') { return 'active-assignments' }
    if ("$Path" -eq '/api/audit') { return 'audit' }
    return ''
}
function Get-PimListQueryColumns {
    # PURE. The CLOSED list of column names a condition may name, per list.
    param([string]$List)
    if ("$List" -eq 'active-assignments') { return @('principal', 'role', 'scope', 'type', 'justification') }
    if ("$List" -eq 'audit') { return @('when', 'actor', 'category', 'action', 'target', 'result', 'change') }
    return @()
}
function Get-PimListQuerySortColumns {
    # PURE. The columns ?lm= may sort by. Review current delegations sorts with its own ?sort= / ?dir= (in SQL), so none.
    param([string]$List)
    if ("$List" -eq 'audit') { return @('when', 'actor', 'category', 'action', 'target', 'result') }
    return @()
}

function ConvertTo-PimListQuery {
    <#
      PURE. The text of ?lm= -> the checked query: @{ ok; error; active; search; filters; sort; needsText }.
      Empty = ok and not active. filters = ordered { col, op, value } / { col, op = 'anyOf', values }; sort = $null or
      @{ col; descending }. needsText = a search, or a condition on "*" (the caller must then have every text column).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [string[]]$Columns = @(), [string[]]$SortColumns = @())
    $lim = Get-PimListQueryLimits
    $out = @{ ok = $true; error = ''; active = $false; search = ''; filters = @(); sort = $null; needsText = $false }
    $bad = { param($m) return @{ ok = $false; error = "$m"; active = $false; search = ''; filters = @(); sort = $null; needsText = $false } }
    if ($null -eq $Text -or -not "$Text".Trim()) { return $out }
    if ($Text.Length -gt $lim.textMax) { return (& $bad "the list filter is too long ($($Text.Length) characters; at most $($lim.textMax))") }
    $q = $null
    try { $q = $Text | ConvertFrom-Json } catch { return (& $bad 'the list filter is not valid JSON') }
    if ($null -eq $q -or ($q -is [string]) -or ($q -is [ValueType]) -or (Test-PimListLayoutIsList -Value $q)) { return (& $bad 'the list filter must be an object { search, filters, sort }') }
    foreach ($n in @(Get-PimListLayoutPropNames -Object $q)) { if (@('search', 'filters', 'sort') -cnotcontains $n) { return (& $bad "the list filter has a field that is not part of it: $n") } }

    $search = Get-PimListLayoutProp -Object $q -Name 'search'
    if ($null -eq $search) { $search = '' }
    if (-not (Test-PimListLayoutText -Value $search -Max $lim.valueMax -AllowEmpty)) { return (& $bad "search must be text of at most $($lim.valueMax) characters") }
    $search = $search.Trim()

    $ops = @(Get-PimListLayoutOperators)
    $list = New-Object System.Collections.Generic.List[object]
    $filters = Get-PimListLayoutProp -Object $q -Name 'filters'
    $star = $false
    if ($null -ne $filters) {
        if (-not (Test-PimListLayoutIsList -Value $filters)) { return (& $bad 'filters must be a list') }
        foreach ($f in @($filters)) {
            if ($null -eq $f -or ($f -is [string]) -or ($f -is [ValueType]) -or (Test-PimListLayoutIsList -Value $f)) { return (& $bad 'a condition must be an object { col, op, value }') }
            foreach ($n in @(Get-PimListLayoutPropNames -Object $f)) { if (@('col', 'op', 'value', 'values') -cnotcontains $n) { return (& $bad "a condition has a field that is not part of it: $n") } }
            $fc = Get-PimListLayoutProp -Object $f -Name 'col'
            $fo = Get-PimListLayoutProp -Object $f -Name 'op'
            if (-not ($fc -is [string]) -or ($fc -cne '*' -and @($Columns) -cnotcontains $fc)) { return (& $bad "a condition names a column this list cannot filter on (known: $((@($Columns) + '*') -join ', '))") }
            if (-not ($fo -is [string]) -or $ops -cnotcontains $fo) { return (& $bad "a condition's operator must be one of: $($ops -join ', ')") }
            if ($fo -ceq 'anyOf') {
                if ($fc -ceq '*') { return (& $bad '"any of" needs one column') }
                $vals = Get-PimListLayoutProp -Object $f -Name 'values'
                if (-not (Test-PimListLayoutIsList -Value $vals)) { return (& $bad 'an "any of" condition needs values: a list of texts') }
                $vo = New-Object System.Collections.Generic.List[string]
                foreach ($x in @($vals)) {
                    if (-not (Test-PimListLayoutText -Value $x -Max $lim.valueMax -AllowEmpty)) { return (& $bad "an ""any of"" condition holds a value that is not a text of at most $($lim.valueMax) characters") }
                    if (-not $vo.Contains($x)) { $vo.Add($x) }
                }
                if ($vo.Count -lt 1 -or $vo.Count -gt $lim.values) { return (& $bad "an ""any of"" condition holds 1 to $($lim.values) values") }
                if ($null -ne (Get-PimListLayoutProp -Object $f -Name 'value')) { return (& $bad 'an "any of" condition has values, not a value') }
                $list.Add([ordered]@{ col = $fc; op = $fo; values = @($vo.ToArray()) })
            } else {
                $fv = Get-PimListLayoutProp -Object $f -Name 'value'
                if (-not (Test-PimListLayoutText -Value $fv -Max $lim.valueMax)) { return (& $bad "a '$fo' condition needs a text of 1 to $($lim.valueMax) characters") }
                if ($null -ne (Get-PimListLayoutProp -Object $f -Name 'values')) { return (& $bad "a '$fo' condition has a value, not values") }
                if ($fc -ceq '*') { $star = $true }
                $list.Add([ordered]@{ col = $fc; op = $fo; value = $fv })
            }
        }
        if ($list.Count -gt $lim.filters) { return (& $bad "at most $($lim.filters) conditions") }
    }

    $sortOut = $null
    $sort = Get-PimListLayoutProp -Object $q -Name 'sort'
    if ($null -ne $sort) {
        if (($sort -is [string]) -or ($sort -is [ValueType]) -or (Test-PimListLayoutIsList -Value $sort)) { return (& $bad 'sort must be { col, dir }') }
        foreach ($n in @(Get-PimListLayoutPropNames -Object $sort)) { if (@('col', 'dir') -cnotcontains $n) { return (& $bad "sort has a field that is not part of it: $n") } }
        $sc = Get-PimListLayoutProp -Object $sort -Name 'col'
        $sd = Get-PimListLayoutProp -Object $sort -Name 'dir'
        if (-not ($sc -is [string]) -or @($SortColumns) -cnotcontains $sc) { return (& $bad "this list cannot be sorted by that column (known: $(@($SortColumns) -join ', '))") }
        if (($sd -is [string]) -or ($sd -is [bool]) -or @('1', '-1') -notcontains "$sd") { return (& $bad 'sort.dir must be 1 or -1') }
        $sortOut = @{ col = $sc; descending = ("$sd" -eq '-1') }
    }
    $out.search = $search; $out.filters = @($list.ToArray()); $out.sort = $sortOut
    $out.needsText = [bool]($search -or $star)
    $out.active = [bool]($search -or $list.Count -or $sortOut)
    return $out
}

function Test-PimListQueryText {
    # PURE. One condition against one text, the way the page compares: trimmed, case-insensitive, the value is TEXT.
    param([AllowNull()][string]$Hay, [Parameter(Mandatory)][object]$Filter)
    $h = "$Hay".Trim().ToLowerInvariant()
    $op = "$($Filter.op)"
    if ($op -ceq 'anyOf') {
        foreach ($v in @($Filter.values)) { if ("$v".Trim().ToLowerInvariant() -ceq $h) { return $true } }
        return $false
    }
    $n = "$($Filter.value)".Trim().ToLowerInvariant()
    if ($op -ceq 'contains')    { return ($h.IndexOf($n, [StringComparison]::Ordinal) -ge 0) }
    if ($op -ceq 'notContains') { return ($h.IndexOf($n, [StringComparison]::Ordinal) -lt 0) }
    if ($op -ceq 'equals')      { return ($h -ceq $n) }
    if ($op -ceq 'startsWith')  { return $h.StartsWith($n, [StringComparison]::Ordinal) }
    return $false   # an operator that is not one of the five matches nothing (the query was checked before; fail closed)
}

function Select-PimListRows {
    <#
      PURE over -Read { param($row, $column) -> text }. The rows of a WHOLE list that match the checked query, in the
      query's sort (the list's own order when it has none, and between equal values). "*" and the search read every
      column of -Columns. Returns an array (possibly empty).
    #>
    param([AllowNull()][object[]]$Rows, [Parameter(Mandatory)][object]$Query, [Parameter(Mandatory)][scriptblock]$Read, [string[]]$Columns = @())
    $keep = New-Object System.Collections.Generic.List[object]
    $needle = "$($Query.search)".Trim().ToLowerInvariant()
    $filters = @($Query.filters)
    $i = 0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $all = $null
        $ok = $true
        if ($needle) {
            $all = (@($Columns | ForEach-Object { "$(& $Read $r $_)" }) -join ' | ').ToLowerInvariant()
            if ($all.IndexOf($needle, [StringComparison]::Ordinal) -lt 0) { $ok = $false }
        }
        foreach ($f in $filters) {
            if (-not $ok) { break }
            if ($null -eq $f) { continue }
            $hay = ''
            if ("$($f.col)" -ceq '*') { if ($null -eq $all) { $all = (@($Columns | ForEach-Object { "$(& $Read $r $_)" }) -join ' | ').ToLowerInvariant() }; $hay = $all }
            else { $hay = "$(& $Read $r "$($f.col)")" }
            if (-not (Test-PimListQueryText -Hay $hay -Filter $f)) { $ok = $false }
        }
        if ($ok) { $keep.Add([pscustomobject]@{ i = $i; k = $(if ($Query.sort) { "$(& $Read $r "$($Query.sort.col)")" } else { '' }); r = $r }) }
        $i++
    }
    $items = @($keep.ToArray())
    if ($Query.sort -and $items.Count -gt 1) {
        $items = @($items | Sort-Object -Property @{ Expression = 'k'; Descending = [bool]$Query.sort.descending }, @{ Expression = 'i'; Descending = $false })
    }
    return @($items | ForEach-Object { $_.r })
}

function Get-PimAuditListValue {
    # PURE. The text of one audit event in one column of the Audit list, as the page shows it (the time as stored, UTC).
    param([AllowNull()][object]$Event, [string]$Column)
    switch -CaseSensitive ("$Column") {
        'when'     { return "$(Get-PimListLayoutProp -Object $Event -Name 'ts')" }
        'actor'    { return "$(Get-PimListLayoutProp -Object $Event -Name 'actor')" }
        'category' { $c = "$(Get-PimListLayoutProp -Object $Event -Name 'category')"; if ($c) { return $c } else { return 'other' } }
        'action'   { $a = "$(Get-PimListLayoutProp -Object $Event -Name 'action')"; if ($a -eq 'config.csv.save') { return 'config.save' } else { return $a } }
        'target'   { return "$(Get-PimListLayoutProp -Object $Event -Name 'target')" }
        'result'   { $x = "$(Get-PimListLayoutProp -Object $Event -Name 'result')"; if ($x) { return $x } else { return 'ok' } }
        'change'   { return "$(Get-PimListLayoutProp -Object $Event -Name 'change')" }
    }
    return ''
}

function Invoke-PimManagerListQueryGate {
    <#
      Called for every /api request before the list handlers: a ?lm= on one of the two paged lists that is not exactly a
      list query is answered 400 with the reason HERE; anything else is $null (carry on -- the list's own handler then
      applies its role gate and the checked query). Nothing is read from a store and no row is touched.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][object]$Response)
    $list = Get-PimListQueryListForPath -Path $Path
    if (-not $list) { return $null }
    $t = $null
    try { $t = $Request.QueryString['lm'] } catch { $t = $null }
    if ($null -eq $t -or -not "$t".Trim()) { return $null }
    $q = ConvertTo-PimListQuery -Text "$t" -Columns (Get-PimListQueryColumns -List $list) -SortColumns (Get-PimListQuerySortColumns -List $list)
    if ($q.ok) { return $null }
    Write-JsonResponse -Response $Response -Status 400 -Body ([ordered]@{ ok = $false; listQueryRefused = $true; error = "The list filter was refused: $($q.error)." })
    return 400
}
