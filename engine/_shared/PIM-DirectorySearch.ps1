<#
  PIM-DirectorySearch.ps1 -- REQUIREMENTS §35.8

  PURE core for the directory-people lookup that every people-picker in the
  Manager needs and that NONE of them had.

  WHY THIS FILE EXISTS
  --------------------
  §35.8 recorded five places where the operator has to TYPE a value that the
  product could offer: Approvers -> Identity (UPN) and Role, Departments ->
  Owners and Contact, and the wizard's Azure scope. Three of those five are
  PEOPLE, and they were blocked on the same missing thing: the Manager exposed
  no /api/users, /api/people or /api/directory -- nothing anywhere searched the
  tenant for a person. This is that missing data source.

  WHAT THIS IS, AND IS NOT
  ------------------------
  No calls, no writes. It validates and normalises a query, builds the Graph
  request path, and shapes a result row. The endpoint performs the call. That
  keeps the injection-escaping and the "a blank query is not everyone" rule
  offline-testable, which is where they belong.

  TWO RULES THIS FILE ENFORCES, AND WHY
  -------------------------------------
  1. A BLANK OR 1-CHARACTER QUERY IS REFUSED, NEVER BROADENED. The lean-context
     rule (§22 / §35.5) is that this solution never bulk-lists a big tenant --
     the v1 wizard's `Get-MgUser -all:$true` is exactly what makes it slow. A
     picker that answers an empty query with "everyone" is that same mistake
     arriving one layer down, and it would do it on every keystroke.

  2. THE TERM IS ESCAPED FOR THE SYNTAX IT LANDS IN. A surname with an
     apostrophe -- O'Brien -- terminates an OData string literal early. Left
     unescaped that is a broken query at best and an injected one at worst, and
     it arrives via a name that real people genuinely have.

  PS 5.1-safe (no ?./??).
#>

$script:PimDirectoryMinQueryLength = 2
$script:PimDirectoryDefaultTop     = 20
$script:PimDirectoryMaxTop         = 50

function ConvertTo-PimODataStringLiteral {
    <#
      Escape a term for embedding in an OData string literal ('...'). In OData a
      single quote is escaped by DOUBLING it. Without this, O'Brien closes the
      literal and the rest of the name is parsed as syntax.
    #>
    [CmdletBinding()]
    param([string]$Term)
    return ("$Term" -replace "'", "''")
}

function ConvertTo-PimGraphSearchTerm {
    <#
      Escape a term for embedding in a Graph $search phrase ("field:term").
      The phrase is double-quoted, so a backslash and a double quote must both
      be escaped -- backslash FIRST, or the escape character we add is itself
      re-escaped.
    #>
    [CmdletBinding()]
    param([string]$Term)
    # 🪤 In a -replace REPLACEMENT string, backslash is NOT an escape character
    # (only '$' is special). So the replacement must be the two literal
    # backslashes we want -- '\\' -- not '\\\\', which inserts four and is what
    # this line did on its first cut. The test caught it.
    $t = "$Term" -replace '\\', '\\'
    $t = $t -replace '"', '\"'
    return $t
}

function Resolve-PimDirectoryQuery {
    <#
      .SYNOPSIS
        Validate + normalise a people-search request. Pure.

      .OUTPUTS
        PSCustomObject: ok(bool), code, reason, term, top.
        code is one of: ok | no-query | too-short
    #>
    [CmdletBinding()]
    param(
        [string]$Query,
        $Top
    )
    $term = "$Query".Trim()

    if (-not $term) {
        return [pscustomobject]@{
            ok = $false; code = 'no-query'; term = ''; top = 0
            reason = 'a search term is required -- an empty query is refused rather than returning the whole directory'
        }
    }
    if ($term.Length -lt $script:PimDirectoryMinQueryLength) {
        return [pscustomobject]@{
            ok = $false; code = 'too-short'; term = $term; top = 0
            reason = "search term must be at least $($script:PimDirectoryMinQueryLength) characters"
        }
    }

    # Clamp rather than honour. An unbounded -Top is how a picker turns into the
    # bulk list this file exists to avoid.
    $n = 0
    if (-not [int]::TryParse("$Top", [ref]$n)) { $n = $script:PimDirectoryDefaultTop }
    if ($n -le 0) { $n = $script:PimDirectoryDefaultTop }
    if ($n -gt $script:PimDirectoryMaxTop) { $n = $script:PimDirectoryMaxTop }

    return [pscustomobject]@{ ok = $true; code = 'ok'; reason = ''; term = $term; top = $n }
}

function Get-PimDirectoryPeopleSearchPath {
    <#
      PRIMARY query: Graph $search, which matches TOKENS WITHIN a name -- so
      typing a surname finds the person. $filter/startswith cannot do that, and
      searching people by surname is what admins actually do.
      Requires the ConsistencyLevel: eventual header (see Get-PimDirectorySearchHeaders).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Term, [int]$Top = 20)
    $t = ConvertTo-PimGraphSearchTerm -Term $Term
    $phrase = '"displayName:' + $t + '" OR "userPrincipalName:' + $t + '" OR "mail:' + $t + '" OR "surname:' + $t + '" OR "givenName:' + $t + '"'
    # +1 so the caller can tell "there are more" from "that is all of them".
    $take = $Top + 1
    return "/users?`$search=$([uri]::EscapeDataString($phrase))&`$top=$take&`$select=id,displayName,userPrincipalName,mail,accountEnabled&`$orderby=displayName"
}

function Get-PimDirectoryPeopleFilterPath {
    <#
      FALLBACK query: $filter + startswith. No special header and very widely
      permitted, but prefix-only -- a surname will not match. Used only when the
      $search attempt fails, and the response reports WHICH mode answered so a
      degraded result is visible rather than silent.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Term, [int]$Top = 20)
    $t = ConvertTo-PimODataStringLiteral -Term $Term
    $f = "startswith(displayName,'$t') or startswith(userPrincipalName,'$t') or startswith(mail,'$t')"
    $take = $Top + 1
    return "/users?`$filter=$([uri]::EscapeDataString($f))&`$top=$take&`$select=id,displayName,userPrincipalName,mail,accountEnabled"
}

function Get-PimDirectorySearchHeaders {
    # $search on /users is only served with eventual consistency.
    return @{ ConsistencyLevel = 'eventual' }
}

function ConvertTo-PimDirectoryPerson {
    <#
      Shape one Graph user into the picker's row. Deliberately NARROW: a picker
      needs a label, a value and enough to disambiguate two people with the same
      display name. Anything more is directory data leaving the tenant boundary
      for no reason.
    #>
    [CmdletBinding()]
    param($User)
    if ($null -eq $User) { return $null }
    $upn = "$($User.userPrincipalName)".Trim()
    $dn  = "$($User.displayName)".Trim()
    if (-not $upn -and -not $dn) { return $null }
    return [pscustomobject]@{
        id                = "$($User.id)"
        displayName       = $dn
        userPrincipalName = $upn
        mail              = "$($User.mail)".Trim()
        accountEnabled    = [bool]$User.accountEnabled
        # What a picker should put in the field. UPN is the identity every one of
        # the §35.8 fields actually stores; displayName is only the label.
        value             = $(if ($upn) { $upn } else { $dn })
    }
}

function Select-PimDirectoryPeoplePage {
    <#
      Trim an over-fetched result (Top+1) to the page and report truncation.
      'truncated' lets the GUI say "refine your search" instead of implying the
      list is complete -- a partial list presented as a whole one is how someone
      concludes a person does not exist.
    #>
    [CmdletBinding()]
    param([object[]]$People = @(), [int]$Top = 20)
    $all = @($People | Where-Object { $null -ne $_ })
    if ($Top -lt 1) { $Top = 1 }
    if ($all.Count -gt $Top) {
        return [pscustomobject]@{ people = @($all[0..($Top - 1)]); truncated = $true }
    }
    return [pscustomobject]@{ people = $all; truncated = $false }
}

function Get-PimDirectorySearchHttpStatus {
    [CmdletBinding()]
    param([string]$Code)
    switch ("$Code") {
        'ok'                { return 200 }
        'no-query'          { return 400 }
        'too-short'         { return 400 }
        'graph-unavailable' { return 503 }
        'graph-error'       { return 502 }
        default             { return 500 }
    }
}
