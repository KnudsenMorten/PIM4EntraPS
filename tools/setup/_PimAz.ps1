#requires -Version 5.1
<#
.SYNOPSIS
    ONE guarded way to call the az CLI. Dot-source this BEFORE the first `az` call in any
    setup/deploy script: it defines a function named `az` that shadows the CLI, so no call
    site changes.

.DESCRIPTION
    🔴 WHY THIS EXISTS -- measured on mgmt1, 2026-09-05, on the live internal-prod update.

    PowerShell 5.1 converts ANY write to a native command's stderr into a NativeCommandError
    ErrorRecord. The whole update path runs with `$ErrorActionPreference = 'Stop'`. So a mere
    WARNING from az -- not an error, not a non-zero exit -- ABORTS THE UPDATE.

    az writes ordinary, harmless things to stderr all the time:
      * `WARNING: The behavior of this command has been altered by the following extension: containerapp`
      * `... cryptography/hazmat/backends/openssl/backend.py:8: UserWarning: You are using
         cryptography on a 32-bit Python on a 64-bit Windows Operating System.`

    That second one killed `PIM-Update-mfnpr-internal` at the container-app DISCOVERY step:
        UPDATE FAILED: D:\a\_work\1\s\...\backend.py:8: UserWarning: ...
        outcome=failure (built=True deployed=False)
    The image had built perfectly. A Python performance hint stopped it being deployed.

    🪤 `2>$null` DOES NOT PREVENT THIS. The call sites already carried a comment calling the
    redirect "load-bearing" for exactly this warning. It is not. Measured, all five shapes
    THREW under `$ErrorActionPreference='Stop'`:
        $x = az ... 2>$null                          -> THREW
        @(az ... 2>$null)                            -> THREW
        az ... 2>$null | ForEach-Object { ... }       -> THREW
        $raw = az ... 2>$null ; @($raw) | ...         -> THREW
        az ... --only-show-errors 2>$null            -> THREW
    Redirection changes where the text GOES; it does not stop the ErrorRecord being raised.
    Only `$ErrorActionPreference` decides whether that record is terminating -- which is why
    the guard has to wrap the invocation, and cannot be a flag on it.

    🪤 AND IT ONLY BITES SOME HOSTS, WHICH IS WHY IT LOOKED LIKE IT WORKED. Whether az warns
    depends on the az CONFIG DIR: the two customer update tasks (wa678, rj466) run with an
    isolated `AZURE_CONFIG_DIR` holding no extensions, az stays silent, and they have gone
    green nightly. Internal prod ran on the shared default dir, which HAS extensions
    installed -- so the same code, same az, same command, on the same machine, failed. A pass
    on one environment says nothing about the next one here.

    🔒 WHAT THE GUARD DOES NOT DO: it never hides a real failure. Only the EXIT CODE decides
    success, exactly as before; every call site's `if ($LASTEXITCODE -ne 0)` keeps working.
    On a non-zero exit the captured stderr is PRINTED (as host text, not as an error record),
    so a genuine az failure is more visible than it was, not less.

.NOTES
    PS 5.1-safe. No modules. Dot-source only -- executing this file directly does nothing.
#>

# Resolved once per session, and deliberately NOT via `Get-Command az`: that would find the
# shadow function below and recurse. -CommandType Application can only match the real CLI.
$script:PimAzExe = $null
function Get-PimAzExecutable {
    if ($script:PimAzExe -and (Test-Path -LiteralPath $script:PimAzExe)) { return $script:PimAzExe }
    $cmd = Get-Command -Name 'az.cmd', 'az.bat', 'az.exe' -CommandType Application -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($cmd) { $script:PimAzExe = $cmd.Source }
    return $script:PimAzExe
}

# 🔴 §40.2 -- SAY THE POLICY DENIAL ONCE, IN THE OPERATOR'S LANGUAGE.
#
# Measured at a live customer 2026-09-08. One cause -- "Azure Policy permits only westeurope" --
# arrived as FIVE near-identical walls of text, one per denied resource, each carrying the full
# policyAssignment / policyDefinition / evaluationDetails JSON, and every one of them prefixed by
# the CLI's own 32-bit-Python OpenSSL banner. The operator, sitting with the customer, could not
# tell which line mattered and asked "what is missing?" three times. The deploy was behaving
# correctly the whole time; it was simply unreadable.
#
# Two behaviours, both narrow:
#   1. strip the OpenSSL banner -- it is on EVERY az call and is never actionable;
#   2. recognise RequestDisallowedByPolicy as a CLASS: print the target, the assignment, the
#      offending value, the permitted value and the action -- and print each assignment ONCE per
#      run, because the second and third denials teach nothing the first did not.
# Anything unrecognised falls through to the full raw text. A summariser that swallows an error it
# did not understand would be worse than the noise it replaces.
$script:PimPolicySeen = @{}

# 🔴 "INSUFFICIENT PRIVILEGES" AFTER THE PERMISSION WAS GRANTED -- AND THE GRANT IS FINE.
#
# Measured at a customer 2026-09-11. Three Microsoft Graph application permissions were granted and
# admin-consented to the deploy SPN; the appRoleAssignments were verified present, on Microsoft
# Graph, on the right principal. The very next deploy still failed:
#     az exit 1: ERROR: Insufficient privileges to complete the operation.
# five times over, creating the Easy Auth app registration.
#
# 🔑 THE ACCESS TOKEN PREDATED THE GRANT. az keeps an MSAL cache inside $AZURE_CONFIG_DIR, and a
# fresh `az login` does NOT discard a cached access token that has not expired -- so the deploy kept
# presenting a token whose `roles` claim was EMPTY, for up to an hour after the permission existed.
# Decoding the token from a clean config dir returned all three roles immediately.
#
# This reads exactly like "the grant did not work", and the natural response -- grant it again,
# check the consent, suspect the wrong principal -- is wasted on a directory that is already
# correct. So when Graph says this, SAY WHAT THE TOKEN ACTUALLY CARRIES. An empty roles claim is
# the whole diagnosis; a populated one means the permission genuinely is missing.
#
# 🪤 Read the token with the REAL az executable, not the shadow: this runs from inside the shadow's
# own failure handler, and a failure here would recurse. Said once per run -- the second occurrence
# teaches nothing, and this fires on every call in a retry loop.
$script:PimPrivHintSaid = $false
function Write-PimGraphPrivilegeHint {
    if ($script:PimPrivHintSaid) { return }
    $script:PimPrivHintSaid = $true
    $roles = $null
    try {
        $exe = Get-PimAzExecutable
        if (-not $exe) { return }
        $tok = & $exe account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
        $tok = "$tok".Trim()
        if (-not $tok -or ($tok -notmatch '\.')) { return }
        $seg = $tok.Split('.')[1].Replace('-', '+').Replace('_', '/')
        $seg = $seg.PadRight($seg.Length + ((4 - ($seg.Length % 4)) % 4), '=')
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json
        $roles = @($claims.roles)
    } catch { return }

    if (@($roles | Where-Object { "$_".Trim() }).Count) {
        Write-Host ("      the Graph token carries: {0}" -f ((@($roles) | Sort-Object) -join ', ')) -ForegroundColor Yellow
        Write-Host  '      -- so this operation needs one that is NOT in that list. Grant it and re-run.' -ForegroundColor Yellow
    } else {
        Write-Host  '      THE GRAPH TOKEN CARRIES NO APPLICATION PERMISSIONS AT ALL (empty roles claim).' -ForegroundColor Red
        Write-Host  '      If the permissions WERE granted, this is a STALE CACHED TOKEN, not a missing grant:' -ForegroundColor Yellow
        Write-Host  '      az caches access tokens in $AZURE_CONFIG_DIR and `az login` does not discard an' -ForegroundColor Yellow
        Write-Host  '      unexpired one, so a token minted before the consent keeps being presented.' -ForegroundColor Yellow
        Write-Host ("      -> point AZURE_CONFIG_DIR at a fresh directory and re-run (current: {0})" -f $(if ("$env:AZURE_CONFIG_DIR".Trim()) { $env:AZURE_CONFIG_DIR } else { '(default)' })) -ForegroundColor Yellow
        Write-Host  '         If the roles claim is still empty from a clean directory, the grant really is missing.' -ForegroundColor DarkGray
    }
}

function Write-PimAzFailure {
    param([string]$Text, [int]$Code)

    $t = ($Text -replace '(?s)[A-Za-z]:\\[^\s]*_util\.py:\d+:\s*UserWarning:.*?64-bit Python\.\s*', '').Trim()

    if ($t -notmatch 'RequestDisallowedByPolicy') {
        Write-Host ("    az exit {0}: {1}" -f $Code, $t) -ForegroundColor DarkYellow
        if ($t -match 'Insufficient privileges|Authorization_RequestDenied') { Write-PimGraphPrivilegeHint }
        return
    }

    $target = if ($t -match "Target:\s*([^\s,]+)") { $Matches[1] } else { '(resource)' }
    # Assignment name and the human definition title sit in the "Policy identifiers" JSON.
    $assignments = @([regex]::Matches($t, '"policyAssignment"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"') |
                        ForEach-Object { $_.Groups[1].Value })
    $definitions = @([regex]::Matches($t, '"policyDefinition"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"') |
                        ForEach-Object { $_.Groups[1].Value })
    if (-not $assignments) { $assignments = @('(unnamed assignment)') }

    Write-Host ("    BLOCKED BY AZURE POLICY: {0}" -f $target) -ForegroundColor Red
    for ($i = 0; $i -lt $assignments.Count; $i++) {
        $a = $assignments[$i]
        $d = if ($i -lt $definitions.Count) { $definitions[$i] } else { '' }
        if ($script:PimPolicySeen.ContainsKey($a)) {
            Write-Host ("      {0} -- same policy as before, see above" -f $a) -ForegroundColor DarkGray
            continue
        }
        $script:PimPolicySeen[$a] = $true
        Write-Host ("      assignment : {0}{1}" -f $a, $(if ($d) { "  ($d)" } else { '' })) -ForegroundColor Red

        # 🪤 NAME THE FIELD, NOT JUST THE POLICY. An assignment displayed as "Disable public network
        # access - SQL Databases" turned out to evaluate Microsoft.Sql/servers/publicNetworkAccess --
        # a SERVER property. Choosing which policy to exempt by reading its DISPLAY NAME therefore
        # sent an operator at the wrong one twice, at a customer, mid-deploy (2026-09-08). The
        # evaluatedExpressions block already says exactly which field failed and what it wanted;
        # printing it removes the guesswork the name creates.
        # The FIRST evaluated expression is almost always the resource-type match, which tells the
        # operator nothing -- skip it and report the one that actually differs.
        $field = $null; $saw = $null; $wanted = $null
        foreach ($m in [regex]::Matches($t, '"expression"\s*:\s*"([^"]+)"[\s\S]{0,200}?"expressionValue"\s*:\s*"([^"]+)"[\s\S]{0,120}?"targetValue"\s*:\s*(?:"([^"]+)"|\[([^\]]*)\])')) {
            if ($m.Groups[1].Value -eq 'type') { continue }
            $field  = $m.Groups[1].Value
            $saw    = $m.Groups[2].Value
            $wanted = if ($m.Groups[3].Success) { $m.Groups[3].Value }
                      else { ($m.Groups[4].Value -replace '"','' -replace '\s+',' ').Trim() }
            break
        }
        $allowed = if ($t -match '"listOfAllowedLocations"\s*:\s*\[\s*([^\]]+)\]') { ($Matches[1] -replace '"','' -replace '\s+',' ').Trim() } else { $null }

        if ($field) {
            Write-Host ("      field      : {0}" -f $field) -ForegroundColor Yellow
            Write-Host ("      this deploy sets '{0}'; the policy requires '{1}'" -f $saw, $wanted) -ForegroundColor Yellow
        }
        if ($allowed) {
            Write-Host ("      -> re-run with -Location {0}" -f ($allowed -split ',')[0].Trim()) -ForegroundColor Yellow
        }
        else {
            Write-Host  '      -> exempt THIS assignment for the subscription, or change the deploy to satisfy it' -ForegroundColor Yellow
            Write-Host  '         (exempt by ASSIGNMENT NAME above -- a policy display name can describe a' -ForegroundColor DarkGray
            Write-Host  '          different resource type than the field it actually evaluates)' -ForegroundColor DarkGray
        }
    }
    Write-Host  '      (full policy JSON suppressed -- re-run with -Verbose for the raw error)' -ForegroundColor DarkGray
    Write-Verbose ("az exit {0}: {1}" -f $Code, $t)
}

function ConvertTo-PimAzBatchArg {
    <#
    .SYNOPSIS
        §46.1a -- make ONE argument survive cmd.exe, for the case where `az` is a batch file.

    .DESCRIPTION
        🔴 THE MECHANISM, measured across three failures in one evening (§46.1):
        PowerShell only wraps a native-command argument in quotes when it contains WHITESPACE.
        `az` on Windows is **az.cmd**, a batch file, so an unquoted argument is then parsed by
        **cmd.exe**, which treats ( ) & | < > ^ as syntax:

            a query of  [?properties.active].name | [0]  -> az exit 255: -o was unexpected at this time
            a query of  reverse(sort_by([],&x))[0].name  -> invalid jmespath_type value: 'reverse(sort_by([],'
        (written without the --query prefix on purpose: the standing gate in Test-PimSetupHosting
        scans source for that prefix followed by a metacharacter, and an EXAMPLE of the defect
        must not read as an instance of it.)

        Nothing is wrong with JMESPath, az, or PowerShell -- each behaves as documented, and the
        COMPOSITION is what breaks. Worse, one of those failures returned a plausible-looking
        WRONG value (cmd echoed its prompt into the captured output and a revision name became a
        whole command line), which the auto-rollback then used.

        🔑 The rule this implements: if PowerShell will NOT quote it and cmd WOULD reparse it,
        quote it ourselves. Inside double quotes cmd treats every one of those characters as an
        ordinary character, and the batch file passes them through to az intact.

        🪤 A NEWLINE CANNOT BE FIXED BY QUOTING -- cmd TRUNCATES the command line at the first
        one. That is TEST-16: a multi-line --analytics-query reached Log Analytics as just the
        table name, every filter after line 1 silently DISCARDED, and it FAILED OPEN -- a broader
        result set still answers, so six assertions went green over unscoped logs. So this
        REFUSES instead, turning a silent wrong answer into a loud one.

        🔒 What it deliberately does NOT touch: arguments that already contain whitespace (which
        PowerShell quotes for us, so cmd already sees them as literal) or a double quote of their
        own (whose correct escaping depends on the call site's intent). The per-call-site rule --
        no ( ) & | < > ^ inside a --query, enforced by the standing gate in Test-PimSetupHosting
        -- stays exactly as it is. This is the belt to that pair of braces, not a replacement:
        it makes a call site that forgets the rule fail safely rather than silently.
    #>
    param([object]$Value, [switch]$ForBatch)
    $s = "$Value"
    if (-not $ForBatch) { return $s }
    if ($s -match "[`r`n]") {
        throw ("Invoke-PimAz: an argument contains a NEWLINE, and az here is a batch file (az.cmd) -- " +
               "cmd.exe truncates the command line at the first newline, so everything after it would be " +
               "SILENTLY DISCARDED and the call would still succeed with a wrong answer (TEST-16). Put the " +
               "value on ONE line. Argument began: '" + ($s -split "[`r`n]")[0] + "'")
    }
    # Whitespace -> PowerShell quotes it -> cmd already treats the metacharacters as literal.
    # An embedded double quote -> leave it exactly as the call site wrote it.
    if ($s -match '\s' -or $s.Contains('"')) { return $s }
    if ($s -match '[()&|<>^]') { return '"' + $s + '"' }
    return $s
}

function Invoke-PimAz {
    # Run the az CLI. Returns its STDOUT; sets $LASTEXITCODE; never lets stderr be fatal.
    #
    # 🪤 NO param() BLOCK AND NO [CmdletBinding()], DELIBERATELY. Both make PowerShell's
    # parameter binder read the az arguments as PowerShell ones, and az's short flags collide
    # with the common parameters:
    #     az ... -o tsv  ->  Parameter cannot be processed because the parameter name 'o' is
    #                        ambiguous. Possible matches include: -OutVariable -OutBuffer.
    # With no declared parameters every token lands in $args untouched, which is the only way
    # a shadow can be transparent to ~50 existing call sites.
    $AzArgs = $args
    $exe = Get-PimAzExecutable
    if (-not $exe) {
        # A missing CLI is a real problem, but it is the CALLER's to report -- the same way an
        # az that exits non-zero is. Signalling it as an exit code keeps every existing
        # `if ($LASTEXITCODE -ne 0)` correct instead of introducing a second failure channel.
        Write-Host '    az CLI not found on PATH (az.cmd / az.exe).' -ForegroundColor Yellow
        $global:LASTEXITCODE = 9009
        return
    }

    $prevEA = $ErrorActionPreference
    try {
        # 🔴 THE WHOLE POINT OF THIS FILE IS THIS ONE LINE.
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = 0

        # 🪤 `2>&1`, NOT `2>$errFile`. The first version redirected to a temp file, and the run
        # SURVIVED (that is the fix working) but the transcript filled with NativeCommandError
        # stack traces anyway -- 5.1 still raises the record, and the file redirect does not stop
        # it reaching the error stream. Measured on the first live run: ~20 KB of noise around a
        # successful deploy. An unattended job whose log is mostly stack traces from things that
        # did not go wrong is one nobody will read the night something does.
        # `2>&1` MERGES stderr into the output stream as ErrorRecords, so nothing is written to
        # the error stream at all; we then split them out ourselves and stay silent unless az
        # actually failed.
        # §46.1a. Only when the resolved CLI is a BATCH file is cmd.exe in the path at all --
        # az.exe takes its arguments straight from the Win32 command line and needs none of this.
        $isBatch = ("$exe" -match '\.(cmd|bat)$')
        $SafeArgs = @(foreach ($a in $AzArgs) { ConvertTo-PimAzBatchArg -Value $a -ForBatch:$isBatch })
        $raw  = & $exe @SafeArgs 2>&1
        $code = $LASTEXITCODE

        $out = New-Object System.Collections.Generic.List[object]
        $err = New-Object System.Collections.Generic.List[string]
        foreach ($item in @($raw)) {
            if ($item -is [System.Management.Automation.ErrorRecord]) { [void]$err.Add("$item") }
            else { [void]$out.Add($item) }
        }

        # Only a real failure is reported, and then in full -- so a genuine az error is MORE
        # visible than it was before the guard, not less.
        # 🔴 AND IT IS PUBLISHED, NOT ONLY PRINTED. Splitting stderr out of the returned value is
        # what makes this shadow quiet, but it also means a caller doing
        #     $out = az ... 2>&1 ; if ($LASTEXITCODE) { <inspect $out> }
        # gets an EMPTY $out and cannot tell WHY az failed -- only that it did. That is not
        # hypothetical: Resolve-PimMiAppId has carried a refusal check since 2026-09-08 ("a refusal
        # is not a delay -- waiting cannot grant a permission"), reading exactly that variable, and
        # under this shadow it could never fire. Measured at a customer 2026-09-11: a deploy SPN
        # with Owner and no Graph roles got "Insufficient privileges to complete the operation",
        # and the retry loop spent 120s concluding "a newly-created managed identity is eventually
        # consistent" -- the confident wrong diagnosis that check exists to prevent.
        # 🪤 CLEARED ON EVERY CALL, including successful ones. A stale error text read by a later
        # caller is worse than none: it attributes a failure to the wrong command.
        $global:PimAzLastError = ''
        if ($code -ne 0 -and $err.Count) {
            $global:PimAzLastError = ($err -join ' ').Trim()
            Write-PimAzFailure -Text $global:PimAzLastError -Code $code
        }

        $global:LASTEXITCODE = $code
        return $out.ToArray()
    } finally {
        $ErrorActionPreference = $prevEA
    }
}

# THE SHADOW. Declaring no parameters is deliberate: everything lands in $args untouched, so
# existing call sites -- including `@subArgs` splats and trailing `2>$null` -- keep working
# verbatim. Defined in the dot-sourcing script's scope, so it covers that script and anything
# it dot-sources, and nothing else on the machine.
function az { Invoke-PimAz @args }
