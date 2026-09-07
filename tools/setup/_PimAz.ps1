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
        $raw  = & $exe @AzArgs 2>&1
        $code = $LASTEXITCODE

        $out = New-Object System.Collections.Generic.List[object]
        $err = New-Object System.Collections.Generic.List[string]
        foreach ($item in @($raw)) {
            if ($item -is [System.Management.Automation.ErrorRecord]) { [void]$err.Add("$item") }
            else { [void]$out.Add($item) }
        }

        # Only a real failure is reported, and then in full -- so a genuine az error is MORE
        # visible than it was before the guard, not less.
        if ($code -ne 0 -and $err.Count) {
            Write-Host ("    az exit {0}: {1}" -f $code, (($err -join ' ').Trim())) -ForegroundColor DarkYellow
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
