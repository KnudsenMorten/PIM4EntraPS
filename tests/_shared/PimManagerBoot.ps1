#Requires -Version 5.1
<#
.SYNOPSIS
    Shared Manager-boot helper for the PIM4EntraPS test harness.

.DESCRIPTION
    ROOT-FIX for the recurring test stall: the boot tests used to bind FIXED ports
    (8799 / 8804 / 8811 / 8822 / 8833 / ...). Two concurrent runs -- or a leftover
    zombie Manager from a prior crashed run -- would collide on the same port and the
    suite would HANG waiting for a token that never came.

    This helper instead boots Open-PimManager.ps1 with -Port 0, which makes the
    Manager allocate a FREE loopback port at runtime (its own Get-FreeTcpPort) and
    print `loopback listening on http://127.0.0.1:<port>/`. We parse the ACTUAL bound
    port + the session token from stdout and hand both back, so the client URL always
    targets the real port. Two runs (or a zombie on an old port) can never collide.

    Belt-and-braces:
      * Get-PimFreeTcpPort -- allocate a free TCP port (port 0 -> read assigned ->
        release) for callers that must know a port BEFORE boot. PS 5.1-safe
        (System.Net.Sockets.TcpListener).
      * Stop-PimStaleManagers -- best-effort kill of leftover headless Manager
        processes from a prior run, so a zombie never holds a port or muddies stdout.
      * Start-PimManagerForTest tears nothing down itself; callers MUST call
        Stop-PimManagerForTest in a finally (the per-test pattern) so no zombies leak.

    PS 5.1-compatible throughout (no ?./??, no ConvertFrom-Json -AsHashtable reliance).
#>

# ---------------------------------------------------------------------------
# Get-PimFreeTcpPort -- bind a TcpListener on loopback:0, read the OS-assigned
# port, release it, and return the number. Mirrors the product's Get-FreeTcpPort
# (Open-PimManager.ps1) so the test harness picks ports the same way the Manager
# does. There is an inherent (tiny) TOCTOU window between release + rebind; the
# preferred path is -Port 0 (let the Manager bind+report), but this is here for
# callers that genuinely need a number up front.
# ---------------------------------------------------------------------------
function Get-PimFreeTcpPort {
    $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
    $l.Start()
    try { return ([System.Net.IPEndPoint]$l.LocalEndpoint).Port }
    finally { $l.Stop() }
}

# ---------------------------------------------------------------------------
# Stop-PimStaleManagers -- kill leftover headless Open-PimManager.ps1 processes
# from a prior (crashed/aborted) run so they don't hold a port or leak a token
# into a fresh run's stdout. Matches on the command line referencing the Manager
# script. Best-effort: never throws, never touches non-Manager powershell.exe.
# ---------------------------------------------------------------------------
function Stop-PimStaleManagers {
    [CmdletBinding()] param([int[]]$ExcludePid = @())
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            if ($ExcludePid -contains [int]$p.ProcessId) { continue }
            if ([int]$p.ProcessId -eq $PID) { continue }
            $cl = "$($p.CommandLine)"
            if ($cl -match 'Open-PimManager\.ps1' -and $cl -match '(-Server\b|-NoLaunch\b)') {
                try { Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    } catch {}
}

# ---------------------------------------------------------------------------
# Start-PimManagerForTest -- boot Open-PimManager.ps1 headless on a DYNAMIC free
# port and wait until it reports BOTH the bound port and the session token on
# stdout. Returns a context object:
#     @{ Process; Port; Token; BaseUrl; Headers; StdoutPath; StderrPath }
# so the caller probes the REAL port the Manager bound, never a guessed one.
#
# Parameters mirror the per-test boot lines:
#   -ManagerPath  full path to Open-PimManager.ps1 (required)
#   -ExtraArgs    additional script args (e.g. -Instance <name>, -ConfigRoot <dir>)
#   -StdoutPath   where to redirect stdout (a unique temp path; required)
#   -TimeoutSec   how long to wait for the token/port (default 30)
#
# It does NOT take a fixed -Port: it always boots with -Port 0 so the Manager
# binds a free loopback port and prints it -- the collision-proof path. If the
# Manager somehow can't bind (its own 10-attempt retry exhausts), it exits and we
# report the failure instead of hanging.
# ---------------------------------------------------------------------------
function Start-PimManagerForTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManagerPath,
        [string[]]$ExtraArgs = @(),
        [Parameter(Mandatory)][string]$StdoutPath,
        [int]$TimeoutSec = 30
    )
    if (-not (Test-Path -LiteralPath $ManagerPath)) { throw "Manager script not found: $ManagerPath" }

    $errPath = "$StdoutPath.err"
    Get-ChildItem "$StdoutPath*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    # -Port 0 => the Manager allocates + reports a FREE loopback port (no collision).
    $psargs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$ManagerPath`"",'-Server','-NoLaunch','-Port','0')
    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) { $psargs += $ExtraArgs }

    $proc = Start-Process powershell.exe -ArgumentList $psargs -RedirectStandardOutput $StdoutPath -RedirectStandardError $errPath -PassThru -WindowStyle Hidden

    $token = $null
    $boundPort = 0
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $StdoutPath) {
            $txt = Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue
            if ($txt) {
                if ($boundPort -le 0) {
                    $pm = [regex]::Match($txt, 'listening on http://(?:127\.0\.0\.1|localhost):(\d+)/')
                    if ($pm.Success) { $boundPort = [int]$pm.Groups[1].Value }
                }
                if (-not $token) {
                    $tm = [regex]::Match($txt, 'session token:\s*([0-9a-fA-F\-]{16,})')
                    if ($tm.Success) { $token = $tm.Groups[1].Value }
                }
                if ($token -and $boundPort -gt 0) { break }
            }
        }
        if ($proc.HasExited) { Start-Sleep -Milliseconds 300; break }
    }

    $base = if ($boundPort -gt 0) { "http://127.0.0.1:$boundPort" } else { $null }
    return [pscustomobject]@{
        Process    = $proc
        Port       = $boundPort
        Token      = $token
        BaseUrl    = $base
        Headers    = if ($token) { @{ Authorization = "Bearer $token" } } else { @{} }
        StdoutPath = $StdoutPath
        StderrPath = $errPath
    }
}

# ---------------------------------------------------------------------------
# Stop-PimManagerForTest -- tear down a context from Start-PimManagerForTest:
# stop the process (if still alive) and remove its stdout/stderr files. Safe to
# call with $null or a partial context; never throws. Call this in a finally.
# ---------------------------------------------------------------------------
function Stop-PimManagerForTest {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Context)
    process {
        if (-not $Context) { return }
        try { if ($Context.Process -and -not $Context.Process.HasExited) { Stop-Process -Id $Context.Process.Id -Force -ErrorAction SilentlyContinue } } catch {}
        try { if ($Context.StdoutPath) { Get-ChildItem "$($Context.StdoutPath)*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue } } catch {}
    }
}
