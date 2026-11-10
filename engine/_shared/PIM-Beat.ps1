# PIM-Beat.ps1 -- QUIESCE-DIED-1 step (1) (framework 8.18 option (a), Invardia 2026-11-10): a PROCESS liveness beat for every
# PIM container job. A .NET timer (C#, its own thread-pool thread, NO PowerShell runspace) writes ONE stdout line every
# PIM_BEAT_SECONDS (default 300) -- "[beat] alive <execution> step=<step> up=<min>m" -- whatever the main thread is blocked on
# (a Graph Retry-After wait, an unlabelled batch read, a silent ARM poll). stdout = the container console = Log Analytics
# ContainerAppConsoleLogs_CL, which is what the died rule reads. A beat proves the PROCESS is alive, nothing more.
# Only inside a Container Apps job execution (CONTAINER_APP_JOB_EXECUTION_NAME set); PIM_BEAT_SECONDS=0 turns it off.
# Never fails the job: every call is wrapped; a beat that cannot start says so once and the job goes on.

function Get-PimBeatDefaultSeconds { <# PURE. LITERAL. The beat interval when PIM_BEAT_SECONDS is not set. #> return 300 }

function Get-PimBeatSeconds {
    <# PURE. -Value = PIM_BEAT_SECONDS. '' -> the default; '0' -> 0 (off); a number 30..900 -> it; anything else -> the default. #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return (Get-PimBeatDefaultSeconds) }
    $n = 0
    if (-not [int]::TryParse($v, [ref]$n)) { return (Get-PimBeatDefaultSeconds) }
    if ($n -eq 0) { return 0 }
    if ($n -lt 30 -or $n -gt 900) { return (Get-PimBeatDefaultSeconds) }
    return $n
}

function Format-PimBeatLine {
    <# PURE. The one beat line (the C# timer writes the same shape; Test-PimBeat compares them). #>
    param([string]$Execution, [string]$Step, [int]$UpMinutes)
    $s = $(if ("$Step".Trim()) { "$Step".Trim() } else { '-' })
    return "[beat] alive $Execution step=$s up=$($UpMinutes)m"
}

$script:PimBeatTypeSource = @'
using System;
using System.Threading;
public static class PimProcessBeat {
    private static Timer _timer;
    private static string _exec = "";
    private static volatile string _step = "-";
    private static DateTime _start;
    private static readonly object _gate = new object();
    public static bool Running { get { return _timer != null; } }
    public static string Line() {
        int up = (int)Math.Floor((DateTime.UtcNow - _start).TotalMinutes);
        return "[beat] alive " + _exec + " step=" + _step + " up=" + up + "m";
    }
    private static void Tick(object state) {
        try { lock (_gate) { Console.Out.WriteLine(Line()); Console.Out.Flush(); } } catch { }
    }
    public static void Start(string execution, int seconds) {
        lock (_gate) {
            if (_timer != null) { return; }
            _exec = execution ?? ""; _start = DateTime.UtcNow;
            _timer = new Timer(Tick, null, seconds * 1000, seconds * 1000);
        }
    }
    public static void SetStep(string step) { _step = String.IsNullOrWhiteSpace(step) ? "-" : step.Trim(); }
    public static void Stop() { lock (_gate) { if (_timer != null) { _timer.Dispose(); _timer = null; } } }
}
'@

function Start-PimBeat {
    <#
      Starts the process beat once (a second call is a no-op). -Execution defaults to CONTAINER_APP_JOB_EXECUTION_NAME; with
      none (a local / test run) nothing starts. Returns @{ started; seconds; reason }. Never throws.
    #>
    param([string]$Execution = "$([Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME'))",
          [AllowEmptyString()][AllowNull()][string]$Seconds = "$([Environment]::GetEnvironmentVariable('PIM_BEAT_SECONDS'))")
    $out = [ordered]@{ started = $false; seconds = 0; reason = '' }
    try {
        $x = "$Execution".Trim()
        if (-not $x) { $out.reason = 'not a container job execution -- no beat'; return [pscustomobject]$out }
        $sec = Get-PimBeatSeconds -Value $Seconds
        $out.seconds = $sec
        if ($sec -eq 0) { $out.reason = 'PIM_BEAT_SECONDS=0 -- the beat is off'; return [pscustomobject]$out }
        if (-not ('PimProcessBeat' -as [type])) { Add-Type -TypeDefinition $script:PimBeatTypeSource -Language CSharp -ErrorAction Stop }
        [PimProcessBeat]::Start($x, $sec)
        $out.started = [bool][PimProcessBeat]::Running
        $out.reason = "a liveness line every $sec s (QUIESCE-DIED-1)"
    } catch { $out.reason = "the beat could not start ($((("$($_.Exception.Message)") -split "`n")[0])) -- the job goes on" }
    return [pscustomobject]$out
}

function Set-PimBeatStep {
    <# Names what the job is doing now, for the next beat line. A no-op when the beat is not running. Never throws. #>
    param([string]$Step)
    try { if (('PimProcessBeat' -as [type]) -and [PimProcessBeat]::Running) { [PimProcessBeat]::SetStep("$Step") } } catch { }
}

function Stop-PimBeat {
    <# Stops the beat (end of the job). Never throws. #>
    try { if ('PimProcessBeat' -as [type]) { [PimProcessBeat]::Stop() } } catch { }
}
