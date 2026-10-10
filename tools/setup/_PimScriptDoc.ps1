#Requires -Version 5.1
<#
.SYNOPSIS
    Framework 12.7 SCRIPT-DOC-1 + 12.10 item 11 -- the ONE place that knows where a PIM script's documentation page,
    download and checksum list live, the command form every surface shows (save, verify, preview, run), and the run
    frame every script a person runs uses (the first line "<Script> version <x.y.z> - documentation: <page>",
    REQUIREMENTS 100.52, and a local transcript).

.DESCRIPTION
    PURE except Start-PimScriptRun / Stop-PimScriptRun (they print and start / stop a transcript in the temp folder).
    Loaded by every in-scope script (tools\setup + tools\pim-activator), by Build-PimSupportScripts.ps1 (it inlines this
    file into each standalone), by the Manager (Open-PimManager.ps1 hands the constants to the page) and by the engine
    libraries that build fix commands (PIM-PermissionHealth, PIM-MailTransport, PIM-WorkloadPrereqs).
    Change a URL HERE and only here: tests\Test-PimScriptDocs.ps1 fails on any script whose .LINK, page constant or
    manifest docUrl disagrees with it.

    The in-scope list ($script:PimScriptDocScripts) is the set of scripts a person runs that 12.7 covers: each has a
    manifest tools\setup\script-docs\<Script>.doc.json, a .LINK to its page, the Documentation line, -WhatIf, and a
    -WhatIf run case under tests\script-docs\.
#>

# --- the constants (Invardia confirmed 2026-10-09: page = <base><Script>/ with a trailing slash; index = <base>) -------
$script:PimScriptDocBaseUrl     = 'https://invardia.com/docs/pim/scripts/'
$script:PimSupportScriptBaseUrl = 'https://invardia.com/support/pim/'
$script:PimSupportScriptSumsUrl = 'https://invardia.com/support/pim/SHA256SUMS.txt'

# --- the version the banner names (REQUIREMENTS 100.52, owner 2026-10-10: "do you provide the version in all scripts, so i
# can troubleshoot better"). Build-PimSupportScripts.ps1 rewrites the NEXT line in a standalone file to the version it was
# built from (the marker comment is what it looks for); in the repository it stays empty and Get-PimScriptVersion reads
# the solution's VERSION file next to this helper (tools\setup\..\..\VERSION).
$script:PimScriptDocVersion = ''   # BUILD-VERSION
$script:PimScriptDocHelperDir = "$PSScriptRoot"

# --- every script 12.7 covers: path relative to tools\ ; Standalone = published as one file by Build-PimSupportScripts --
$script:PimScriptDocScripts = @(
    @{ Path = 'setup/Initialize-PimSqlAdminGroup.ps1';             Standalone = $true }
    @{ Path = 'pim-activator/Deploy-PimActivatorBackend.ps1';      Standalone = $true }
    @{ Path = 'pim-activator/Publish-PimActivatorRemediation.ps1'; Standalone = $true }
    @{ Path = 'pim-activator/Deploy-PimActivatorClient.ps1';       Standalone = $true }
    @{ Path = 'setup/Grant-PimEnginePermissions.ps1';              Standalone = $true }
    @{ Path = 'setup/Initialize-PimWorkloadPrereqs.ps1';           Standalone = $true }
    @{ Path = 'setup/Initialize-PimMailSender.ps1';                Standalone = $true }
    @{ Path = 'setup/Set-PimSmtpRelayPassword.ps1';                Standalone = $true }
    @{ Path = 'setup/Set-PimSqlTier.ps1';                          Standalone = $true }
    @{ Path = 'setup/New-PimHubPrepareScript.ps1';                 Standalone = $true }
    @{ Path = 'setup/Install-PimManager.ps1';                      Standalone = $false }
    @{ Path = 'setup/Invoke-PimDeployAll.ps1';                     Standalone = $false }
    @{ Path = 'setup/Invoke-PimMspBuild.ps1';                      Standalone = $false }
    @{ Path = 'setup/Copy-PimSettings.ps1';                        Standalone = $false }
    @{ Path = 'setup/Set-PimManagerAccess.ps1';                    Standalone = $false }
    @{ Path = 'setup/Set-PimBreakGlassAccounts.ps1';               Standalone = $false }
    @{ Path = 'setup/Set-PimEmergencyPassphrase.ps1';              Standalone = $false }
    @{ Path = 'setup/Find-PimStrayTestObjects.ps1';                Standalone = $false }
    @{ Path = 'setup/Set-PimLicense.ps1';                          Standalone = $false }
    @{ Path = 'pim-activator/Deploy-PimActivatorHybrid.ps1';       Standalone = $false }
    @{ Path = 'setup/Update-PimCommunity.ps1';                     Standalone = $false }
    @{ Path = 'setup/Grant-PimSupportAccess.ps1';                  Standalone = $false }
    @{ Path = 'setup/Confirm-PimInstall.ps1';                      Standalone = $false }
    @{ Path = 'setup/Set-PimManagerCustomHost.ps1';                Standalone = $false }
    @{ Path = 'setup/Deploy-PimRfaBroker.ps1';                     Standalone = $false }
    @{ Path = 'setup/Rebuild-PimEnvInternal.ps1';                  Standalone = $false }
    @{ Path = 'setup/Rebuild-PimEnvExternal.ps1';                  Standalone = $false }
    @{ Path = 'setup/Remove-PimContainerStack.ps1';                Standalone = $false }
    @{ Path = 'setup/New-PimHostingPrerequisites.ps1';             Standalone = $false }
)

function Get-PimScriptDocName {
    # PURE. 'Grant-PimEnginePermissions.ps1' / '.\x\Grant-PimEnginePermissions' -> 'Grant-PimEnginePermissions'.
    param([Parameter(Mandatory)][string]$Script)
    $leaf = "$Script".Trim() -replace '^.*[\\/]', ''
    return ($leaf -replace '(?i)\.ps1$', '')
}

function Get-PimScriptDocUrl {
    # PURE. The script's documentation page at Invardia: <base><Script>/ (no .ps1, trailing slash).
    param([Parameter(Mandatory)][string]$Script)
    return ($script:PimScriptDocBaseUrl + (Get-PimScriptDocName -Script $Script) + '/')
}

function Get-PimSupportScriptUrl {
    # PURE. The published standalone copy: <support base><Script>.ps1.
    param([Parameter(Mandatory)][string]$Script)
    return ($script:PimSupportScriptBaseUrl + (Get-PimScriptDocName -Script $Script) + '.ps1')
}

function Get-PimSupportScriptCommand {
    <#
      PURE. The lines every surface shows for a published script (12.10 item 11: save, verify, read, run -- never
      pipe-to-execute), in this order:
        Invoke-WebRequest <url> -OutFile <Script>.ps1                                        (save)
        <checksum check against the published SHA256SUMS.txt -- throws when it does not match> (verify)
        <the signature status, on Windows>                                                     (verify)
        # What does this script do? <doc page>   (add -WhatIf to preview every change)        (read)
        <-Run lines>                                                                           (run)
      The run line is LAST on purpose: callers that append parameters to the returned text extend the run line.
      -Run: the command line(s) that run the saved file, e.g. ".\Grant-PimEnginePermissions.ps1 -TenantId '...'";
      none = ".\<Script>.ps1". Returns string[] (join with a newline to show / send).
    #>
    param([Parameter(Mandatory)][string]$Script, [string[]]$Run = @())
    $name = Get-PimScriptDocName -Script $Script
    $file = "$name.ps1"
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Invoke-WebRequest $(Get-PimSupportScriptUrl -Script $name) -OutFile $file")
    $lines.Add("`$sum = @(((Invoke-RestMethod $($script:PimSupportScriptSumsUrl)) -split '\r?\n') -match '\s$([regex]::Escape($file))$')[0] -replace '\s.*$', ''; if (-not `$sum -or (Get-FileHash .\$file -Algorithm SHA256).Hash -ne `$sum) { throw 'Checksum mismatch -- do not run $file' }")
    $lines.Add("if (`$IsWindows -ne `$false) { (Get-AuthenticodeSignature .\$file).Status }")
    $lines.Add("# What does this script do? $(Get-PimScriptDocUrl -Script $name)   (add -WhatIf to preview every change)")
    $runs = @(@($Run) | Where-Object { "$_".Trim() })
    if (-not $runs.Count) { $runs = @(".\$file") }
    foreach ($r in $runs) { $lines.Add("$r") }
    return $lines.ToArray()
}

function Get-PimScriptVersion {
    # The PIM version this script is: the build stamp in a standalone file, else the solution's VERSION file (resolved
    # from this helper's folder), else 'unknown' (a copied helper with nothing around it -- never a failure).
    param([string]$Stamp = "$($script:PimScriptDocVersion)", [string]$HelperDir = "$($script:PimScriptDocHelperDir)")
    if ("$Stamp".Trim()) { return "$Stamp".Trim() }
    if ("$HelperDir".Trim()) {
        try {
            $vf = Join-Path (Split-Path (Split-Path $HelperDir -Parent) -Parent) 'VERSION'
            if (Test-Path -LiteralPath $vf -PathType Leaf) {
                $v = "$([IO.File]::ReadAllText($vf))".Trim()
                if ($v) { return $v }
            }
        } catch { }
    }
    return 'unknown'
}

function Get-PimScriptBannerText {
    # PURE. The banner line: "<Script> version <x.y.z> - documentation: <doc page>".
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$Version)
    $name = Get-PimScriptDocName -Script $Script
    return ('{0} version {1} - documentation: {2}' -f $name, $Version, (Get-PimScriptDocUrl -Script $name))
}

function Write-PimScriptBanner {
    <#
      REQUIREMENTS 100.52: the FIRST line every script a person runs prints -- its own name, version and documentation
      page -- so a transcript a customer sends shows exactly what ran. Called by Start-PimScriptRun (every in-scope script
      calls that first thing after loading its helpers), so it is written once, here.
      Write-Host = the host / Information stream: Start-Transcript records it, the pipeline (JSON, -PassThru) never sees
      it, -WhatIf does not change it.
      Printed by the OUTERMOST script only: a script called by another in the same process (the owner flag is set until
      the outer one's Stop-PimScriptRun) or in a child process it started (PIM_SCRIPT_BANNER_PID names a live parent)
      prints nothing. Returns $true when it printed.
    #>
    param([Parameter(Mandatory)][string]$Script)
    $name = Get-PimScriptDocName -Script $Script
    if ("$($global:PimScriptBannerOwner)") { return $false }
    $parentPid = 0
    if ([int]::TryParse("$env:PIM_SCRIPT_BANNER_PID", [ref]$parentPid) -and $parentPid -gt 0 -and $parentPid -ne $PID) {
        if (Get-Process -Id $parentPid -ErrorAction SilentlyContinue) { return $false }
    }
    $global:PimScriptBannerOwner = $name
    $env:PIM_SCRIPT_BANNER_PID = "$PID"
    Write-Host (Get-PimScriptBannerText -Script $name -Version (Get-PimScriptVersion))
    return $true
}

function Start-PimScriptRun {
    <#
      12.7 + 12.10 item 11: call it right after the param block / helper loading, BEFORE anything else prints.
      Starts a transcript in <temp>\pim-manager-logs\<Script>-<utc>.log (nothing else on disk; the temp folder is the
      one place -WhatIf may write) and prints, as the first line, the banner (Write-PimScriptBanner, REQUIREMENTS 100.52:
      "<Script> version <x.y.z> - documentation: <doc page>"; the outermost script only), then "Log: <path>".
      Nested runs (one in-scope script calling another in the same process) keep the outer transcript.
      Returns the log path ('' when the transcript could not start -- the run goes on, with a warning).
      Scripts print no secret values (SECRET-IN-OUTPUT audit), so the transcript holds none either.
    #>
    param([Parameter(Mandatory)][string]$Script)
    $name = Get-PimScriptDocName -Script $Script
    $path = ''
    if ("$($global:PimScriptRunLog)") {
        $path = "$($global:PimScriptRunLog)"
    } elseif ("$env:PIM_SCRIPT_NO_TRANSCRIPT" -ne '1') {
        try {
            $dir = Join-Path ([IO.Path]::GetTempPath()) 'pim-manager-logs'
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -Confirm:$false | Out-Null }
            $path = Join-Path $dir ('{0}-{1}.log' -f $name, [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
            Start-Transcript -LiteralPath $path -Append -WhatIf:$false -Confirm:$false | Out-Null
            $global:PimScriptRunLog = $path
            $global:PimScriptRunOwner = $name
        } catch { $path = '' }
    }
    $null = Write-PimScriptBanner -Script $name   # 100.52: "<Script> version <x.y.z> - documentation: <page>" (outermost only)
    if ($path) { Write-Host "Log: $path" } elseif ("$env:PIM_SCRIPT_NO_TRANSCRIPT" -ne '1') { Write-Warning 'No transcript could be started for this run.' }
    return $path
}

function Stop-PimScriptRun {
    # Call it in the script's finally block: prints "Log written: <path>" and stops the transcript this script started.
    param([Parameter(Mandatory)][string]$Script)
    $name = Get-PimScriptDocName -Script $Script
    if ("$($global:PimScriptBannerOwner)" -eq $name) {
        # 100.52: the outermost script is done -- the next script run in this session prints its banner again
        $global:PimScriptBannerOwner = $null
        if ("$env:PIM_SCRIPT_BANNER_PID" -eq "$PID") { $env:PIM_SCRIPT_BANNER_PID = $null }
    }
    if (-not "$($global:PimScriptRunLog)" -or "$($global:PimScriptRunOwner)" -ne $name) { return }
    $path = "$($global:PimScriptRunLog)"
    Write-Host "Log written: $path"
    try { Stop-Transcript | Out-Null } catch { }
    $global:PimScriptRunLog = $null
    $global:PimScriptRunOwner = $null
}
