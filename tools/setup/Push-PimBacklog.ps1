#Requires -Version 5.1
<#
.SYNOPSIS
    PIM Manager (vendor) -- pushes PIM's backlog to Invardia's back office "Backlog" (framework BACKLOG-1). Dry run unless -Apply.

.DESCRIPTION
    Builds the snapshot from docs\REQUIREMENTS.md (tools\setup\Pim-Backlog.ps1: one item per open / in-progress line, its
    stage from the line's own words, grouped by chapter), checks it with the rules Invardia checks it with, writes the JSON
    body to -OutFile, and -- with -Apply -- sends it with PUT https://invardia.com/api/backlog/pim-manager as PIM's
    PUBLISHER identity (Invardia.Publisher.pim-manager, certificate only; the same Key Vault secrets as the release and
    community scripts). Invardia keeps every stage change as history. A push that would remove a large share of the open
    items is refused (409) unless -ConfirmRemovals.

      .\tools\setup\Push-PimBacklog.ps1                     # dry run: counts + the body file, nothing sent
      .\tools\setup\Push-PimBacklog.ps1 -Apply              # send

    VENDOR ONLY: nothing here runs at a customer. No modules and no az: REST (Invoke-WebRequest) only. Never prints the token.
#>
[CmdletBinding()]
param(
    [string]$RequirementsPath,
    [switch]$Apply,
    [switch]$ConfirmRemovals,
    [string]$OutFile,
    [int]$MaxGroups = 0,
    [string]$BaseUrl = 'https://invardia.com',
    # No real ids in shipped source (SEC-02) and no az (NO-AZ, 3.0.3): the vendor's tenant and PIM's publisher identity
    # (client id + certificate thumbprint) are passed in -- the machine-local wrapper C:\ProgramData\pim\ops\push-backlog.ps1
    # reads them from the vendor's Key Vault. Needed only with -Apply; a dry run reads the local file alone.
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$ApiResource = 'api://a5a57537-c847-482b-8878-9a229cbca61b'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Pim-Backlog.ps1')
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $RequirementsPath) { $RequirementsPath = Join-Path $solRoot 'docs\REQUIREMENTS.md' }
if (-not $OutFile) { $OutFile = Join-Path ([IO.Path]::GetTempPath()) 'pim-backlog-snapshot.json' }

$text = [IO.File]::ReadAllText($RequirementsPath, [Text.Encoding]::UTF8)
$b = New-PimBacklogSnapshot -RequirementsText $text -MaxGroups $MaxGroups
$problems = @(Test-PimBacklogSnapshot -Snapshot $b.Snapshot -MaxGroups $MaxGroups)
$json = $b.Snapshot | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
$stages = (@($b.Counts.Keys | Where-Object { $b.Counts[$_] }) | ForEach-Object { '{0} {1}' -f $b.Counts[$_], $_ }) -join ', '
$tags = (@($b.TagCounts.Keys | Where-Object { $b.TagCounts[$_] }) | ForEach-Object { '{0} {1}' -f $b.TagCounts[$_], $_ }) -join ', '
$summary = "{0} item(s) in {1} group(s); stages: {2}; tags: {3}; {4} id(s) by hash; body {5:N0} bytes -> {6}" -f $b.Items, $b.Groups, $stages, $(if ($tags) { $tags } else { 'none' }), $b.HashIds, ([Text.Encoding]::UTF8.GetByteCount($json)), $OutFile
foreach ($w in $b.Warnings) { Write-Warning $w }
if ($problems.Count) { throw ("the backlog is not fit to push -- nothing was sent:`n  " + (($problems | Select-Object -First 30) -join "`n  ")) }
if (-not $Apply) {
    Write-Host ("Backlog (dry run, nothing sent): {0}" -f $summary)
    return [pscustomobject]@{ Ok = $true; Sent = $false; Text = "dry run: $summary"; Items = $b.Items; Counts = $b.Counts; TagCounts = $b.TagCounts; Groups = $b.Groups }
}

if (-not "$TenantId".Trim()) { throw '-Apply needs -TenantId, -ClientId and -CertThumbprint (the vendor wrapper C:\ProgramData\pim\ops\push-backlog.ps1 passes them)' }
$cid = "$ClientId".Trim(); $thumb = "$CertThumbprint".Trim()
if ($cid -notmatch '^[0-9a-fA-F-]{36}$' -or $thumb -notmatch '^[0-9a-fA-F]{40}$') { throw '-Apply needs the publisher -ClientId (a GUID) and -CertThumbprint (40 hex characters)' }
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
$token = Get-PimRestToken -Resource $ApiResource -TenantId $TenantId -ClientId $cid -CertThumbprint $thumb -Force
$r = Send-PimBacklogSnapshot -Snapshot $b.Snapshot -Token $token -BaseUrl $BaseUrl -ConfirmRemovals:$ConfirmRemovals
$token = $null
Write-Host ("Backlog: {0} -- {1}" -f $summary, $r.Text)
[pscustomobject]@{ Ok = $r.Ok; Sent = $r.Ok; Status = $r.Status; Text = ("{0} ({1})" -f $r.Text, $summary); Items = $b.Items }
