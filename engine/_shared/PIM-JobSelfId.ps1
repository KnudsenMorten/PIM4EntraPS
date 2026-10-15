#Requires -Version 5.1
<#
.SYNOPSIS
    PIM 100.166 (a) / framework 12.24 -- the UPDATER's half of "pull / publish read their own run status": existing jobs
    learn their own resource id (PIM_JobId) and get 'Reader' on themselves. Its own file, loaded ONLY by the updater
    (tools/pim-engine/update-job-entry.ps1): PIM-TenantSizing.ps1 is embedded in customer-run scripts (Set-PimSqlTier.ps1),
    which must not carry a role-assignment they never run (Test-PimScriptDocs B2). Needs PIM-TenantSizing.ps1 (its ACA api
    version) and PIM-ArmContainerApps.ps1 (Invoke-PimArmBusyRetry) loaded first. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimJobSelfReaderAssignmentName {
    <# PURE. A stable role-assignment name (GUID) for "<principal> is Reader on <job>", so a repeated PUT is idempotent. #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $h = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(("{0}|{1}|reader" -f "$Scope".ToLowerInvariant(), "$PrincipalId".ToLowerInvariant()))) } finally { $md5.Dispose() }
    return ([guid]::new($h)).ToString()
}

function Invoke-PimJobSelfIdUpdate {
    <#
      framework 12.24 / PIM 100.166 (a), EXISTING installs: the managed-tenant pull and the publish job learn their OWN resource
      id (env PIM_JobId), so their cadence gate can read the status of an earlier run instead of the 6-hour fallback; and
      their identity gets 'Reader' on the job itself (the tick's BUG-268 right, scope = that job only).
      A job is one of them when its container runs downlink-job-entry.ps1 or publish-job-entry.ps1 (name-independent).
      * The env: one PATCH (configuration WITHOUT secrets + the template as read, PIM_JobId added) only when it is missing or
        wrong. Busy is waited out (Invoke-PimArmBusyRetry), then left for the next update.
      * The grant: an idempotent PUT under a stable name; 409 RoleAssignmentExists = already; a refusal (the updater may not
        assign roles -- framework 12.23 P9: nothing routine needs an admin) is a plain NOTE, never a failure.
      Never throws. Returns @{ ok; envSet[]; granted[]; notes[]; detail; log[] }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][scriptblock]$Arm, [int[]]$BusyWaits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep)
    $log = New-Object System.Collections.Generic.List[string]
    $envSet = New-Object System.Collections.Generic.List[string]; $granted = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]; $failed = $false
    $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs"
    try { $list = & $Arm 'GET' "$base`?api-version=$($script:PimTenantSizingAcaApi)" $null }
    catch { return [pscustomobject]@{ ok = $false; envSet = @(); granted = @(); notes = @(); detail = "own run status: the jobs could not be listed ($((("$($_.Exception.Message)") -split "`n")[0]))"; log = @() } }
    $isOurs = { param($jo) foreach ($c in @($jo.properties.template.containers)) { $t = (@($c.command) + @($c.args)) -join ' '; if ($t -match '(?i)(downlink|publish)-job-entry\.ps1') { return $true } }; return $false }
    foreach ($j in @(@($list.value) | Where-Object { $_ -and (& $isOurs $_) })) {
        $name = "$($j.name)"; $id = "$base/$name"; $path = "$id`?api-version=$($script:PimTenantSizingAcaApi)"
        # ---- the env ----
        $ci = -1; $k = 0
        foreach ($c in @($j.properties.template.containers)) { if (((@($c.command) + @($c.args)) -join ' ') -match '(?i)(downlink|publish)-job-entry\.ps1') { $ci = $k; break }; $k++ }
        $cur = @(@($j.properties.template.containers)[$ci].env | Where-Object { "$($_.name)" -eq 'PIM_JobId' } | Select-Object -First 1)
        if ($cur.Count -and "$($cur[0].value)" -ieq $id) { $log.Add("${name}: PIM_JobId already set") }
        else {
            try {
                [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write {
                    $jw = & $Arm 'GET' $path $null
                    if (-not $jw) { throw "job '$name' not found" }
                    $cw = @($jw.properties.template.containers)[$ci]
                    $ev = @(@($cw.env) | Where-Object { $_ -and "$($_.name)" -ne 'PIM_JobId' }) + @([pscustomobject]@{ name = 'PIM_JobId'; value = $id })
                    $cw | Add-Member -NotePropertyName env -NotePropertyValue $ev -Force
                    $cfg = [ordered]@{}
                    foreach ($p in @($jw.properties.configuration.PSObject.Properties)) { if ($p.Name -ne 'secrets') { $cfg[$p.Name] = $p.Value } }
                    & $Arm 'PATCH' $path @{ properties = @{ configuration = $cfg; template = $jw.properties.template } } })
                $envSet.Add($name); $log.Add("${name}: PIM_JobId set (its next run can read the status of its own earlier runs)")
            } catch {
                $failed = $true
                $m = (("$($_.Exception.Message)") -split "`n")[0]
                $log.Add($(if ($m -match '(?i)OperationInProgress|active provisioning operation') { "${name}: busy -- PIM_JobId set on the next update" } else { "${name}: PIM_JobId NOT set ($m)" }))
            }
        }
        # ---- the grant ----
        $oid = ''
        $miCid = "$(@(@(@($j.properties.template.containers)[$ci].env) | Where-Object { "$($_.name)" -eq 'PIM_ManagedIdentityClientId' } | Select-Object -First 1).value)".Trim()
        if ($miCid -and $j.identity.userAssignedIdentities) {
            foreach ($p in @($j.identity.userAssignedIdentities.PSObject.Properties)) { if ("$($p.Value.clientId)" -ieq $miCid) { $oid = "$($p.Value.principalId)".Trim() } }
        }
        if (-not $oid) { $oid = "$($j.identity.principalId)".Trim() }
        if (-not $oid) { $notes.Add("${name}: no identity to grant 'Reader' on itself"); continue }
        $an = Get-PimJobSelfReaderAssignmentName -Scope $id -PrincipalId $oid
        $body = @{ properties = @{ roleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"; principalId = $oid; principalType = 'ServicePrincipal' } }
        try {
            [void](& $Arm 'PUT' "$id/providers/Microsoft.Authorization/roleAssignments/$an`?api-version=2022-04-01" $body)
            $granted.Add($name); $log.Add("${name}: 'Reader' on itself ensured")
        } catch {
            $m = (("$($_.Exception.Message)") -split "`n")[0]
            if ($m -match '(?i)RoleAssignmentExists|\b409\b') { $log.Add("${name}: 'Reader' on itself already assigned") }
            else { $notes.Add("${name}: 'Reader' on itself is not assigned and this updater may not assign it ($m) -- the job keeps the 6-hour fallback; a redeploy of $name grants it") }
        }
    }
    $detail = ('own run status: PIM_JobId set on {0}{1}; Reader ensured on {2}{3}' -f $envSet.Count, $(if ($envSet.Count) { " ($($envSet -join ', '))" } else { '' }), $granted.Count, $(if ($notes.Count) { "; $($notes.Count) note(s)" } else { '' }))
    return [pscustomobject]@{ ok = (-not $failed); envSet = @($envSet.ToArray()); granted = @($granted.ToArray()); notes = @($notes.ToArray()); detail = $detail; log = @($log.ToArray()) }
}

