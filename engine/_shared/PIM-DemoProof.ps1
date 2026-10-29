#Requires -Version 5.1
<#
.SYNOPSIS
  REQUIREMENTS s98 (live demo environment) -- THE ONE PROOF that an environment is the internal demo one.

.DESCRIPTION
  Moved here unchanged (s98.3, 2026-10-29) from the demo dataset module, so that the scheduler's 'demo-baseline-restore'
  job can REQUIRE the same proof the demo setup scripts use, without loading the dataset module (which no engine file and
  no scheduler may load -- Test-PimImpactCounters F5). The dataset module dot-sources this file, so every caller it had
  keeps the same functions.

  Positive proof required -- anything unsure is a refusal:
    * the update ring must be RECORDED and be 0 or 1 (2 / 3 = customer rings; not recorded or unreadable = unsure);
    * a licence must be stored, verify (Valid or Grace), and name an internal / demo licensee.
  PURE except Get-PimDemoEnvironmentProof, whose two reads have test seams (-ReadRing / -ReadLicence).
  Windows PowerShell 5.1 + pwsh 7. ASCII only.
#>

$script:PimDemoAllowedCustomerPattern = '(?i)\b(internal|demo)\b'

function Get-PimDemoAllowedCustomerPatternDefault { '(?i)\b(internal|demo)\b' }

function ConvertTo-PimDemoRingNumber {
    <# PURE. '1' / 'ring1' / ' Ring 1 ' -> 1; anything else -> $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ("$Value" -match '^\s*(?i:ring)?\s*([0-3])\s*$') { return [int]$Matches[1] }
    return $null
}

function Get-PimDemoModeEligibility {
    <#
      PURE. May THIS environment hold the demo dataset? Positive proof required -- anything unsure is a refusal:
        * the update ring must be RECORDED and be 0 or 1 (2 / 3 = customer rings; not recorded or unreadable = unsure);
        * a licence must be stored, verify (Valid or Grace), and name an internal / demo licensee (customer matching
          -AllowedCustomerPattern, default \b(internal|demo)\b). No licence, an invalid one, or a customer's = refused.
      Returns @{ allowed; reasons[]; ring; customer }.
      s98.3: a BLANK pattern (the script variable not visible in the caller's scope) is the default pattern, never "match
      everything" -- '' -match '' is true, so a blank pattern would have let any licensee through.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Ring, [bool]$RingRecorded = $false, [AllowEmptyString()][string]$RingError = '',
          [AllowEmptyString()][string]$LicenceStatus = '', [AllowEmptyString()][string]$LicenceCustomer = '', [AllowEmptyString()][string]$LicenceError = '',
          [string]$AllowedCustomerPattern = $script:PimDemoAllowedCustomerPattern)
    if (-not "$AllowedCustomerPattern".Trim()) { $AllowedCustomerPattern = Get-PimDemoAllowedCustomerPatternDefault }
    $why = New-Object System.Collections.Generic.List[string]
    $rn = ConvertTo-PimDemoRingNumber $Ring
    if ("$RingError".Trim()) { $why.Add("the update ring could not be read ($("$RingError".Trim())) -- unsure, so refused") }
    elseif (-not $RingRecorded -or $null -eq $rn) { $why.Add('the update ring is not recorded in this environment -- unsure, so refused') }
    elseif ($rn -ge 2) { $why.Add("this environment is on update ring $rn (a customer ring) -- demo data is never put on a customer environment") }
    if ("$LicenceError".Trim()) { $why.Add("the licence could not be read ($("$LicenceError".Trim())) -- unsure, so refused") }
    elseif ("$LicenceStatus".Trim() -notin @('Valid', 'Grace')) { $why.Add("no valid licence (status '$("$LicenceStatus".Trim())') -- only the internal / demo licence proves a demo environment") }
    elseif (-not ("$LicenceCustomer" -match $AllowedCustomerPattern)) { $why.Add("the licence is for '$("$LicenceCustomer".Trim())', not an internal / demo licensee -- a customer environment") }
    return [pscustomobject]@{ allowed = ($why.Count -eq 0); reasons = @($why.ToArray()); ring = $rn; customer = "$LicenceCustomer".Trim() }
}

function Get-PimDemoEnvironmentProof {
    <#
      THE ONE PROOF that an environment is the internal demo one, read from its store: the recorded update ring
      (pim.Settings UpdateState) and the stored licence (pim.Settings License, verified offline), judged by
      Get-PimDemoModeEligibility. Shared by every setup script that may only run on a demo environment
      (Set-PimDemoMode -Enable, Set-PimDemoSamples) and by the demo-baseline-restore job (s98.3) -- so none of them carries
      a weaker copy. Never throws: a ring or a licence that cannot be read is recorded as its error, which the eligibility
      refuses (unsure = refused).
      Needs Read-PimUpdateState / Get-PimUpdateStateVerdict (PIM-UpdateState.ps1), Get-PimSqlSettingRaw (PIM-SqlStore.ps1)
      and Get-PimLicense (PIM-License.ps1) loaded by the caller. -ReadRing / -ReadLicence: test seams (each returns what
      the real reader returns, or throws).
      Returns the eligibility (@{ allowed; reasons[]; ring; customer }) plus ringText / ringRecorded / licenceStatus.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$ReadRing = $null, [scriptblock]$ReadLicence = $null)
    $ring = ''; $ringRec = $false; $ringErr = ''
    try {
        $rec = if ($ReadRing) { & $ReadRing $ConnectionString } else { Read-PimUpdateState -ConnectionString $ConnectionString }
        $v = Get-PimUpdateStateVerdict -Record $rec
        $ringRec = [bool]$v.recorded; $ring = "$($v.ring)"
    } catch { $ringErr = "$($_.Exception.Message)" }
    $licStatus = ''; $licCustomer = ''; $licErr = ''
    try {
        $raw = if ($ReadLicence) { & $ReadLicence $ConnectionString } else { Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name 'License' }
        if ("$raw".TrimStart().StartsWith('"')) { $raw = "$raw" | ConvertFrom-Json }   # stored as a JSON string of the document
        if ("$raw".Trim()) { $lic = Get-PimLicense -LicenseText "$raw"; $licStatus = "$($lic.Status)"; $licCustomer = "$($lic.Customer)" } else { $licStatus = 'Missing' }
    } catch { $licErr = "$($_.Exception.Message)" }
    $elig = Get-PimDemoModeEligibility -Ring $ring -RingRecorded $ringRec -RingError $ringErr -LicenceStatus $licStatus -LicenceCustomer $licCustomer -LicenceError $licErr
    $elig | Add-Member -NotePropertyName ringText -NotePropertyValue $ring -Force
    $elig | Add-Member -NotePropertyName ringRecorded -NotePropertyValue $ringRec -Force
    $elig | Add-Member -NotePropertyName licenceStatus -NotePropertyValue $licStatus -Force
    return $elig
}
