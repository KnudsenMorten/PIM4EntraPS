<#
  PURE core for the deploy report (tools/setup/New-PimDeployReport.ps1).

  🪤 IT LIVES HERE, NOT IN THE SCRIPT, because the script RUNS A DEPLOY when executed -- and
  dot-sourcing a .ps1 executes it. A test that dot-sourced the script to reach the redactor
  therefore kicked off a real deploy with empty arguments. Caught 2026-08-09 by a stray
  "failedSteps : {}" appearing in the middle of the test output. Everything in this file is PURE
  and dot-sourcing it has NO side effects.
#>

Set-StrictMode -Off
# PURE: the redactor. Isolated from all I/O so it is unit-testable offline, which matters more here
# than anywhere else in this script -- a redactor that is not tested is a redactor you are trusting
# with someone else's credentials on the strength of having read it once.
# ---------------------------------------------------------------------------
function Get-PimRedactedText {
    [CmdletBinding()]
    param([string]$Text, [switch]$Identifiers)
    if (-not $Text) { return $Text }
    $t = $Text

    # --- SECRETS: always masked -------------------------------------------------------------
    # Ordered longest/most-specific first: a connection string contains a password, and masking the
    # password alone would leave the server, database and user readable inside a string that reads
    # like a credential. Mask the whole value.
    $t = [regex]::Replace($t, '(?i)(Password|Pwd)\s*=\s*[^;"''\r\n]+',            '$1=***REDACTED***')
    $t = [regex]::Replace($t, '(?i)(AccountKey|SharedAccessKey)\s*=\s*[^;"''\r\n]+', '$1=***REDACTED***')
    $t = [regex]::Replace($t, '(?i)\b(client[_-]?secret|clientsecret)\b(\s*[:=]\s*|"\s*:\s*")[^\s,;"''\r\n]+', '$1$2***REDACTED***')
    $t = [regex]::Replace($t, '(?i)\b(password|passwd|secret|apikey|api[_-]key)\b(\s*[:=]\s*|"\s*:\s*")[^\s,;"''\r\n]+', '$1$2***REDACTED***')
    # Bearer / JWT anywhere (a JWT is three base64url segments; match the shape, not the context).
    $t = [regex]::Replace($t, '(?i)\bBearer\s+[A-Za-z0-9\-_\.=]+',                 'Bearer ***REDACTED***')
    $t = [regex]::Replace($t, '\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]*', '***JWT-REDACTED***')
    # SAS tokens (sig=...) and az --password/-p values as typed on a command line.
    $t = [regex]::Replace($t, '(?i)([?&]sig=)[^&\s"''\r\n]+',                      '$1***REDACTED***')
    $t = [regex]::Replace($t, '(?i)(\s(?:-p|--password|--certificate)\s+)\S+',     '$1***REDACTED***')
    # PEM / certificate blobs -- collapse the body, keep the marker so the reader knows one was there.
    $t = [regex]::Replace($t, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                              '-----BEGIN PRIVATE KEY----- ***REDACTED*** -----END PRIVATE KEY-----')

    # --- IDENTIFIERS: masked only on request ------------------------------------------------
    if ($Identifiers) {
        # GUIDs cover tenant + subscription + app ids. Keep the FIRST 8 chars so two different
        # tenants stay distinguishable in the report -- a report where everything is '***' cannot
        # be reasoned about at all.
        $t = [regex]::Replace($t, '\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '$1-****-****-****-************')
        $t = [regex]::Replace($t, '(?i)\b[A-Za-z0-9\-]+\.onmicrosoft\.com\b', '***TENANT-DOMAIN***')
    }
    return $t
}


