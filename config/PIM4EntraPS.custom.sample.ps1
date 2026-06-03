#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- solution-wide customer override template.

.DESCRIPTION
    Copy this file to `PIM4EntraPS.custom.ps1` (same folder; gitignored) and
    fill in the values marked with <...> placeholders. Most customers fill in
    AUTH here once -- it then applies to EVERY engine in the solution. Use
    per-engine `launcher\<engine>\LauncherConfig.custom.ps1` only for engine-
    specific deviations.

    Layer precedence (closer wins):
      0. launcher/_lib/PIM4EntraPS.shared-defaults.ps1   (solution baseline, ours)
      1-5. config/*.locked.ps1                            (policy / naming data)
      6. config/PIM4EntraPS.custom.ps1   -- THIS FILE     (customer-wide)
      7. launcher/<engine>/LauncherConfig.defaults.ps1   (engine baseline, ours)
      8. launcher/<engine>/LauncherConfig.custom.ps1     (per-engine customer, wins)

.NOTES
    Layer        : solution-wide customer overrides
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- REQUIRED. Uncomment ONE method block, fill in values.
#                       (Skip this section ONLY if every per-engine
#                        LauncherConfig.custom.ps1 sets auth on its own.)
# ============================================================================

# ----- METHOD 1: Managed Identity (recommended for Azure VMs / Arc / Function) -
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'

# ----- METHOD 2: SPN + secret stored in Azure Key Vault ------------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'PIM4EntraPS-Secret'

# ----- METHOD 3: SPN + certificate (thumbprint in local cert store) ------------
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# ----- METHOD 4: SPN + plaintext secret  *** TESTING ONLY *** ------------------
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'


# ============================================================================
# 2.  LOGGING + OUTPUT
# ============================================================================
# Transcript ON by default; set to $true for lab / silent mode.
# $global:PIM_DisableTranscript = $false
# $global:PIM_LogRetentionDays  = 30

# Override output root for engine exports (CSV/JSON). $null = <solution>/output.
# $global:PIM_OutputRoot = $null


# ============================================================================
# 3.  CONFIG VARIANT  (PIM-Baseline-Management-CSV only)
# ============================================================================
# Some launchers accept -ConfigVariant 'local'|'msp'|''. When unset, the
# default per-launcher value applies. Set here ONLY to override the default
# for every invocation in this customer environment.
# $global:PIM_ConfigVariant = ''
