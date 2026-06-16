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


# ============================================================================
# 4.  AUTOMATIC DESTRUCTIVE ACTIONS  (ENVIRONMENT-AWARE -- operator policy)
# ============================================================================
# After the mass account-disable incident, every AUTOMATIC destructive action
# that acts on the WHOLE scanned population is ENVIRONMENT-AWARE: it DEFAULTS ON
# in a TEST tenant and OFF in a PROTECTED tenant (the real internal tenant, or an
# unknown/absent tenant id = the safe default). An EXPLICIT setting below (true or
# false) ALWAYS overrides the env default in either direction.
#
# Two catastrophe guards are ALWAYS ON regardless of environment: a run aborts on
# an empty/unresolved desired set, and the mass-disable circuit breaker aborts a
# run that would disable more than the cap -- even in a test tenant.
#
#   *** NO AUTOMATIC OFFBOARDING is permitted in production until an approval flow
#   exists. *** In a PROTECTED tenant these stay OFF unless you explicitly opt in;
#   do NOT set PIM_EnableAutomaticOffboarding=$true in production until that gate
#   is built (see docs/REQUIREMENTS.md).

# Test-tenant classification: tenant ids listed here are treated as TEST (the
# destructive features below default ON). Default (when unset) = the PIM MSP test
# tenants. Anything not in the list -- INCLUDING the real internal tenant and an
# unknown/absent id -- is PROTECTED (destructive features default OFF). String or
# array; comma/space/semicolon separated is accepted.
# $global:PIM_TestTenantIds = @('<test-tenant-guid-1>','<test-tenant-guid-2>')

# Account-disable / offboarding opt-in (gates the REST 'Admins' disable path).
# Unset => env default (ON in test, OFF in protected). Explicit wins either way:
# $global:PIM_AccountDisableEnabled = $false

# Date-driven admin offboarding (revoke at OffboardDate, delete DeleteAfterDays
# later) + the REST-engine AdminOffboarding membership-removal scope.
# Unset => env default; explicit setting overrides:
# $global:PIM_EnableAutomaticOffboarding = $false

# Lifecycle=Retire: remove a group's role assignments + members and DELETE it
# (naming-prefix guarded). Unset => env default; explicit overrides:
# $global:PIM_EnableGroupRetirement = $false

# Membership drift cleanup: remove live members of managed groups not in the
# assignment CSVs. Unset => env default; explicit overrides. When enabled,
# $global:PIM_OffboardCleanupMode below still controls Report vs Enforce:
# $global:PIM_EnableMembershipDriftCleanup = $false
# $global:PIM_OffboardCleanupMode = 'Report'           # Off | Report | Enforce

# NOTE: the CONTROLLED, opt-in reconcile prune (engine -Mode Full -Prune, which
# is naming-scoped and never prunes an empty desired set) is NOT affected by the
# flags above -- it remains available as the deliberate, scoped reconcile path.
