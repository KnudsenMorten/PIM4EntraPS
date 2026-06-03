#Requires -Version 5.1
<#
.SYNOPSIS
    Quickstart customer config for PIM4EntraPS\PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly (community launcher).

.DESCRIPTION
    Copy this file to LauncherConfig.custom.ps1 in the SAME folder. The custom
    file is gitignored, so the populated copy stays on your machine and is
    never overwritten by a release upgrade.

    AUTH IS USUALLY IN config\PIM4EntraPS.custom.ps1 (solution-wide).
    Use THIS file ONLY for per-engine deviations (per-engine knobs, or to
    override the solution-wide auth for this one engine).

    LAYERED CONFIG MODEL  (each layer overrides the previous)

      1. launcher\_lib\PIM4EntraPS.shared-defaults.ps1  <- solution baseline (ours)
      2. config\*.locked.ps1                              <- naming / filters / policy data (ours)
      3. config\PIM4EntraPS.custom.ps1                    <- solution-wide customer overrides
                                                            (covers EVERY PIM4EntraPS engine)
      4. LauncherConfig.defaults.ps1                       <- per-engine baseline (this folder)
      5. LauncherConfig.custom.ps1                         <- THIS FILE (per-engine,
                                                            wins over solution-wide)
      6. CLI args on the launcher                          <- last word per invocation.

.NOTES
    LauncherConfigVersion : 2
    Solution              : PIM4EntraPS
    Engine                : PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly
    Developed by          : Morten Knudsen, Microsoft MVP
#>

# ============================================================================
# 1.  AUTHENTICATION  -- Skip this section if you set auth in
#                       config\PIM4EntraPS.custom.ps1 (recommended).
#                       Uncomment ONE method block to OVERRIDE for this engine.
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
# 2.  PER-ENGINE OVERRIDES
# ============================================================================
# Place any $global:* you want to deviate from LauncherConfig.defaults.ps1
# here. Closest layer wins, so anything you set here trumps the solution-wide
# value in config\PIM4EntraPS.custom.ps1.
