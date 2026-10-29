<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/pim-manager-community-reversed.svg">
    <img src="docs/img/brand/pim-manager-community.svg" alt="Invardia PIM Manager Community edition" width="420">
  </picture>
</p>

# PIM Manager

**Privileged access that is earned, temporary and proven -- for Microsoft Entra ID, Azure, Intune and Defender XDR.**

> ### ⬇️ Install Community -- free, in your own Azure
> **[Install in two lines](#install)** &nbsp;·&nbsp;
> **[Download the latest release](https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest)** &nbsp;·&nbsp;
> **[Install guide](https://invardia.com/docs/pim-manager/setup/#community-edition)** &nbsp;·&nbsp;
> [Community vs Pro](#community-and-pro)

![PIM Manager Home: engine health, validation findings, break-glass status, delegation by level and expiring access](docs/img/features/home-dashboard-1.png)

## Why PIM Manager

Standing admin rights are what an attacker wants most. In most Microsoft tenants they are spread across nested
groups, portal clicks and old exceptions, so nobody can say who can do what, audits take weeks, and a leaver keeps
access until someone remembers it. Microsoft Entra PIM is the right tool, but it is hard to run by hand once you
have more than a handful of admins: every person needs every role assigned one by one, and nothing tells you when the
tenant drifts away from what you intended.

PIM Manager gives you **one governed model in your own tenant**:

- 🔐 **No standing admin rights.** Admins hold eligible access and activate it for a limited time, with a reason --
  from a browser extension, in seconds.
- 🧩 **Access defined once.** You describe who may do what as nested groups (admin -> role group -> permission group
  -> Entra role, Azure role or workload role). Adding or removing an engineer is **one change instead of thirty-five**.
- 🛑 **Risky changes need approval.** Every change is staged and reviewed before it is committed. Policy changes need
  a SuperAdmin. Mass changes are held by a safety brake. Everything is logged with its before and after.
- 🔍 **Drift is found, not guessed.** The engine keeps the tenant in line with your model and shows every difference
  between what you defined and what is live.
- 🏠 **Runs in your Azure.** PIM Manager, its engine and its database run in your own subscription on managed
  identities.
- 💸 **Free to start.** The Community edition is free for a single tenant, for as long as you like.

## Install

You need **PowerShell 7** and an account that is **Owner of the Azure subscription** and **Privileged Role
Administrator** in Entra ID. You sign in in your browser: no app secret, no certificate, no Azure CLI and no PowerShell
modules. Line 1 downloads the installer, line 2 runs it. Open a new PowerShell 7 window for each.

**1. The most common: Community, browser sign-in, everything else defaulted.** Start here.

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
.\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
```

**2. See the plan first.** Checks your sign-in, rights, subscription and region and lists every step. Changes nothing.

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
.\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -WhatIf
```

**3. Your own region, resource group and admins.** When you have a naming standard or want the alerts to go to a team
mailbox.

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
.\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Location westeurope `
    -ResourceGroup rg-pim-manager -SuperAdmins 'admin1@contoso.com','admin2@contoso.com' -AlertRecipients 'pim-alerts@contoso.com'
```

**4. Pro, or a free 60-day Pro trial.** The same command plus the enrollment key from your Invardia portal or trial
mail ([start a trial](https://invardia.com/trial/)); with a licence file, use `-LicencePath <file>` instead.

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
.\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -EnrollmentKey '<enrollment key>'
```

**5. It stopped -- carry on.** Fix what the installer named, then run the same command with `-Resume`: finished steps
are skipped.

```powershell
.\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Resume
```

Several tenants (MSP) is Pro MSP: see [Pro MSP](https://invardia.com/products/pim-manager/). Every parameter, what the
installer creates and the rights it grants: **[Setup](https://invardia.com/docs/pim-manager/setup/)**.

**Updates.** Community updates itself at night from the public release. To update by hand instead, run
`.\tools\setup\Update-PimCommunity.ps1 -Apply` from the install folder whenever you choose.

## What it does

### See who can do what

The **Access map** traces every admin through role groups and permission groups to the roles and scopes they can
reach. **Reports** list every reachable target per admin, and **Role Lookup** finds the least-privileged role for a
task -- or who can activate a given role today.

![The Access map: an admin traced through a role group and permission groups to roles and scopes](docs/img/features/access-map-1.png)

![Who can do what: every target each admin can reach](docs/img/features/who-can-do-what-1.png)

![Role Lookup: the least-privileged role for a task, and who can activate it](docs/img/features/role-lookup-1.png)

### Just-in-time access with the PIM Activator

Admins tick the groups and roles they need, give one reason and a duration, and activate them together from the
**PIM Activator** browser extension for Edge and Chrome. The guided rollout page deploys it to managed devices.

![PIM Activator: activate several groups and roles with one justification](docs/img/features/pim-activator-1.png)

![The guided PIM Activator rollout](docs/img/features/pim-activator-guided-1.png)

### Build access in minutes, not portal clicks

**Get Started** walks you through the first setup with a progress bar. The **create-access wizard** builds a delegation
(Entra role, Azure scope, Intune or Defender XDR role) with the right groups, tier and policy. **Policy templates** set
activation duration, approval, MFA and justification in plain words.

![Get Started: the first setup with progress and step status](docs/img/features/get-started-1.png)

![The create-access wizard](docs/img/features/create-access-wizard-1.png)

![Policy templates and the delegations that use them](docs/img/features/policy-templates-1.png)

### Every change is reviewed, braked and logged

Nothing reaches the tenant until it is committed. **Pending changes** shows every staged change with a keyed diff. The
**safety brake** holds oversized runs and policy changes for a SuperAdmin. The **audit trail** records who changed
what, with before and after.

![Review and commit: every staged change before it is committed](docs/img/features/pending-changes-1.png)

![The safety brake: a held change set waiting for a SuperAdmin](docs/img/features/safety-brake-1.png)

![The audit trail: who changed what, before and after](docs/img/features/audit-trail-1.png)

### A desired-state engine that finds drift

The engine applies your model to Entra ID, Azure, Intune and Defender XDR through PIM for Groups, touches only what
you defined, and shows every difference between your model and the live tenant.

![Drift: live vs desired state per area](docs/img/features/drift-detection-1.png)

![The engine jobs page](docs/img/features/desired-state-engine-1.png)

![Entra roles, Azure RBAC, Intune and Defender XDR in one model](docs/img/features/entra-azure-intune-defender-1.png)

### Admin accounts, break-glass and tiers

Separate admin accounts with Temporary Access Passes and automatic disable, break-glass accounts that are watched,
and a **tier impact report** that shows what a change does to your Tier 0, 1 and 2 boundaries.

![Admin accounts](docs/img/features/admin-accounts-1.png)

![Break-glass and emergency override](docs/img/features/break-glass-override-1.png)

![Tier impact report](docs/img/features/tier-impact-report-1.png)

### Pro: reviews, on-premises AD and many tenants

Pro adds access reviews the engine enforces, PIM for on-premises Active Directory, more workloads, and for MSPs one
definition set rolled out to many customer tenants in waves, with fleet conformance.

![Access reviews: one review per department, enforced by the engine (Pro)](docs/img/features/access-reviews-1.png)

![PIM for on-premises Active Directory (Pro)](docs/img/features/pim-for-active-directory-1.png)

![MSP fleet conformance (Pro MSP)](docs/img/features/msp-fleet-conformance-1.png)

![MSP rollout rings (Pro MSP)](docs/img/features/msp-rollout-rings-1.png)

### Runs in your own Azure

PIM Manager, the engine and the database run in your subscription on managed identities. You sign in with Entra ID.

![Runs in your Azure: the PIM Manager, engine and database in your subscription](docs/img/features/runs-in-your-azure-1.png)

## Community and Pro

![Community vs Pro, as PIM Manager shows it on a Community install](docs/img/features/free-and-pro-1.png)

| | Community (free) | Pro |
|---|---|---|
| Tenants | One | One (Business, Enterprise) or many (MSP) |
| Full PIM Manager: model, review, commit, change tracking | ✅ | ✅ |
| Entra ID roles, PIM for Groups, administrative units, Azure RBAC | ✅ | ✅ |
| Intune and Defender XDR role delegation, incl. Defender custom roles | ✅ | ✅ |
| Access map, Reports, Role Lookup, drift detection | ✅ | ✅ |
| Admin accounts with Temporary Access Passes and auto-disable | ✅ | ✅ |
| PIM Activator browser extension | ✅ | ✅ |
| Updates | From the public release | Approved releases through Invardia |
| Access reviews enforced by the engine, with evidence export | | ✅ |
| Second approver and delegated administration | | ✅ |
| Access request portal and API | | ✅ |
| Coverage, gaps and the discovery inbox | | ✅ |
| More workloads: Power BI, enterprise-app roles, Azure DevOps, Dataverse, Business Central, Power Platform | | ✅ |
| PIM for on-premises Active Directory | | ✅ |
| Many tenants: definition sets, rollout waves, fleet conformance, central admin accounts | | Pro MSP |
| Support from Invardia | Community (GitHub issues) | ✅ |

Pro editions, prices and the free 60-day trial: **[invardia.com/products/pim-manager](https://invardia.com/products/pim-manager/)**
· [Start a trial](https://invardia.com/trial/) · info@invardia.com

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/pim-manager-community-reversed.svg">
    <img src="docs/img/brand/pim-manager-community.svg" alt="Invardia PIM Manager Community edition" width="300">
  </picture>
  &nbsp;&nbsp;&nbsp;
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/pim-manager-pro-reversed.svg">
    <img src="docs/img/brand/pim-manager-pro.svg" alt="Invardia PIM Manager Pro edition" width="260">
  </picture>
</p>

To register a Pro license on an existing install, use **Settings > Licence** in PIM Manager, or run these two lines as
a member of the environment's SQL admin group (add `-WhatIf` to see what it does first):

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Set-PimLicense.ps1 -OutFile Set-PimLicense.ps1
.\Set-PimLicense.ps1 -LicensePath <file> -SqlServer <server>.database.windows.net -TenantId <tenant> -UseSignedInAccount
```

## The PIM Manager, screen by screen

<details>
<summary>More screenshots (demo data)</summary>

![Home](docs/img/manager-home.png)

![The menu](docs/img/manager-nav.png)

![Access map](docs/img/manager-access-map.png)

![Pending changes](docs/img/manager-pending-changes.png)

![Delegations](docs/img/manager-delegation-list.png)

![Drift](docs/img/manager-drift.png)

![Standing access](docs/img/manager-standing-access.png)

![Reports](docs/img/manager-reports.png)

![Role Lookup](docs/img/manager-role-lookup.png)

![Admin accounts](docs/img/manager-admin-accounts.png)

![Jobs and logs](docs/img/manager-jobs-logs.png)

![Settings](docs/img/manager-settings.png)

![Settings: Hybrid Active Directory (Pro)](docs/img/manager-settings-hybrid-ad.png)

![Community vs Pro in the PIM Manager](docs/img/manager-free-vs-pro.png)

</details>

## Documentation

Everything about PIM Manager is at **[invardia.com/docs/pim-manager](https://invardia.com/docs/pim-manager/)**:

- [Why PIM Manager](https://invardia.com/docs/pim-manager/why/)
- [How to design PIM v2 with nested groups](https://invardia.com/docs/pim-manager/design/)
- [Security design](https://invardia.com/docs/pim-manager/security-design/)
- [Setup](https://invardia.com/docs/pim-manager/setup/) and [Operate](https://invardia.com/docs/pim-manager/operate/)
- [Knowledge base](https://invardia.com/docs/pim-manager/knowledge-base/) and [FAQ](https://invardia.com/docs/pim-manager/faq/)

## What is in this repository

| Folder | What it holds |
|---|---|
| `tools/` | Everything you run: `tools/setup/` (install, update and setup scripts), the PIM Manager app, the engine jobs, the PIM Activator browser extension |
| `engine/` | The engine that applies your PIM model to Entra ID, Azure and the workloads |
| `config/` | Sample configuration files; `config/msp/` holds the multi-tenant build samples |
| `templates/` | Shipped PIM, policy, mail and admin templates |
| `workloads/` | Workload connector definitions (Intune, Defender XDR, Azure RBAC and more) |
| `sql/` | The database schema |
| `docs/` | The feature catalog, the design notes, the security pack and images; the full documentation is at invardia.com |

Community questions and bugs: [GitHub issues](https://github.com/KnudsenMorten/PIM4EntraPS/issues).

## License

Open core: the Community features are free under the terms in [LICENSE](LICENSE); Pro features need a license from
Invardia.

Invardia is a brand of 2LINKIT, founded and owned by Morten Knudsen.
