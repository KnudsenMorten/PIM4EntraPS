<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/pim-manager-reversed.svg">
    <img src="docs/img/brand/pim-manager.svg" alt="Invardia PIM Manager" width="420">
  </picture>
</p>

# PIM Manager

**Privileged access for Microsoft Entra and Azure, governed as one model.**

> ### ⬇️ Download / Install Community — free
> **[Download the latest release](https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest)** &nbsp;·&nbsp;
> **[Install guide](https://invardia.com/docs/pim-manager/setup/#community-edition)** &nbsp;·&nbsp;
> [Quick start below](#community-quick-start)
>
> Installs into your own Azure subscription with one command. Pro adds more: [Free vs Pro](https://invardia.com/products/pim-manager/).

Standing admin rights are the access an attacker wants most, and Microsoft Entra PIM gets hard to run by hand once
you have more than a handful of admins: every person needs every role assigned one by one, nothing tells you when the
tenant drifts from what you intended, and a leaver keeps access until someone remembers it.

PIM Manager fixes that. You describe who may do what once, as nested groups (admin -> role group -> permission
group -> Entra role, Azure role or workload). An engine in your own Azure subscription applies it through PIM for
Groups, keeps the tenant in line with it, and shows you every difference. Admins activate what they need, just in
time, from the PIM Activator browser extension.

- **Eligible, not standing.** Admins hold eligible access and activate it for as long as your policy allows.
- **One change instead of thirty-five.** Adding or removing an engineer is one group membership, not every role.
- **Risky changes wait.** Role policy changes and mass changes wait for approval, and every change is logged with its
  before and after.
- **Runs in your Azure.** PIM Manager, its engine and its database run in your own subscription on managed
  identities.

![PIM Manager Home: tiles for engine health, validation findings, break-glass status, delegation by level and expiring access](docs/img/manager-home.png)

![The Access map: who reaches which Entra role or Azure scope, through which groups](docs/img/manager-access-map.png)

![Pending changes: every change is staged and reviewed before it is committed](docs/img/manager-pending-changes.png)

## Documentation

Everything about PIM Manager is at **[invardia.com/docs/pim-manager](https://invardia.com/docs/pim-manager/)**:

- [Why PIM Manager](https://invardia.com/docs/pim-manager/why/)
- [How to design PIM v2 with nested groups](https://invardia.com/docs/pim-manager/design/)
- [Security design](https://invardia.com/docs/pim-manager/security-design/)
- [Setup](https://invardia.com/docs/pim-manager/setup/) and [Operate](https://invardia.com/docs/pim-manager/operate/)
- [Knowledge base](https://invardia.com/docs/pim-manager/knowledge-base/) and [FAQ](https://invardia.com/docs/pim-manager/faq/)

## Community quick start

The Community edition is free and installs into your own Azure subscription from this repository.

```powershell
git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
cd PIM4EntraPS
```

Then follow **[Setup](https://invardia.com/docs/pim-manager/setup/)**: it creates the deploy identity (a
certificate, never a secret) and deploys PIM Manager, the engine and the database with one command, which you run
first without `-Apply` to see the plan. You need PowerShell 7 and git; no Azure CLI and no PowerShell modules.

## Pro editions and support

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

PIM Manager Pro (Pro Business, Pro Enterprise, Pro MSP) adds the features marked Pro in the documentation and
support from Invardia: [invardia.com/products/pim-manager](https://invardia.com/products/pim-manager/), a 60-day
trial at [invardia.com/trial](https://invardia.com/trial/), questions to info@invardia.com.

To register a Pro license, use **Settings > Licence** in PIM Manager, or run these two lines as a member of the
environment's SQL admin group: line 1 downloads the script from Invardia, line 2 runs it with a browser sign-in (no
certificate, no secret). Add `-WhatIf` to see what it does first.

```powershell
Invoke-WebRequest https://invardia.com/support/pim/Set-PimLicense.ps1 -OutFile Set-PimLicense.ps1
.\Set-PimLicense.ps1 -LicensePath <file> -SqlServer <server>.database.windows.net -TenantId <tenant> -UseSignedInAccount
```

Community questions and bugs: [GitHub issues](https://github.com/KnudsenMorten/PIM4EntraPS/issues).

## License

Open core: the Community features are free under the terms in [LICENSE](LICENSE); Pro features need a license from
Invardia.

Invardia is a brand of 2LINKIT, founded and owned by Morten Knudsen.
