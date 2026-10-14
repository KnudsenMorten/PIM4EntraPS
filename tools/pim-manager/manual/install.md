# Install

PIM Manager installs into your own Azure subscription in one guided run. Invardia's installation wizard collects your
answers and gives you the command; you run it yourself in Azure Cloud Shell or PowerShell on Windows. No PowerShell
modules are needed: the scripts use REST and .NET only, and you sign in in the browser.

## Before you start

| You need | Why |
|---|---|
| An Azure subscription and **Owner** on it (or Contributor + User Access Administrator) | The install creates the resource group and its resources and gives the product's identities their Azure roles. |
| **Privileged Role Administrator** in Entra ID (Global Administrator also works) | Microsoft Graph application permissions for the engine and the portal, and the role-assignable SQL admin group. |
| **Application Administrator** in Entra ID | The portal's sign-in app registration. |
| Exchange Administrator (optional) | Only for the mail sender: one shared mailbox and a send right scoped to it. |
| A licence file or an enrollment key (Pro) | The licence is checked before anything is deployed. |

You run the install signed in as yourself. A service principal, another tenant or another subscription is refused
before anything is touched.

## The guided install

1. Run the command from the wizard. Use `-WhatIf` first to see every check and step without changing anything.
2. The checks: your answers and licence, your sign-in, your rights and the subscription.
3. The deploy: resource group, network, registry, Log Analytics, SQL, the jobs and the portal.
4. The portal is created **closed** (a deny-all ingress rule) and opens only after Entra sign-in is configured and
   verified.
5. The licence is registered and the installation is verified end to end.

A failed step stops the run with the reason and the fix. Run the same command again with `-Resume` after fixing it;
completed steps are skipped.

## What the install sets up for database access

- Each component gets its own database user, created from its own managed identity, and its own database role (see
  [Database access](sql-access)).
- The signed grant procedure and its in-database certificate are installed once, by the install itself. From then on
  every update applies its schema and grants on its own: nothing routine ever needs a database administrator again.
- The setup identity is a database administrator only for the length of the install. Afterwards the SQL admin group is
  empty, unless you name the Invardia Support app (see [Support access](support-access)).
- SQL auditing is switched on to the installation's own Log Analytics workspace, kept 90 days.

## Choices you make at install

| Choice | Options |
|---|---|
| Topology | Single (one tenant), Managing tenant (a provider that manages other tenants), Managed tenant |
| Network | Public with Entra sign-in in front, IP-restricted, or private (internal-only environment and private endpoints) |
| Region | West Europe, Sweden Central or Denmark East |
| Database size | Standard tier, S0 at minimum; a higher tier you set is kept |
| Optional parts | Mail sender, PIM Activator, access requests, hybrid worker for on-premises AD |

The private-network options and how to prepare your network are described in Invardia's guides at
https://invardia.com/docs/pim/.
