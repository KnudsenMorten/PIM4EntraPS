# What's new in PIM Manager

## 3.1.23.2 · 2026-11-14 · Security

A security update for the sign-in front of PIM Manager.

### New features

None in this version.

### Fixes

- **Sign-in security update** - The sign-in front now runs on the latest patched Microsoft sign-in components. Nothing changes in how you sign in or work.

## 3.1.23 · 2026-11-13 · Feature update

A new What's new page shows every PIM Manager release in plain words, newest first.

### New features

- **What's new page** - Open Settings > What's new to see every release, newest first, with what it changes for you. The same list is on invardia.com and in the Community repository.

### Fixes

- **Clearer release notes** - The release notes describe each change by its effect, in plain words.

## 3.1.22 · 2026-11-13 · Fix-only

Your Defender XDR roles stay exactly as you set them, and the workload job no longer fails after Microsoft's change.

**Action needed:** Create the role in the Defender portal; Drift: live vs desired lists which ones.

### New features

None in this version.

### Fixes

- **Your Defender XDR roles are never changed** - PIM Manager only adds your groups to roles that already exist. It never creates, changes or deletes a role.
- **No group gets more than you defined** - If a role grants more than you asked for, the group is not added and you see what is extra.
- **The workload job runs again** - Microsoft now shows some role permissions in a shorter form. PIM Manager reads both forms the same way, so the job no longer stops.
- **Differences in Data sources are only reported** - A difference in Data sources is shown to you and no longer fails the run.

## 3.1.20 · 2026-11-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 3.1.19 · 2026-11-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 3.1.18 · 2026-11-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 3.1.17 · 2026-11-12 · Fix-only

The delegation overview loads far faster in tenants with many subscriptions.

### New features

None in this version.

### Fixes

- **The delegation overview loads much faster** - In a tenant with 2,000 subscriptions, eligible Azure roles now load in about 3 minutes instead of 40. Anything missed the first time is read again.

## 3.1.16 · 2026-11-12 · Feature update

You can follow a policy change from save to applied on one page.

### New features

- **Follow a policy change on one page** - When you save policy choices, PIM Manager plans the change at once and shows each step on the same page: planning, waiting for Approve all, approved and applied.

### Fixes

- **Approvals always shows policy changes** - The Approvals page now always includes its policy part.
- **Clearer Overview and save messages** - The Overview gap tile uses the coverage check, waiting policy choices show as an info line, and the save message no longer sounds like the second-approver setting.
- **No false updater error** - The updater no longer logs an error for a database user that already exists.

## 3.1.15 · 2026-11-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 3.1.14 · 2026-11-12 · Fix-only

Old versions are cleaned up after each update.

### New features

None in this version.

### Fixes

- **Old versions are cleaned up after updates** - After a successful update, PIM Manager keeps only the current and previous version plus anything in use.

## 3.1.13 · 2026-11-12 · Feature update

You can now create and manage access packages in PIM Manager without touching your existing groups.

### New features

- **Create access packages in PIM Manager** - Use Create > Access package to make one, then list, view, pause or resume it. Packages also show in the Access map.
- **Each package gets its own new groups** - Every package gets new groups ending in -AP, locked to it. Your existing groups are never touched, and a package pauses if anything is unclear.

### Fixes

- **No orphan-group mails for new installs** - An install with no definitions yet no longer sends orphan-group warnings. Its groups show as not imported yet.

## 3.1.12 · 2026-11-12 · Feature update

Existing office accounts can now be used as admins, and PIM Manager never changes an account it did not create.

### New features

- **Use existing office accounts as admins** - The importer, adopt and the Create admin wizard now fully support existing office accounts, synced from AD or cloud-only. PIM Manager never changes an account it did not create.

### Fixes

- **Smaller fixes** - The hybrid worker never touches existing office accounts, and the database statistics share now rounds to a whole number.

## 3.1.11 · 2026-11-12 · Feature update

Every mail now tells you at a glance which environment and tenant it is about.

### New features

- **Every mail names its environment** - Each PIM Manager mail names its environment in the subject and first line, and the tenant in the body.

### Fixes

- **Invardia support sees database health** - The health report to Invardia support now includes the database tier, size, recent load and statistics health.

## 3.1.10 · 2026-11-11 · Feature update

Community installs can choose to connect to Invardia for health reports and updates on request.

### New features

- **Community installs can connect to Invardia** - Choose Connect this install to Invardia to send health reports and get updates on request; Update now then works as in Pro. If you say no, nothing identifying is sent.

### Fixes

None in this version.

## 3.1.9 · 2026-11-11 · Feature update

You can now see Entra role holders that were assigned outside PIM.

### New features

- **See Entra roles assigned outside PIM** - Review all delegations now also lists Entra role holders assigned outside PIM, such as partner (GDAP) groups, Microsoft apps and roles scoped to an administrative unit.

### Fixes

None in this version.

## 3.1.8 · 2026-11-11 · Feature update

You now see exactly what grants access outside PIM Manager, without the noise of ordinary groups.

### New features

- **See exactly who has access outside PIM Manager** - Review all delegations shows people, apps and deleted accounts with an Entra or Azure role, role-holding groups and their members, and apps with high-privilege permissions.

### Fixes

- **Less noise in delegation reviews** - Ordinary groups and their members are no longer listed, and the Discovery and gaps report speaks only about PIM groups and PIM admins.
- **Delegation overview reads less** - The delegation overview reads far less, the Azure part once a night, and the page shows when each part was read.
- **Simpler office account creation** - When you create an office account, the steps that do not apply are skipped.

## 3.1.7 · 2026-11-11 · Feature update

A person can now hold PIM delegations on their own existing account, which PIM Manager never changes.

### New features

- **Delegations on a person's existing account** - The new admin type Existing account lets a person hold PIM delegations on their own office account. PIM Manager finds it by exact name and never creates, changes, disables or deletes it.
- **Warning on high-privilege use** - PIM Manager warns you when such an account gets more than level 4-5.

### Fixes

None in this version.

## 3.1.6 · 2026-11-11 · Security

PIM Manager runs on the latest .NET runtime with Microsoft's newest security fixes.

### New features

None in this version.

### Fixes

- **Latest .NET security fixes** - PIM Manager and its sign-in front now run on .NET 10.0.15, which includes Microsoft's latest security fixes. Nothing changes in how it works.

## 3.1.5 · 2026-11-11 · Fix-only

The mail sender setup now reports ready only when Exchange has really confirmed it.

**Action needed:** If the mail sender setup ends as pending, re-run it later.

### New features

None in this version.

### Fixes

- **Mail sender setup reports ready only when true** - The mail sender setup uses the mailbox's real primary address, reuses a scope that already covers it, and reports ready only once Exchange confirms each sending identity.
- **Clear stop when converting from Linux** - Converting to private from a Linux shell such as Azure Cloud Shell now refuses the Rebuild route at the start instead of failing halfway.

## 3.1.4 · 2026-11-11 · Fix-only

An update held back by a running job now arrives within minutes instead of a day later.

### New features

None in this version.

### Fixes

- **Held updates are retried within minutes** - If a nightly update waits because a PIM job is running, the updater now tries again every 15 minutes instead of waiting a day. It never changes anything while a job runs.

## 3.1.3 · 2026-11-11 · Security

Secrets are kept in your installation's own Key Vault, and break-glass keeps working after an identity move.

### New features

None in this version.

### Fixes

- **Secrets move into your own Key Vault** - Once support has given access, the updater places every secret in the installation's Key Vault, with a check and automatic restore.
- **Rotated secrets are stored in Key Vault** - A rotated secret is now written to the Key Vault too.
- **Break-glass works after an identity move** - Before, break-glass activation could be refused after the web identity moved, until the passphrase was set again. Key Vault access now moves with the identity.

## 3.1.2 · 2026-11-11 · Fix-only

Fewer false reports of runs taking far longer than usual.

### New features

None in this version.

### Fixes

- **Fewer false long-run reports** - A run is reported as far longer than usual only when it takes over twice the longest recent good run and at least 30 minutes.

## 3.1.1 · 2026-11-11 · Fix-only

Invardia support can see more of your installation's health, without changing anything.

### New features

None in this version.

### Fixes

- **Invardia support sees more health details** - PIM Manager now reports when its updater last ran and how it ended, and whether your Key Vault has purge protection and holds every secret. Nothing is changed.

## 3.1.0 · 2026-11-10 · Feature update

PIM Manager 3.1 runs on long-term supported Microsoft software and brings together the improvements of the 3.0 series.

### New features

- **Runs on supported .NET 10 and PowerShell 7.6** - PIM Manager runs on .NET 10 LTS and PowerShell 7.6 LTS on Microsoft's current image, supported to November 2028. Nothing changes for you.
- **Invardia support link** - Health and run results go to Invardia support. Undelivered reports are retried without mailing you, and the status turns amber only after three failed rounds in a row.
- **New Get Started steps** - Get Started has steps for Azure resources and Workloads, and a Who needs what table shows each identity's rights.
- **Stalled runs are shown and reported** - The Jobs page shows Running far longer than usual, and Invardia support is told. Runs are never stopped.
- **Smaller improvements** - Error catalogue pages for every error code, Recognised admin names with *, Drift showing only PIM-named objects, Entra access packages, two-line install, and four-eyes approval and evidence export in both editions.

### Fixes

None in this version.

## 3.0.85 · 2026-11-10 · Fix-only

The link to Invardia support now has one clear name everywhere.

### New features

None in this version.

### Fixes

- **One name: Invardia support link** - The link that sends health and run results to Invardia support now has one name everywhere: Invardia support link. Turning it off stops all reports to Invardia support.

## 3.0.84 · 2026-11-10 · Fix-only

Undelivered reports to Invardia support no longer reach your inbox or raise early warnings.

### New features

None in this version.

### Fixes

- **Undelivered reports no longer mail you** - A report to Invardia support that could not be delivered is retried and never mailed to you. The Invardia support link turns amber only after three failed rounds in a row.
- **Rights list matches what PIM Manager does** - The approved rights list now matches the product; the updater keeps reading SuperAdmins' mail addresses for alerts.

## 3.0.83 · 2026-11-10 · Fix-only

Invardia support now learns about stalled runs without you having to report them.

### New features

None in this version.

### Fixes

- **Stalled runs are reported to Invardia support** - A run that stops making progress or takes far longer than usual is now reported to Invardia support as well as on the Jobs page. Nothing is ever stopped or restarted.

## 3.0.82 · 2026-11-10 · Feature update

Get Started now guides you through Azure resources and Workloads, and shows who needs which rights.

### New features

- **Get Started: Azure resources step** - A new optional step shows the scopes PIM Manager manages and, per scope, the command that gives the engine User Access Administrator.
- **Get Started: Workloads step** - A new optional step shows what is missing for Defender XDR, Intune and Power BI, with Confirm or Not used.
- **Who needs what table** - Engine permissions opens with a table listing each identity by name and object id with its rights.

### Fixes

- **Clearer Settings** - A category click goes to the top, the leftover card reads Remove access when its definition is deleted, and the Emergency override card explains itself and stays off until a passphrase is set.

## 3.0.81 · 2026-11-10 · Fix-only

The mail check gives a complete answer, and you no longer see rights you do not need.

### New features

None in this version.

### Fixes

- **Mail check reads both sending identities** - The mail check now checks both sending identities instead of showing a line as not checked. If it cannot read them, the Mail sender step no longer stays open.
- **User Access Administrator shown only when needed** - It is no longer mentioned when no Azure resource delegation is defined.

## 3.0.80 · 2026-11-10 · Feature update

Admin accounts are found by names that end with your admin marker, and Drift shows only what PIM Manager owns.

### New features

- **Admin names can match at start or end** - Recognised admin names accepts * at the start or end, so accounts like jdoe-a-id are found: Admin-* means starts with, *-a-id means ends with.

### Fixes

- **Drift lists only PIM-named objects** - In an area with no definitions, the Drift page and mail list only PIM-named objects. A failed read shows as not checked, and administrative units have their own label.
- **Clearer commit status** - After a commit, the status says queued and on hold instead of saved and waiting.

## 3.0.79 · 2026-11-10 · Fix-only

The Engine permissions check no longer lists rights as missing that the engine already has.

### New features

None in this version.

### Fixes

- **Engine permissions check looks at the engine** - On Get Started and Home, the check now always checks the engine. Before, some installations checked the web app and listed rights as missing that the engine already had.

## 3.0.78 · 2026-11-10 · Security

PIM Manager moves to Microsoft software that is supported until November 2028.

### New features

None in this version.

### Fixes

- **Runs on supported .NET 10 and PowerShell 7.6** - PIM Manager now runs on .NET 10 LTS and PowerShell 7.6 LTS, supported to November 2028, and is patched at every build. The older versions reached end of support on 10 November 2026.
- **Home permission check works again** - The permission check on the Home page no longer fails with an error at some installations.

## 3.0.76 · 2026-11-10 · Security

Every identity PIM Manager creates now has a published list of approved rights, and new installs grant fewer rights.

### New features

None in this version.

### Fixes

- **Published rights list for every identity** - PIM Manager now ships an approved list of rights for every identity it creates, so Invardia can check the live rights every day.
- **Fewer rights for the engine on new installs** - New installations no longer give the engine three Microsoft permissions it never needs.
- **Documentation matches the product** - The documentation now describes the two-line install, the Community nightly updater, the free second approver, evidence export and time-limited support database access as they work.

## 3.0.75 · 2026-11-10 · Feature update

Microsoft Entra access packages can now decide who joins a delegation group, while PIM controls activation.

### New features

- **Entra access packages fill delegation groups** - An access package can decide who joins a delegation group, while PIM still decides how access is activated. It acts only when a package is defined; switching it off hands the groups back to PIM.

### Fixes

None in this version.

## 3.0.74 · 2026-11-10 · Fix-only

You can now tell a job that is still working from one that has stopped.

### New features

None in this version.

### Fixes

- **Working jobs are easy to tell apart** - Every PIM job now notes what it is doing every 5 minutes while it runs, so a working run can be told apart from one that has died.

## 3.0.73 · 2026-11-10 · Fix-only

The support database access step no longer shows a false failure.

### New features

None in this version.

### Fixes

- **Support database access step no longer fails** - The step no longer asks for an extension shorter than 5 minutes, which Microsoft refuses and which showed as a failed step.

## 3.0.72 · 2026-11-09 · Fix-only

The installation report no longer flags a standard identity as non-standard.

### New features

None in this version.

### Fixes

- **Installation report shows documentation job correctly** - The installation report no longer marks the documentation job's identity as non-standard.

## 3.0.71 · 2026-11-09 · Security

The web app needs one right less, because the engine now reads access reviews.

### New features

None in this version.

### Fixes

- **Fewer rights for the web app** - The engine now reads access reviews, so the web app no longer needs an access review right.

## 3.0.70 · 2026-11-09 · Security

Invardia support holds database admin rights only while a support session is open.

### New features

None in this version.

### Fixes

- **Support database access is time-limited** - While a support session is open, the Invardia Support app is a database administrator only until the session ends, at most 24 hours.
- **Guards never hold back an update** - Strict mode only lowers PIM Manager's own change limits; it never blocks an update.

## 3.0.69 · 2026-11-09 · Security

The PIM Manager web app now works with the narrowest rights possible.

### New features

None in this version.

### Fixes

- **Web app runs with the narrowest rights** - PIM Manager keeps only basic user and group reads and Reader on its own resource group. Everything else it shows is read by the engine, as of the last engine run.
- **Documentation job uses its own identity** - The Installation documentation job runs as its own standard identity.
- **Job rename works with a private database** - The job rename step now works at installations with a private database.

## 3.0.68 · 2026-11-09 · Fix-only

PIM jobs can move to their standard names without any risk to your schedule.

### New features

None in this version.

### Fixes

- **Jobs move to standard names safely** - Each PIM job can be re-created under its standard name with the same identity. The schedule switches only after one proven run, and nothing is removed before that.

## 3.0.67 · 2026-11-09 · Fix-only

After an identity move, every check and screen uses the identity each part really runs as.

### New features

None in this version.

### Fixes

- **Setup checks follow the moved identity** - Every setup check, fix command and grant uses the identity each app or job signs in as, and re-running setup keeps it. No right is removed.
- **Screens name each job clearly** - Screens show each job as its role, its real name and the identity it runs as.

## 3.0.66 · 2026-11-09 · Fix-only

Mail keeps working after an identity move, with one clear fix when a send is refused.

### New features

None in this version.

### Fixes

- **Mail fixes name the right identity** - After an identity move, PIM Manager names the identity the engine signs in as. A refused mail send shows one fix command with the real identity, tenant and mailbox.
- **Admin rights stay with the engine** - The identity move never copies User Access Administrator or Owner to any role but the engine.

## 3.0.65 · 2026-11-09 · Fix-only

The identity move now respects your allowed-locations policy and keeps database admin rights where they belong.

### New features

None in this version.

### Fixes

- **Identity move respects allowed locations** - A new identity is created where its app or job already runs, so an allowed-locations policy no longer refuses it.
- **Database admin rights stay with the database job** - The identity move never copies database admin group membership to any role but the database job.

## 3.0.63 · 2026-11-08 · Fix-only

A moved installation no longer shows two setup checks as missing.

### New features

None in this version.

### Fixes

- **No false missing setup checks after a move** - Two setup checks, including Manager may start the engine after a change, now read the identity in use after the identity move, so they no longer show as missing.

## 3.0.62 · 2026-11-08 · Fix-only

The identity move proves every part correctly, and setup steps say clearly when they wait on you.

### New features

None in this version.

### Fixes

- **Identity move proves each part correctly** - The identity move now proves the updater and the web front correctly after they move to their new identity.
- **Clearer waiting status for setup steps** - A setup step that waits on a support ticket now says waiting for the customer, with the ticket number, instead of showing a gap.
- **Approved exceptions are named** - One job can keep its old identity by an owner-approved exception, and the identity check names it.

## 3.0.60 · 2026-11-08 · Fix-only

No more false missing permissions after the identity move.

### New features

None in this version.

### Fixes

- **No false missing permission after a move** - The update check now reads the permissions of the engine's own identity, so no false missing permission shows after the identity move. The Manager finds the engine by its new name.
- **Old database users removed only on request** - Old database users that own nothing and hold no rights are removed only when you ask.
- **Web front move is proven** - Moving the web front's identity now proves that the sign-in page answers and that anonymous access is still refused.

## 3.0.59 · 2026-11-08 · Fix-only

Community installs stop failing the access review job, and the hybrid worker recovers from a bad update by itself.

### New features

None in this version.

### Fixes

- **Community access review job no longer fails** - Community installations no longer fail the access review job every run; it starts only where the edition includes it.
- **Hybrid worker undoes a bad self-update** - After each self-update the hybrid worker tests itself and returns to the previous version if the test fails. This is recorded and shown in its status.
- **Identity move copies only needed rights** - Each role gets only the rights it needs, and the move waits for directory delays before it checks the result.
- **Engine Azure rights can be narrowed** - The engine's User Access Administrator right can be trimmed to the scopes PIM Manager manages.

## 3.0.58 · 2026-11-08 · Fix-only

The updater's ownership proof no longer stays pending, and the sign-in front always matches the release.

### New features

None in this version.

### Fixes

- **Ownership proof no longer stays pending** - The updater checks its app registration ownership proof up to six times, so a slow directory answer no longer leaves it pending.
- **Sign-in front matches the release** - An opted-in installation always builds the sign-in front at this release's version, never a newer shared one.

## 3.0.57 · 2026-11-07 · Fix-only

Every update now shows whether your identities follow the standard and whether old ones still hold rights.

### New features

None in this version.

### Fixes

- **Updates report non-standard identities** - Every update reports whether each identity follows the standard name and whether an old identity still holds rights.
- **Purge protection for the relay password vault** - A Key Vault created by the SMTP relay password setup now has purge protection.
- **Clearer security pack** - The security pack lists the updater's right to change only its own app registrations and describes the database admin group the same way throughout.

## 3.0.56 · 2026-11-07 · Fix-only

Community installations get a clear message on Pro-only pages, and the Community edition has a new licence.

### New features

None in this version.

### Fixes

- **Clear message on Pro pages in Community** - On a Community installation, Pro-only pages show one plain line: This is part of PIM Manager Pro. Your installation is Community.
- **New Community licence** - The Community edition is now licensed under the PolyForm Shield License 1.0.0. The Pro terms ship only in the Pro package.

## 3.0.55 · 2026-11-07 · Fix-only

A Community updater never takes ownership of a Pro app registration in the same tenant.

### New features

None in this version.

### Fixes

- **Community updater owns only its own app** - On a Community installation the updater owns only its own sign-in app registration, never a Pro registration in the same tenant.

## 3.0.54 · 2026-11-07 · Fix-only

PIM Manager's app registrations are owned by the installation's own updater, checked on every update.

### New features

None in this version.

### Fixes

- **The updater owns PIM Manager's app registrations** - Every update checks and reports whether the updater owns PIM Manager's app registrations and proves it once with a harmless change. It never adds itself or removes anyone.

## 3.0.53 · 2026-11-07 · Fix-only

Removing a job identity from the database admin group now works reliably on every group.

### New features

None in this version.

### Fixes

- **Database admin group removal is reliable** - Taking a job identity out of the database admin group now works on role-assignable groups that hide their members, and is checked from both sides.

## 3.0.52 · 2026-11-07 · Fix-only

The Community release is fully separate from Pro, and managed tenants use least-privilege database access.

### New features

None in this version.

### Fixes

- **Community edition runs as before** - The public Community release no longer contains Pro code, and Community installations install, update and run as before. Tenant preparation works in Community.
- **Least-privilege database access on managed tenants** - On a managed tenant, every update gives the job that pulls changes its own least-privilege database user and reports whether it still uses the database admin group.

## 3.0.51 · 2026-11-07 · Fix-only

Database setup never disturbs a running PIM job.

### New features

None in this version.

### Fixes

- **Database setup works safely during job runs** - While a PIM job runs, database setup only adds users, roles and grants; every other step waits. An update no longer starts full database setup during a running job.

## 3.0.50 · 2026-11-06 · Fix-only

Important security alerts now also reach Invardia support, so help can start before you ask.

### New features

None in this version.

### Fixes

- **Security alerts also reach Invardia support** - Live access that differs from your definitions, new unmanaged privileged roles or groups, and break-glass being switched on now also alert Invardia support.
- **Support can tell long jobs from stuck ones** - Update stages and running PIM jobs with their duration are now reported to Invardia support.
- **Right-sized new installations** - A new installation starts at 2 CPU and 4 GiB, or 4 CPU and 8 GiB from 15,000 users, instead of being raised later.
- **Smaller fixes** - A resumed install never reuses another version's package, and settings pages store only the values you set yourself.

## 3.0.49 · 2026-11-06 · Fix-only

Updates on very large tenants no longer give up while a long snapshot is still running.

### New features

None in this version.

### Fixes

- **Updates wait for long snapshots** - An update now waits up to the active-assignments snapshot's usual length, at most 3 hours, instead of 20 minutes. Progress shows every 5 minutes, and a run is never stopped.

## 3.0.48 · 2026-11-05 · Fix-only

Newly granted permissions no longer show as missing while they take effect.

### New features

None in this version.

### Fixes

- **No false missing access after new permissions** - Right after new permissions are granted, the database job and support access no longer show as missing or blocked. A membership that cannot be read yet shows as not yet known.
- **Least-privilege check keeps its result** - The database least-privilege check keeps its result after the updater leaves the database admin group.

## 3.0.47 · 2026-11-05 · Fix-only

Setup and updates now give the database job its access by themselves, with no manual step.

### New features

None in this version.

### Fixes

- **Database job access is set up for you** - Setup and every update add the database job to the database admin group through PIM, check it before the job starts, and renew it before it ends.
- **Clearer status after a new membership** - Right after a new membership, a refused database sign-in shows as waiting, not as a failure.

## 3.0.46 · 2026-11-05 · Fix-only

Approved updates now reach you within minutes, and pages stay fast after large changes.

### New features

None in this version.

### Fixes

- **Approved updates arrive within minutes** - Updates are now checked every 15 minutes on every ring, so an approved version arrives within minutes instead of at night.
- **Pages stay fast after large changes** - PIM Manager keeps its database statistics fresh, so pages stay fast after large writes.

## 3.0.45 · 2026-11-05 · Fix-only

An undone update now tells you why, and the user count is more reliable.

### New features

None in this version.

### Fixes

- **Undone updates say why** - An update undone after its health check now says why: the app could not be read, or the new version did not start.
- **More reliable user count** - The enabled-user count is read again when it cannot be right, for example while an on-premises sync is still writing.

## 3.0.44 · 2026-11-05 · Fix-only

A healthy installation is no longer rolled back when Azure answers slowly.

### New features

None in this version.

### Fixes

- **No rollback of a healthy installation** - Updates no longer roll back a healthy installation when Azure is slow to list app versions.
- **Private installs rebuild their build pool reliably** - A private installation's build pool is always made again after a tier change, also when Azure is slow to remove the old one.
- **Status reports catch up faster** - Status reports to Invardia now catch up within one cycle.

## 3.0.43 · 2026-11-05 · Fix-only

Status reports to Invardia catch up faster.

### New features

None in this version.

### Fixes

- **Status reports catch up faster** - Status reports to Invardia now catch up within one cycle, and your committed changes are still applied while they are sent.

## 3.0.42 · 2026-11-05 · Fix-only

Updates never change the database while a PIM job is running.

### New features

None in this version.

### Fixes

- **Updates never interrupt a running job** - The updater waits up to 20 minutes for running PIM jobs. If they are still running, it waits for a later run and changes nothing.
- **Build pool idle between builds** - A private installation's build pool sits at zero between builds and scales up only for a build.

## 3.0.41 · 2026-11-05 · Security

Invardia support keeps read-only access by default, and each PIM component can move to its own identity safely.

### New features

None in this version.

### Fixes

- **Support access stays read-only** - Invardia support keeps read-only database access, with admin rights only inside an open support session.
- **As-built document reaches support directly** - A private installation's as-built document reaches Invardia support straight from the installation, checked on arrival, with no outside access to its storage.
- **Managing tenant builds clean up after themselves** - A managing tenant build removes its own temporary database admin membership when it finishes.
- **Each component can move to its own identity** - A new script moves each PIM component to its own identity, proving the new one works before any old right is removed.
- **Simpler hybrid worker deploy** - The hybrid worker deploy script is now one self-contained, checked file.

## 3.0.40 · 2026-11-05 · Feature update

PIM Manager shows your own environment name everywhere, and new installations give support read-only access.

### New features

- **Your environment name shows everywhere** - PIM Manager shows the environment name you keep in Invardia in mail subjects, exports, the environment report, the header and the browser tab.

### Fixes

- **Support access is read-only by default** - A new installation gives Invardia support read-only database access, with admin rights only during an open support session.

## 3.0.39 · 2026-11-05 · Fix-only

The database job shows as in place when it really is.

### New features

None in this version.

### Fixes

- **Database job status is correct** - The database job counts as in place when its last run succeeded.
- **Smaller fixes** - Clearer documentation wording, and a sign-in front update with wording changes only.

## 3.0.38 · 2026-11-05 · Fix-only

Every installation now uses the current support access setup.

### New features

None in this version.

### Fixes

- **Support access is brought up to date** - An installation on the earlier support access setup is moved to the current one first. Time-limited admin access for support opens only on the current one.

## 3.0.37 · 2026-11-04 · Feature update

You can export and import templates, and nobody needs standing database admin rights any more.

### New features

- **Export and import a template** - Use Settings > Copy & tools > Export and import a template. Every imported row waits for your review in Pending changes.

### Fixes

- **No person needs database admin rights** - Every installation gets its own in-network database job, kept by updates, and the setup checks report it.
- **Support database access follows your consent** - Invardia support has read-only access, with admin rights only during an open support session and for at most 8 hours.
- **Azure roles use the longest allowed duration** - An Azure role assignment asks for the longest duration the role's PIM policy allows at that scope.

## 3.0.36 · 2026-11-04 · Feature update

You can export and import templates, and nobody needs standing database admin rights any more.

### New features

- **Export and import a template** - Use Settings > Copy & tools > Export and import a template. Every imported row waits for your review in Pending changes.

### Fixes

- **No person needs database admin rights** - Every installation gets its own in-network database job, kept by updates, and the setup checks report it.
- **Support database access follows your consent** - Invardia support has read-only access, with admin rights only during an open support session and for at most 8 hours.
- **Azure roles use the longest allowed duration** - An Azure role assignment asks for the longest duration the role's PIM policy allows at that scope.

## 3.0.35 · 2026-11-04 · Fix-only

When Invardia cannot be reached in time, the update status now says so plainly.

### New features

None in this version.

### Fixes

- **Clear message when Invardia cannot be reached** - When an update cannot reach Invardia in time, the status says so plainly. The next update run asks again, and nothing was changed.

## 3.0.34 · 2026-11-04 · Fix-only

The setup checks now show what is really in place.

### New features

None in this version.

### Fixes

- **Setup checks show what is really in place** - A job that can already read its own runs is no longer listed as missing, and the database access check shows a current result again.
- **Support access counts correctly** - Support database access counts as done when read-only access and the time-limited admin access are in place.

## 3.0.33 · 2026-11-04 · Fix-only

Drift and alerts now show only the groups PIM Manager defines, and private installs stay private.

### New features

None in this version.

### Fixes

- **Drift shows only PIM Manager groups** - Drift, alerts and pages never list a group PIM Manager does not define. Before, a tenant's own groups and their owners showed as drift.
- **Private installs can route through your hub** - A private installation can get a return route for your internal ranges through your hub firewall.
- **Private installs stay private** - A private installation is never opened up, not even for a build or the mail sender setup.

## 3.0.32 · 2026-11-04 · Fix-only

New installations use standard names and clear resource tags.

### New features

None in this version.

### Fixes

- **Standard names for new installs** - A new install uses the standard names and tags its resource group with product, ring, edition, hosting, tenant, owner and purpose. Existing installs keep their names.

## 3.0.31 · 2026-11-04 · Fix-only

A private install no longer stops when it cannot reach a central DNS zone.

### New features

None in this version.

### Fixes

- **Private install carries on without DNS rights** - If a private install may not read or link a central DNS zone, it warns, names the task for your network team and carries on.
- **A failed build pool is replaced** - A build pool left failed by an earlier run is removed and made again.
- **Installer advises only safe changes** - Installer messages now suggest only safe changes.

## 3.0.30 · 2026-11-04 · Fix-only

A private install checks its internet route first instead of creating something that would fail.

### New features

None in this version.

### Fixes

- **Private install checks internet access first** - Before it creates its build pool, a private install checks that the pool can reach the internet. If not, it names your step instead of creating a pool that would fail.

## 3.0.29 · 2026-11-04 · Feature update

Four-eyes approval and the evidence export are now part of Community as well as Pro.

### New features

- **Four-eyes approval and evidence export in Community** - The second approver and the evidence and audit export are now part of both Community and Pro. Core security is the same in both editions.

### Fixes

- **Shorter application access dialog** - The dialog for letting applications ask for access is shorter, with the tier rule under More info.

## 3.0.28 · 2026-11-04 · Fix-only

Community installs get the same sign-in front as Pro, with the same core security.

### New features

None in this version.

### Fixes

- **Community gets the same sign-in front** - A Community install's updater now builds the sign-in front like Pro does, so an existing Community install can move off Easy Auth.

## 3.0.27 · 2026-11-04 · Fix-only

Azure role assignments with a time limit apply again instead of failing.

### New features

None in this version.

### Fixes

- **Time-limited Azure roles apply again** - Azure role assignments that a scope's PIM policy limits in duration now apply at the longest allowed duration. Before, they failed.
- **Power BI checks only when used** - With Power BI switched off and nothing defined for it, its prerequisites are no longer checked or shown.
- **Clearer workload prerequisites** - A prerequisite that only the portal can show now says first that Confirm or Not used closes it.
- **Sign-in clean-up** - A new install removes a sign-in setting it no longer needs once sign-in is live.

## 3.0.26 · 2026-11-04 · Fix-only

Get Started no longer blocks a SuperAdmin who may approve their own break-glass list.

### New features

None in this version.

### Fixes

- **Approve your own break-glass list** - In Get Started, with self-approval on, the SuperAdmin who raised the break-glass list can approve it right in the step.
- **Templates banner shows where to switch** - The Templates preview banner now names its switch: Settings > Features & edition > Governance preview.

## 3.0.25 · 2026-11-04 · Fix-only

The installer checks your Azure region first, and private installs keep their Key Vault private.

### New features

None in this version.

### Fixes

- **Installer checks the Azure region first** - The installer checks that the chosen Azure region accepts new resources before it creates anything.
- **Private Key Vault stays private** - A private install keeps its Key Vault private, also after a deleted vault is recovered.
- **Smaller fixes** - The PIM Manager address reaches Invardia from the first update, and every hand-over file is in the checksum list.

## 3.0.24 · 2026-11-03 · Fix-only

Shorter install commands, and Invardia sees the true state of every setup step.

### New features

None in this version.

### Fixes

- **Invardia sees the true setup state** - Invardia's install view now shows the true state of every one-time setup step instead of unknown.
- **Shorter install commands** - The second install line carries only the tenant, subscription, region and the options you actually chose.
- **Private installs check DNS zones first** - A private-network install checks every private DNS zone it needs before it creates anything, and names all missing ones at once.
- **Running the installer twice works** - Running the installer twice in the same PowerShell window no longer fails; it signs in again.
- **Cleaner release package** - Every release package from Invardia is checked before it is published.

## 3.0.23 · 2026-11-03 · Fix-only

Every installation reports its setup steps to Invardia, so all installations can be kept the same.

### New features

None in this version.

### Fixes

- **Setup steps are reported to Invardia** - Every install reports its one-time setup steps to Invardia from a real check on every update, so all installs can be kept the same.
- **As-built report storage respects your policy** - Where a tenant policy forbids public access, the as-built report storage is created private, and a refusal no longer stops the rest of the setup.
- **No more could-not-check message** - The updater no longer says it could not check the engine permissions.

## 3.0.22 · 2026-11-03 · Fix-only

Community updates no longer fail on a short Invardia hiccup.

### New features

None in this version.

### Fixes

- **Community updates retry on short outages** - When the nightly updater gets no answer from Invardia, it asks again after 30 seconds, 1 minute and 2 minutes before it records a failure.

## 3.0.21 · 2026-11-03 · Fix-only

Updates no longer fail on a short Invardia hiccup.

### New features

None in this version.

### Fixes

- **Updates retry on short outages** - When the nightly updater gets no answer from Invardia, it asks again after 30 seconds, 1 minute and 2 minutes before it records a failure.

## 3.0.20 · 2026-11-03 · Security

PIM Manager roles are linked to the person, not to the sign-in name.

### New features

None in this version.

### Fixes

- **Manager access follows the person** - Each Manager access entry is linked to the person's Entra object. Nobody loses access during the change.

## 3.0.19 · 2026-11-02 · Feature update

You can install PIM Manager on a private network, or make an existing install private, with the same two lines.

### New features

- **Private network with the same two lines** - Add the private network option to the two install lines to install privately or to turn an existing public installation private. The database and registry get public access off.
- **Use your own network and hub** - You can use an existing network in another resource group and peer it with your hub. Rights are checked first, and private DNS zones can be linked to the hub.

### Fixes

None in this version.

## 3.0.18 · 2026-11-02 · Feature update

One installer now serves every edition, with no edition to choose.

### New features

- **One installer for Community and Pro** - One installer file serves Community, Pro and Trial, with no edition to choose in the command. The update ring defaults to 3.
- **Install through the Invardia Support app** - An install can be run through the Invardia Support app, which gets Troubleshoot access by default.

### Fixes

None in this version.

## 3.0.17 · 2026-11-02 · Feature update

Installing takes two lines, and Trial and Pro licences arrive by themselves.

### New features

- **Your licence arrives by itself** - Trial and Pro installs ask Invardia for their licence right after the install. A trial needs no approval.
- **Install with two lines** - Install with two lines, with every setting as a parameter and no answer file.

### Fixes

- **Support database access needs your consent** - Time-limited support database access is given only with your consent.
- **Smaller fixes** - The support session shows its end time in UTC.

## 3.0.16 · 2026-11-02 · Security

Stronger protection for scripts, updates and sign-ins across PIM Manager.

### New features

None in this version.

### Fixes

- **Published scripts need PowerShell 7** - Every script published for you now needs PowerShell 7 and lists the role you need and the addresses it reaches.
- **Checked hybrid worker installs** - Security improvements for hybrid worker installs.
- **Local PIM Manager opens with a one-time link** - The local PIM Manager opens with a one-time link.
- **Access-request keys can be limited** - Access-request keys and applications can now be limited to named groups.
- **Smaller fixes** - Stronger sign-in checks, the hub owner script runs on its own again, and more AI assistant tools are listed.

## 3.0.15 · 2026-11-01 · Security

Stronger protection for the hybrid worker server on an Azure VM.

### New features

None in this version.

### Fixes

- **Stronger protection on the hybrid worker server** - Security improvements for the managed identity of the hybrid worker server on an Azure VM. Setup and the daily update keep these settings.

## 3.0.14 · 2026-11-01 · Security

Your update key is tied to your own installation.

### New features

None in this version.

### Fixes

- **Update key tied to your installation** - Each installation has its own lasting id with Invardia, and its update key is tied to it. The id is kept across updates and is separate from anonymous telemetry.

## 3.0.13 · 2026-11-01 · Fix-only

The API and MCP reference and API applications are now part of PIM Manager Pro.

### New features

None in this version.

### Fixes

- **API and MCP reference is part of Pro** - The API and MCP reference page and API applications are now part of PIM Manager Pro, like the AI assistant. The PIM Manager page itself works the same in both editions.

## 3.0.12 · 2026-11-01 · Feature update

Your scripts and AI assistant can now do more, while a person still saves every change.

### New features

- **API and MCP reference in Settings** - Find it under Settings > API and MCP reference, shown for your own role, with a plain description of each route.
- **More AI assistant tools** - The assistant can now decide and end access requests, and read conformance, role permissions, commit history, permissions health and the config backup list.
- **Scripts and services can use PIM Manager** - SuperAdmins can allow named applications to read, prepare changes and run jobs. It is off by default, and a person still saves every change.

### Fixes

None in this version.

## 3.0.11 · 2026-11-01 · Security

Security improvements for self-service requests, policy baselines and hybrid worker updates.

### New features

None in this version.

### Fixes

- **Stronger protection for self-service requests** - Security improvements for self-service group requests.
- **Signed policy baselines** - Security improvements for policy baselines.
- **Signed hybrid worker updates** - Security improvements for the hybrid worker's daily update.
- **Stronger self-service sign-in** - Security improvements for self-service sign-in and PINs.

## 3.0.10 · 2026-10-31 · Feature update

You can now set a time of day by which every PIM Activator activation ends.

### New features

- **Set a daily end time for activations** - On the Client onboarding page, set a time of day by which every PIM Activator activation ends.

### Fixes

- **Mail send right stays in place** - A mail send right is never removed when Exchange does not report a scope's filter.
- **Managed tenants set up mail themselves** - A managed tenant build no longer sets up the mail sender. Your Exchange administrator does it under Get Started > Mail sender.
- **Hybrid worker removal keeps shared servers** - Removing the hybrid worker keeps the server when another product is registered on it, or when that cannot be checked.

## 3.0.9 · 2026-10-31 · Fix-only

Browser sign-ins in the setup and PIM Activator scripts now finish without an error page.

### New features

None in this version.

### Fixes

- **Browser sign-ins finish properly** - Browser sign-ins in the setup and PIM Activator scripts no longer end with "This site can't be reached".

## 3.0.8 · 2026-10-31 · Fix-only

Installing no longer creates a mailbox or gives the installing account an Exchange role.

**Action needed:** Have your Exchange administrator set up mail under Get Started > Mail sender.

### New features

None in this version.

### Fixes

- **Mail sender is set up separately** - The installation no longer creates a mailbox, and the installing account gets no Exchange role.
- **Hybrid worker removal keeps shared servers** - Removing the hybrid worker leaves the server standing when another product's worker runs on it, and removes only PIM Manager's own part.

## 3.0.7 · 2026-10-30 · Fix-only

The monthly management report is never switched on by surprise.

### New features

None in this version.

### Fixes

- **Monthly report switch explains itself** - The monthly management report switch explains itself under More info and asks you before it is switched on.

## 3.0.6 · 2026-10-29 · Feature update

Pro can now build a management report as a PowerPoint and mail it every month.

### New features

- **Management report as a PowerPoint** - In Pro, build a PowerPoint under Reports > Management report from the sections and period you pick.
- **Monthly report by mail** - Mail a monthly report to the people you choose. It is off by default.

### Fixes

- **Missing figures are labelled** - A report figure that cannot be read says so instead of showing 0.

## 3.0.5 · 2026-10-29 · Feature update

PIM Manager installs in two lines, and settings can be exported and imported.

### New features

- **Install in two lines** - PIM Manager installs in two lines with a browser sign-in, in Community and Pro alike.
- **Export and import settings** - You can export your settings to a file and import them from one.
- **Guards show a red count** - The Guards menu shows a red count when a guard holds changes for a SuperAdmin.
- **New options, off by default** - Eligible group owners and a nightly demo reset are built in, both off by default.

### Fixes

- **Engine rights follow your scopes** - The engine's Azure rights follow the scopes you define, never Owner. After an update, PIM Manager reports any new permission the engine needs.
- **Fewer unneeded engine runs** - Engine runs are skipped when nothing changed; a full check still runs every 4 hours.
- **No false not role-assignable label** - An Azure refusal that heals on the next run is no longer labelled group not role-assignable.
- **Smaller fixes** - The Departments grid no longer shows blank rows, and restoring a list setting keeps its keys.

## 3.0.4 · 2026-10-28 · Fix-only

Jobs no longer fail right after you save a new role.

### New features

None in this version.

### Fixes

- **New groups no longer cause failed jobs** - A group PIM Manager creates is recorded straight away, so a run that starts meanwhile no longer reports it as waiting for adoption. Jobs no longer fail right after you save a new role.

## 3.0.3 · 2026-10-28 · Fix-only

A Community install's deployment plan now shows the update ring it really gets.

### New features

None in this version.

### Fixes

- **Deployment plan shows the right ring** - A Community install's deployment plan now shows the update ring it really gets.
- **Smaller fixes** - A clearer folder layout for the setup scripts, and a security pack that describes the update checks exactly.

## 3.0.2 · 2026-10-28 · Feature update

PIM Manager Community now keeps itself up to date from the signed public release.

### New features

- **Community updates itself** - PIM Manager Community updates itself at night from the signed public release, or when you start it by hand. Either way the release is checked before anything changes.

### Fixes

- **Single-tenant installs stay single-tenant** - A single-tenant install no longer switches on MSP features.
- **Removed items stay hidden** - Removed admins, groups and administrative units no longer show in reports, search or the Home counts.
- **No automatic major version jumps** - An update never moves to a new major version on its own.

## 3.0.1 · 2026-10-28 · Fix-only

Community installs can take updates that change the policy baseline.

### New features

None in this version.

### Fixes

- **Community accepts baseline updates** - A Community install can now take an update that changes the policy baseline.
- **Clear message for Pro-only setup** - The multi-tenant setup scripts now say they need PIM Manager Pro instead of failing in a Community install.

## 3.0.0 · 2026-10-28 · Fix-only

PIM Manager 3.0 starts a new generation with short version numbers.

### New features

None in this version.

### Fixes

- **A new generation: PIM Manager 3.0** - PIM Manager 3.0 starts a new generation, with short version numbers from now on.
- **Each edition shows its own logo** - Community shows the Community logo in mails and printed reports, as the portal header already does. Pro keeps the Pro logo.

## 2.4.679 · 2026-10-27 · Fix-only

Deleted groups disappear from PIM Manager once they are gone from Entra ID.

### New features

None in this version.

### Fixes

- **Deleted groups no longer linger** - After PIM Manager deletes a group marked for deletion, the group disappears from every view. Deletion counts and warnings count only groups that still exist in Entra ID.

## 2.4.678 · 2026-10-27 · Fix-only

Run now works reliably for the tenant list, and removed admins, groups and delegations no longer clutter your lists.

### New features

None in this version.

### Fixes

- **Run now works for the tenant list** - Refreshing the tenant list with Run now no longer fails or keeps a shorter list of Azure scopes. A partly refused read keeps the fuller list you already had.
- **Removed items are hidden in lists** - Deleted admins, retired groups and removed delegations no longer show in the record lists. A Show removed link brings them into view when you need them.
- **Deleted accounts show their real state** - After Delete account, the admin shows Marked for deletion until PIM Manager has deleted it. The account is deleted only after its group memberships are removed.
- **Fewer failed runs from short faults** - PIM Manager retries its Azure sign-in a few times before a run fails, and the coverage report is always saved.

## 2.4.677 · 2026-10-27 · Fix-only

You can no longer miss changes that still wait for Commit.

### New features

None in this version.

### Fixes

- **Uncommitted changes show in the menu** - Changes you staged but did not commit show as a red count on Pending changes in the menu. You see at once that nothing happens until you commit them.

## 2.4.676 · 2026-10-27 · Feature update

You can delete admin accounts from the Administrator accounts list, and refused deletions now tell you what to do.

### New features

- **Delete account button for admins** - The Administrator accounts list now has a Delete account button.

### Fixes

- **Clear answer when group deletion is off** - Deleting a group while group deletion is switched off is now refused and tells you what to do. Before, the change was committed and nothing happened.
- **Clear answer for on-premises AD admins** - Delete account on an on-premises AD admin now says at once that PIM Manager does not delete AD accounts, and what to do instead.

## 2.4.675 · 2026-10-27 · Fix-only

The Access map shows only access that is actually granted.

### New features

None in this version.

### Fixes

- **Access map shows only granted access** - The Access map no longer shows deleted admins, retired groups or removed delegations. It draws only access that is granted today.

## 2.4.674 · 2026-10-27 · Fix-only

Brief Azure sign-in hiccups no longer fail job runs.

### New features

None in this version.

### Fixes

- **Short sign-in faults no longer fail runs** - A one-off fault in PIM Manager's Azure sign-in no longer fails a job run. PIM Manager tries again, and a lasting fault is reported as temporary, not as a product defect.

## 2.4.673 · 2026-10-24 · Fix-only

Healthy installations are no longer wrongly reported as not fully updated.

### New features

None in this version.

### Fixes

- **Healthy installations report as updated** - The nightly update no longer rewrites parts that are already on the new version. A healthy installation is no longer reported as not fully updated.

## 2.4.672 · 2026-10-24 · Fix-only

PIM Manager no longer takes over existing groups without an administrator's approval.

### New features

None in this version.

### Fixes

- **Existing groups are never taken over silently** - A group that matches a name defined in PIM Manager, but was not created by it, now waits until an administrator adopts it on Jobs > Engine logs and errors.
- **Copy button confirms reliably** - On the Engine logs page, the Copy button now confirms every copy.

## 2.4.671 · 2026-10-23 · Feature update

Database security events are now kept in your own Log Analytics workspace, and the nightly update recovers from short network faults.

### New features

- **Database security events are recorded** - PIM Manager's database now records security events, such as sign-ins and permission changes, in your own Log Analytics workspace for 90 days. New and existing installations get it.
- **About card on the Support page** - The Support page now has an About card with the Invardia legal line.

### Fixes

- **Tier impact report shows level separately** - The Tier impact report takes the tier from the tier marker and shows the level in its own column.
- **Nightly update recovers from network faults** - A nightly update that hits a short network fault while storing the new version retries once. A second failure is reported in plain words.

## 2.4.670 · 2026-10-23 · Fix-only

Screens show plain names and words instead of internal ids; nothing behaves differently.

### New features

None in this version.

### Fixes

- **Plain names instead of internal ids** - Held policy change sets name each rule in words, such as Maximum activation duration. The Guards page and Features cards show names instead of internal ids.
- **Clearer Workload templates and Drift texts** - The Workload templates page says the packs come with PIM Manager, and the Drift note says plainly what the read-only check finds.

## 2.4.669 · 2026-10-23 · Fix-only

Screen texts are clearer and accurate; nothing behaves differently.

### New features

None in this version.

### Fixes

- **Approval texts say what really happens** - The Approvals page says a SuperAdmin can allow self-approval. Approve all says each held policy change set is approved for its exact plan only.
- **Break-glass list explains its effect** - The Break-glass list says it exempts an account from every revoke, disable and offboard action.
- **Plain names in Settings and guards** - Settings and guard names show plain names instead of internal ids and reference numbers.
- **Smaller text improvements** - The Drift note explains what the stray-object sweep finds, the Community vs Pro page says permission templates are imported in the portal, and the Entra roles pack is named PIM Manager reference set.

## 2.4.668 · 2026-10-23 · Feature update

One administrator can now offboard most admins directly, with a second approval kept for the most sensitive accounts.

### New features

- **One administrator can offboard an admin** - You can now delete, remove, disable or offboard an admin directly. A second administrator approves only for tier 0 admins, break-glass accounts, or when the Pro second approver is on.

### Fixes

- **Every offboarding step is audited** - Deleting is always done by a person, never automatically, and every such action is in the audit trail.
- **All levels L0-L9 are counted** - Home and the per-level count now include levels L6-L9. An L7 group was counted as L1 before.

## 2.4.667 · 2026-10-22 · Feature update

PCs and servers without Intune get the same PIM Activator limits and filters as Intune-managed ones.

### New features

- **Same Activator settings without Intune** - The PIM Activator install for PCs and servers without Intune now takes the same limits and name filters as the Intune install. PIM Manager shows the command with your settings filled in.

### Fixes

- **Edge profile tip in the setup step** - The Edge for Business step tells you that a new Edge profile gets the extension once it signs in with the work account.
- **Signed-request check runs when switched on** - The optional signed-request check, off by default, now runs correctly when you switch it on.

## 2.4.666 · 2026-10-22 · Fix-only

The setup script for private installations on the shared sign-in front is now published and documented.

### New features

None in this version.

### Fixes

- **Sign-in front script is published** - The script that prepares a private installation for the shared sign-in front is now published with its own documentation page and a preview mode, like every other support script.

## 2.4.665 · 2026-10-22 · Fix-only

Short network errors no longer fail the nightly update or a job.

### New features

None in this version.

### Fixes

- **Short network errors no longer fail runs** - A one-off network error no longer fails the nightly update or a job. PIM Manager tries again up to three times and never repeats a request that may already have run.

## 2.4.664 · 2026-10-22 · Fix-only

PIM Manager behind the sign-in front is no longer wrongly reported as undersized.

### New features

None in this version.

### Fixes

- **No false undersized warning** - A PIM Manager behind the sign-in front is no longer reported as undersized at the end of an installation or in the environment report.

## 2.4.663 · 2026-10-21 · Fix-only

New installations complete again instead of stopping while PIM Manager is built.

### New features

None in this version.

### Fixes

- **New installations finish again** - A new installation no longer stops while building PIM Manager because Azure refused the request.

## 2.4.662 · 2026-10-21 · Feature update

New installations sign people in through the shared sign-in front, and dates read the same everywhere.

### New features

- **Install through the Invardia Support app** - An installation can now run as the Invardia Support app. The administrators come from your answers, so no person has to sign in.

### Fixes

- **New installations use the shared sign-in front** - A new installation from the website now ends on the shared sign-in front, with its own Key Vault and its own database.
- **Dates in one clear format** - PIM Manager, the access-request portal and the PIM Activator popup show dates as yyyy-MM-dd HH:mm in local time, never in US format.

## 2.4.661 · 2026-10-21 · Fix-only

Direct groups for Entra ID roles no longer fail at Commit.

### New features

None in this version.

### Fixes

- **Direct groups for Entra roles no longer fail** - Creating a direct group now asks Role-assignable after you pick the permission groups. A group that reaches an Entra ID role is always role-assignable, so it no longer fails at Commit.
- **Status reports to Invardia arrive in full** - A status detail that looked like a password made Invardia refuse some status fields for a day. That detail is no longer sent.

## 2.4.660 · 2026-10-21 · Fix-only

New admins are linked to their company and department at once, and setup scripts sign in more reliably.

### New features

None in this version.

### Fixes

- **New admins are linked at once** - A new consultant admin is linked at once to its external company and internal department, and an internal admin to its department.
- **Mail-sender setup no longer fails** - The mail-sender setup reuses what is already in place instead of failing.
- **Setup sign-in works in more cases** - Browser sign-in in the setup scripts works when your PC uses IPv6 for localhost, and an Azure Arc or VM machine identity no longer blocks it.

## 2.4.659 · 2026-10-21 · Fix-only

People who sign in through the sign-in front stay signed in.

### New features

None in this version.

### Fixes

- **Sessions stay signed in** - The sign-in front no longer sends people back to sign in, and a session no longer ends after about an hour.

## 2.4.658 · 2026-10-21 · Feature update

The sign-in front works again, and support scripts sign in in more situations.

### New features

- **Script for least database rights** - A new support script sets PIM Manager's database access to the least rights each part needs.

### Fixes

- **Sign-in front works again** - The previous sign-in front update failed on every page. It now works and keeps longer-lasting sessions.
- **Support scripts sign in more reliably** - Support scripts reach a private database from inside the network without a firewall rule, and sign in when localhost means IPv6 or a machine identity is present.

## 2.4.657 · 2026-10-21 · Fix-only

People signed in through the sign-in front stay signed in across restarts and updates.

### New features

None in this version.

### Fixes

- **Sessions survive restarts and updates** - People who sign in through the sign-in front stay signed in across restarts and updates. Old sign-in cookies no longer block a sign-in.
- **Scripts tell the sign-in front apart** - Rollback and version checks no longer mistake the sign-in front for PIM Manager.

## 2.4.656 · 2026-10-21 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.655 · 2026-10-20 · Fix-only

Pages load again behind the sign-in front and no longer sign out by themselves.

### New features

None in this version.

### Fixes

- **Pages load behind the sign-in front again** - On installations that opted in to the sign-in front, pages load again and the hourly silent refresh no longer signs a page out.

## 2.4.654 · 2026-10-20 · Fix-only

Large tenants get a lighter, faster active-assignments refresh.

### New features

None in this version.

### Fixes

- **Lighter refresh on large tenants** - On large tenants, the active-assignments list re-reads only groups that changed, with a full read once a week, instead of every group every 2 hours.

## 2.4.653 · 2026-10-19 · Fix-only

Runs that Azure stopped early now explain themselves.

### New features

None in this version.

### Fixes

- **Stopped runs explain themselves** - A scheduled run that Azure stopped before it finished now shows its own error code and explanation, not an unrecognised failure.

## 2.4.652 · 2026-10-18 · Fix-only

Unfinished updates and a missing Pro licence are now explained clearly.

### New features

None in this version.

### Fixes

- **Clearer errors for updates and licences** - An update that has not reached every app yet, and a missing Pro licence, now each show their own error code and explanation.

## 2.4.651 · 2026-10-18 · Fix-only

Every mail from PIM Manager now comes from a sender simply named PIM Manager.

### New features

None in this version.

### Fixes

- **Mail sender is named PIM Manager** - Mails now come from a sender named "PIM Manager", without extra parts. New installations get it at once, existing ones once renaming is switched on.

## 2.4.650 · 2026-10-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.649 · 2026-10-18 · Fix-only

Updates report their state more accurately, and Invardia Support keeps the access it needs to help you.

### New features

None in this version.

### Fixes

- **No false out-of-date reports** - An update now retries a part whose request was lost on the network, instead of reporting it out of date.
- **Invardia Support access stays in place** - PIM Manager never removes the Invardia Support app's database access, and the setup check now finds that access reliably.
- **Safer move to the sign-in front** - The move to the sign-in front waits until the new version is running before it switches the old sign-in off.

## 2.4.648 · 2026-10-18 · Fix-only

Moving PIM Manager onto the shared sign-in front is no longer refused by Azure.

### New features

None in this version.

### Fixes

- **Sign-in front move fits Azure limits** - Behind the shared sign-in front, PIM Manager keeps at most 3.75 CPU and 7.5 GB, so Azure no longer refuses the move. Updates never raise it past that.

## 2.4.647 · 2026-10-18 · Fix-only

You can see when you run a pre-release version, and new sign-in protections are ready to switch on.

### New features

None in this version.

### Fixes

- **Header shows pre-release versions** - While your installation runs an early version, the header shows Ring N - Pre-release with its name.
- **Display names can read PIM Manager** - Once that option is on, the update renames the display names people read to "PIM Manager". New installations can choose short resource names.
- **Stronger protection for app permissions** - Setup now checks the web app's permissions in a stronger way.
- **Sign-in without stored secrets prepared** - PIM Manager can sign in through a shared sign-in front without a stored secret, and changes can carry the signed-in user's proof. Both are off by default.
- **Smaller improvements** - Closer status reporting to Invardia after an engine update, and corrected test checks.

## 2.4.646 · 2026-10-18 · Security

Installations with a private database move to the least database rights on their own, safely.

### New features

None in this version.

### Fixes

- **Least database rights, set up by itself** - Installations with a private database now move to the least-privilege database model on their own. Broad rights are removed only after clean engine runs, and restored if a check fails.
- **Planned stops are no longer problems** - A run that PIM Manager stops on purpose, such as during an update or a restart, is no longer reported as a problem.
- **Azure role lookups retry** - A failed Azure role lookup gets its own error code and is retried on the next run instead of being called unrecognised.
- **Failing nightly updates are never hidden** - Frequent update checks can no longer hide a failing nightly update, and every engine run report names the first area that failed.

## 2.4.645 · 2026-10-17 · Fix-only

Mails are easy to read on a phone and Active assignments opens fast on large tenants.

### New features

None in this version.

### Fixes

- **Mails read well on a phone** - Mails put the summary first, use no tables and give each item its own topic line, so they are easy to read on a phone.
- **Active assignments opens fast** - The Active assignments page opens fast on a large tenant.
- **Least database rights for Community** - Community installations can now use the least-privilege database model too.
- **Smaller improvements** - Updates can be started at once, and status reports to Invardia carry more counts.

## 2.4.644 · 2026-10-16 · Fix-only

Fewer false warnings, and status reports to Invardia arrive more completely.

### New features

None in this version.

### Fixes

- **Fewer false warnings** - Database access that is already in place is no longer reported as refused, and a new installation no longer logs a false setup failure.
- **Status reports reach Invardia in full** - One refused status field no longer holds back all the others.

## 2.4.643 · 2026-10-16 · Fix-only

Community installations never ask for a Pro licence, and new installations start with the least database rights.

### New features

None in this version.

### Fixes

- **Community never asks for a Pro licence** - A Community installation no longer asks Invardia for a Pro licence.
- **Least database rights from day one** - New installations get the least-privilege database model during setup.

## 2.4.642 · 2026-10-16 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.641 · 2026-10-16 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.640 · 2026-10-16 · Fix-only

A short licence read fault no longer looks like a missing licence.

### New features

None in this version.

### Fixes

- **Licence reads retry** - The updater retries a licence read that fails once and names the real cause, instead of saying that no licence is installed.

## 2.4.639 · 2026-10-15 · Fix-only

Alert mails are fewer and more useful, and PIM Manager runs with fewer database rights.

### New features

None in this version.

### Fixes

- **Alert mails point to the fix** - An alert mail now names the error code with a link to its page. Licence gaps, throttling and problems already fixed no longer send an alert mail.
- **Long quiet steps are not called stopped** - A long step that reports nothing for a while is no longer mistaken for a stopped run.
- **Fewer database rights needed** - The engine and the portal run with fewer database rights.

## 2.4.638 · 2026-10-15 · Feature update

Support can see what went wrong and how to fix it before you call.

### New features

- **Error codes help support help you** - Every problem a job reports now carries a stable error code and its cause, so support knows the fix before you call. The switch Send error codes and causes to Invardia is on by default.

### Fixes

None in this version.

## 2.4.637 · 2026-10-15 · Feature update

A SuperAdmin can cancel a running engine run, and stuck runs are reported.

### New features

- **Cancel a running engine run** - A SuperAdmin can cancel a running engine run from the Jobs page. A cancelled run is final and never resumes.

### Fixes

- **Stuck runs are reported** - A run that makes no progress for an hour is reported while it keeps running.
- **Runs continue on the new version** - After an update, a run still on the old version is stopped and runs again on the new one.
- **Managed-tenant steps start sooner** - The managed-tenant pull and the publish see at once when an earlier run has ended.

## 2.4.636 · 2026-10-15 · Fix-only

Long runs on very large tenants are never cut short.

### New features

None in this version.

### Fixes

- **Long runs are never cut short** - Every job can now run for up to 7 days, set at install and on every update, so a long run on a very large tenant is never cut short.

## 2.4.635 · 2026-10-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.634 · 2026-10-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.633 · 2026-10-15 · Feature update

The product documentation is now inside PIM Manager, and each part keeps only the database rights it needs.

### New features

- **Documentation inside PIM Manager** - Settings > Documentation now holds the product documentation, also on installations on a private network.

### Fixes

- **Least database rights on every update** - Each part of PIM Manager gets only the database rights it needs, and every update keeps it that way.

## 2.4.632 · 2026-10-14 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.631 · 2026-10-14 · Security

Security hardening for PIM Manager's pages and its database rights.

### New features

None in this version.

### Fixes

- **Stronger protection for every page** - Every PIM Manager page carries extra browser security settings.
- **Fewer rights for the web app** - PIM Manager's web app runs with fewer database rights.

## 2.4.630 · 2026-10-14 · Fix-only

Guards are extra careful for a day after an engine update.

### New features

None in this version.

### Fixes

- **Stricter guards after engine updates** - For 24 hours after an update that changes the engine, every guard with a number uses half its limit. A SuperAdmin can end this early.
- **Daily data-quality mail removed** - The data-quality check and its daily mail are gone.

## 2.4.629 · 2026-10-14 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.628 · 2026-10-14 · Fix-only

Mail subjects are consistent and Discovery no longer repeats the same mails.

### New features

None in this version.

### Fixes

- **Mail subjects in one format** - Every mail subject reads environment, severity, what happened and PIM Manager, so you can sort and filter mails easily.
- **No repeated Discovery mails** - Discovery remembers what it has already reported, so the same item is not mailed again.
- **Smaller fixes** - The data-quality check compares like with like, and the licence request is more robust.

## 2.4.627 · 2026-10-14 · Feature update

PIM Manager can add its groups to your Power BI workspaces after one setup step.

### New features

- **Power BI workspaces in one setup step** - One setup line, run by a person who signs in, adds PIM Manager to the Power BI workspaces it manages. PIM Manager then adds the PIM groups itself, and only adds.

### Fixes

None in this version.

## 2.4.626 · 2026-10-14 · Fix-only

No more false failed mails when two engine runs overlap.

### New features

None in this version.

### Fixes

- **No more false failed mails** - When two engine runs collide, the run record is kept and saved again. A lost record is reported as interrupted, never as failed.

## 2.4.625 · 2026-10-14 · Fix-only

When Power BI refuses a change, you see its full reason.

### New features

None in this version.

### Fixes

- **Power BI refusals show the full reason** - When Power BI refuses a change, PIM Manager shows Power BI's own answer first, so the reason is never cut off.

## 2.4.624 · 2026-10-14 · Feature update

PIM Manager can now manage Power BI workspace roles, and its screens speak in calmer, plainer words.

**Action needed:** Run the workload prerequisites script once to grant the Fabric Administrator role.

### New features

- **Power BI workspace roles** - PIM Manager can now add PIM groups to Power BI workspace roles. It only adds, never removes.
- **Hybrid worker is a switch** - The hybrid worker is now a feature you switch on. It is off by default.
- **Self-approve break-glass changes** - Break-glass changes can be self-approved when self-approval is on.

### Fixes

- **Calmer dialogs and pages** - Switch dialogs show one calm line with details behind More info. Guards say Protecting or Holding back changes, and Jobs shows no more overdue noise.

## 2.4.623 · 2026-10-13 · Fix-only

Alert mails are calmer and easier to act on.

### New features

None in this version.

### Fixes

- **Alert mails are easier to act on** - Alert mails start with the environment name and a calm summary, then the facts, the cause and the fix in plain words, and one button. Technical details come last.
- **Clear error for a missing Power BI workspace** - A Power BI workspace that cannot be found now has its own clear error.

## 2.4.622 · 2026-10-13 · Fix-only

The mail-sender setup tells you why Exchange refused a step.

### New features

None in this version.

### Fixes

- **Mail-sender setup shows Exchange's reason** - When Exchange refuses a step in the mail-sender setup, you now see Exchange's own reason instead of a bare error.

## 2.4.621 · 2026-10-13 · Feature update

Every Access list shows a State column, so problems stand out at a glance.

### New features

- **State column on Access lists** - Every list under Access now has a State column for accounts and groups, with problems first and in colour. A queued new account is never shown red.

### Fixes

- **Gone accounts leave the plan** - Deleted admins whose account no longer exists are no longer planned to be created again.
- **Smaller fixes** - A notice about AD rights for older hybrid installations, reconcile says Left alone, and AD clean-up times show in local time.

## 2.4.620 · 2026-10-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.619 · 2026-10-13 · Feature update

Deleting and revoking access is more precise and better guarded, with new limits you control.

### New features

- **Limits for bulk revoke and admin delete** - You can set bulk-revoke and admin-delete limits on the Guards page.
- **Central admin delete for MSPs** - In an MSP setup, a central admin can be deleted with the managing tenant SuperAdmin's approval, one per run.

### Fixes

- **Deletes and revokes act precisely** - An account delete acts once on the exact account, and deleting and revoking follow scope and level everywhere.
- **Sponsors propose, others approve** - A sponsor proposes a change and someone with permission approves it, never the sponsor themselves.
- **Large withdrawals are held** - Withdrawals from managed tenants above the customer limit are held on the Guards page, and a SuperAdmin can release every hold.
- **Mails name the environment** - Mails show the environment name, never a bare tenant id.

## 2.4.618 · 2026-10-13 · Feature update

Guard holds need a SuperAdmin, AD sync never removes on a doubt, and AD clean-up can be approved in batches.

### New features

- **SuperAdmin approves guard holds** - Changes held by a guard now need a SuperAdmin's approval, with counts on the Guards page.
- **Approve AD clean-up in batches** - AD clean-up and server groups can now be approved in batches.
- **List menu and two protection switches** - Every list has a list menu, and Settings has two new protection switches.

### Fixes

- **AD sync never removes on a doubt** - When AD sync is not sure, it removes nothing.
- **Smaller fixes** - Clear group states with one remove or delete dialog, revoking by scope and level, a settings clean-up, and a retry after a create.

## 2.4.617 · 2026-10-13 · Feature update

A SuperAdmin decides whether PIM Manager may delete groups, and sees how many before confirming.

### New features

- **Switch for group deletion** - A SuperAdmin can switch group deletion on in Settings > Approvals & policy > Group deletion. The confirmation says how many groups will be deleted.

### Fixes

- **Groups waiting for deletion are clear** - A group marked for deletion shows as waiting to be deleted, with the reason. Texts that pointed at a missing menu now point at the right one.

## 2.4.616 · 2026-10-13 · Fix-only

Invardia Support keeps the database access it needs to help you.

### New features

None in this version.

### Fixes

- **Invardia Support keeps its access** - When you name a Support app, the installation gives it its own database access and the end-of-install check confirms it. A script gives existing installations the same.

## 2.4.615 · 2026-10-13 · Fix-only

Active assignments works on large tenants without timing out.

### New features

None in this version.

### Fixes

- **Active assignments work on large tenants** - On a large tenant, the Active assignments list no longer times out. It loads one page at a time, with fast search, filters and sorting.

## 2.4.614 · 2026-10-13 · Fix-only

Assignments to retired groups are stopped at Commit, and workload readiness is reported honestly.

### New features

None in this version.

### Fixes

- **Assignments to retired groups are refused** - Committing an assignment to a retired or undefined group is refused, with the row and two ways out. A group cannot be retired while assignments still name it.
- **Power BI prerequisite checks itself** - The Power BI prerequisite names the group and the identity that must be in it, and checks the membership itself.
- **Unreadable workloads are not ready** - A workload PIM Manager could not read is never counted as ready.

## 2.4.613 · 2026-10-12 · Fix-only

Status reports now say who has to act and how to solve the problem.

### New features

None in this version.

### Fixes

- **Status reports say who acts and how** - Every status report says whether it is ok, a warning, held or failed, and who has to act. A configuration problem comes with its solution in plain steps.
- **Hourly status and every update reported** - The status report goes every hour with the setup checks, and every update run is reported.

## 2.4.612 · 2026-10-12 · Fix-only

PIM Manager sizes itself correctly on install and update, and keeps a size you set.

### New features

None in this version.

### Fixes

- **Right size set automatically** - Installation and updates set the PIM Manager web app to 4 CPU and 8 GB and the database to the S3 tier. An update keeps a size you set.

## 2.4.611 · 2026-10-12 · Fix-only

Active assignments behaves better on large tenants, and alert mails are short and clear.

### New features

None in this version.

### Fixes

- **Active assignments says what is happening** - On a large tenant, a stored list that cannot be loaded now says so instead of starting a new read. Repeat loads are faster.
- **Alert mails in one short table** - Alert mails show who acts, the status, the problem, what to do, the findings one per line, and where to get support.

## 2.4.610 · 2026-10-12 · Fix-only

Alert mails are short and show what to do at a glance.

### New features

None in this version.

### Fixes

- **Alert mails in one short table** - Alert mails show who acts, the status, the problem, what to do, the findings one per line, and where to get support.

## 2.4.609 · 2026-10-12 · Fix-only

Discovery and gaps opens on the gaps and tells you what your selection will create.

### New features

None in this version.

### Fixes

- **Discovery and gaps opens on gaps** - Discovery and gaps opens filtered on Status = Gap. One line says how many gaps you selected and how many groups and roles that creates.

## 2.4.608 · 2026-10-12 · Fix-only

Discovery and gaps opens on the gaps and tells you what your selection will create.

### New features

None in this version.

### Fixes

- **Discovery and gaps opens on gaps** - Discovery and gaps opens filtered on Status = Gap. One line says how many gaps you selected and how many groups and roles that creates.

## 2.4.607 · 2026-10-12 · Fix-only

Discovery and gaps opens on the gaps and tells you what your selection will create.

### New features

None in this version.

### Fixes

- **Discovery and gaps opens on gaps** - Discovery and gaps opens filtered on Status = Gap. One line says how many gaps you selected and how many groups and roles that creates.

## 2.4.606 · 2026-10-12 · Fix-only

Older installations no longer get reminder mails for the new Policies step.

### New features

None in this version.

### Fixes

- **No reminder mail for older installations** - An installation that existed before the Policies step in Get Started no longer gets a reminder mail for it. The step stays open on the page.

## 2.4.605 · 2026-10-12 · Feature update

Discovery and gaps is one page, new admins get their mail reliably, and the menu flags only what needs you.

### New features

- **Discovery and gaps in one page** - Discovery and gaps is now one page under Access.
- **New admin wizard asks where mail goes** - The New admin wizard asks where the admin's mail goes, so the Temporary Access Pass reaches the admin.

### Fixes

- **Menu numbers only when you must act** - The menu shows a number only for an error or a blocking approval.
- **Smaller fixes** - The policy page shows the recommendation, External companies saves from the row, and Delegation overview and Access map scroll properly.

## 2.4.604 · 2026-10-12 · Feature update

Discovery and Coverage are now one page where you can ignore or bring back each gap.

### New features

- **Discovery and gaps in one page** - Discovery and Coverage are now one page, Discovery and gaps, under Access. You can Ignore and Bring back each gap.
- **Microsoft default for group policies** - You can now choose the Microsoft default for group policies as well as for Entra roles.

### Fixes

- **Menu numbers only when you must act** - The menu shows a number only for an error or a blocking approval, and a workload that was not read is shown plainly.

## 2.4.603 · 2026-10-12 · Fix-only

Delegation overview and Access map show everything without hidden parts.

### New features

None in this version.

### Fixes

- **Nothing hidden behind the detail panel** - In Delegation overview and Access map, the board scrolls above the detail panel and the panel's buttons stay visible. The Delegation overview panel can collapse to one line.

## 2.4.602 · 2026-10-12 · Feature update

New admins get their Temporary Access Pass the first time.

### New features

- **Choose where a new admin's mail goes** - The New admin account wizard asks where the admin's mail goes. Forwarding to the owner's office address is on by default, so the Temporary Access Pass arrives the first time.

### Fixes

None in this version.

## 2.4.601 · 2026-10-12 · Fix-only

External companies save at once and show the saved values right away.

### New features

None in this version.

### Fixes

- **External companies save from the row** - An open company row has a Save button that saves at once. The list then shows the saved values without reloading the page.

## 2.4.600 · 2026-10-12 · Fix-only

The menu flags only what really needs you.

### New features

None in this version.

### Fixes

- **Menu numbers only when you must act** - The menu shows a number only for an error or something waiting for a person. Warnings such as gaps are listed on their page instead.

## 2.4.599 · 2026-10-12 · Fix-only

The PIM Manager recommendation is always visible when you choose policy settings.

### New features

None in this version.

### Fixes

- **Recommendation is always shown** - The Policy settings page and the Get Started Policies step always show the PIM Manager recommendation. Keep current can be chosen early and fills in by itself.

## 2.4.598 · 2026-10-12 · Feature update

You decide every PIM policy setting; PIM Manager changes none on its own.

### New features

- **You decide every policy setting** - On the new Policy settings page and in Get Started, you choose Microsoft default, PIM Manager recommendation or Keep current per setting. A quick selection for all settings needs a typed confirmation.
- **Managed tenants can choose differently** - In an MSP setup, the managing tenant's choices are the default, and a managed tenant can choose differently.

### Fixes

- **Every policy change needs a SuperAdmin** - PIM Manager changes no policy on its own, and every resulting change waits for a SuperAdmin to approve it.
- **Unwanted held removals clear themselves** - A held removal plan that is no longer wanted clears by itself on the next run.

## 2.4.597 · 2026-10-12 · Feature update

You can open a support ticket at Invardia straight from PIM Manager.

### New features

- **Get support from inside PIM Manager** - A Get support button opens a support ticket at Invardia. You see and can edit everything before it is sent.

### Fixes

- **Smoother installation** - The installation checks the administrators before it creates anything, remembers the licence file when resumed, and closes the temporary database firewall rule it opened.

## 2.4.596 · 2026-10-11 · Fix-only

Held policy changes look the same everywhere, and audit and report pages are clearer.

### New features

None in this version.

### Fixes

- **Held policy changes look the same everywhere** - Held policy change sets show the same on every page, and a SuperAdmin approves them.
- **Audit rows in plain words** - Audit rows say what changed in plain words.
- **Reports page shows true times** - The Reports page shows the true last sent and next run times.
- **Failed deployment checks alert at once** - A failed deployment check sends its alert at once again.
- **Smaller fixes** - Warnings and open setup steps are amber, the PIM Activator app needs no user assignment, the as-built document fits the page, and the licence command is two lines.

## 2.4.595 · 2026-10-11 · Fix-only

Large batches of policy changes wait for a SuperAdmin's approval again.

### New features

None in this version.

### Fixes

- **Many policy changes wait for approval** - Many policy changes in one run wait for approval again, and a SuperAdmin of the tenant approves them.
- **Warnings are amber, not red** - Warnings now show in amber, so red means a real error.
- **Smaller fixes** - The Guards page no longer shows a run counter, the Demo mode card appears only in a demo environment, and licensed installations are no longer told they update like Community.

## 2.4.594 · 2026-10-11 · Fix-only

Guards hold only changes that cannot be undone, and the rest become warnings.

### New features

None in this version.

### Fixes

- **Guards hold only lasting changes** - Guards hold for approval only changes that cannot heal, such as weakening policies, mass removals, or the last Global Administrator or SuperAdmin.
- **Other issues in one daily mail** - Large policy alignments and open gaps are warnings in one daily Data quality alert mail.
- **Clearer setup advice** - When a tenant-root permission is refused during setup, you see only the published script to fix it.

## 2.4.593 · 2026-10-11 · Fix-only

Script commands are cleaner to copy, and the Licence page needs no extra tools.

### New features

None in this version.

### Fixes

- **Cleaner script commands** - The "What does this script do" link now sits under the command, outside the copied text. The Licence page no longer mentions the Azure command line.

## 2.4.592 · 2026-10-11 · Fix-only

Graph view and Access map use more of the screen and nothing is covered.

### New features

None in this version.

### Fixes

- **More room for Graph view and Access map** - The board keeps most of the screen and the page scrolls, so the detail bar no longer covers it. Back to overview is a clear button.

## 2.4.591 · 2026-10-11 · Fix-only

The installer no longer asks for Owner when your inherited Azure rights are enough.

### New features

None in this version.

### Fixes

- **Inherited Azure rights are counted** - The installer now counts Azure rights inherited from a management group, such as Contributor and User Access Administrator at the tenant root. It no longer asks for Owner then.

## 2.4.590 · 2026-10-11 · Fix-only

New installations no longer fail at the database sign-in, and script commands are simpler to copy.

### New features

None in this version.

### Fixes

- **New tenant installs no longer fail** - The installer no longer fails with Login failed at the database step in a new tenant. A refused sign-in is retried for about two minutes.
- **Script commands are two lines** - Every command PIM Manager shows for a published script is now two lines: download the file, run it. The "What does this script do?" link sits next to it.
- **Install check suggests portal steps** - Every fix the install check suggests is an Azure portal step or a published script, never an Azure command line.

## 2.4.589 · 2026-10-11 · Fix-only

Status problems show honestly, new installations settle smoothly, and new managed tenants connect within minutes.

### New features

None in this version.

### Fixes

- **Undelivered status shows as a warning** - When status reports do not reach Invardia, the Jobs page shows an amber warning with the reason, and an alert goes out at most once a day.
- **Updates wait for the install key** - An update in the first minutes after installing shows "waiting for the install key" and ends successfully. No key a day later shows a warning pointing to Settings > Licence.
- **New managed tenants connect within minutes** - In an MSP setup, the managing tenant allows a newly enrolled managed tenant within minutes. Until then, the managed tenant's install waits and retries by itself instead of failing.
- **Install check verifies more** - The end-of-install check confirms that scheduled jobs are on, have run, and that status reports reached Invardia.

## 2.4.588 · 2026-10-11 · Fix-only

Managed tenants receive changes from the managing tenant again.

### New features

None in this version.

### Fixes

- **Managed tenants receive changes again** - On a managed-tenant installation, the step that pulls changes from the managing tenant no longer refuses to run.

## 2.4.587 · 2026-10-11 · Fix-only

Installations recover more gracefully when a step fails.

### New features

None in this version.

### Fixes

- **A resumed install is no longer refused** - Resuming a stopped installation now continues where it stopped, instead of being refused by its own update ring check.
- **A failed side step keeps a healthy app** - When a side step such as the updater or alerting fails, setup no longer rolls a healthy PIM Manager back. A rollback happens only when the app itself fails its health check.
- **Clearer message when an install step fails** - Under Invardia's installer, a failed step now tells you what failed, the fix when known, and the one command to resume.

## 2.4.586 · 2026-10-11 · Fix-only

A brief network drop no longer stops an installation.

### New features

None in this version.

### Fixes

- **Installs survive a dropped connection** - When the connection to Azure drops for a moment, setup now retries up to three times instead of stopping the installation.

## 2.4.585 · 2026-10-11 · Fix-only

A stopped installation is easy to resume from any window.

### New features

None in this version.

### Fixes

- **The resume command works in a new window** - The resume command the installer prints now works when you paste it into a fresh PowerShell window.

## 2.4.584 · 2026-10-11 · Fix-only

Managed tenant installations no longer stop at the database step.

### New features

None in this version.

### Fixes

- **Database setup signs in correctly** - On a managed tenant install, setting up Azure SQL could fail with a login error. Setup now signs in to the new database correctly.

## 2.4.583 · 2026-10-11 · Fix-only

The as-built document works on existing environments, and updates report their state correctly.

**Action needed:** An Owner of the PIM resource group runs the hosting access setup script once; the update log reminds you until then.

### New features

None in this version.

### Fixes

- **As-built document works on existing environments** - The as-built document could not be made on environments set up by the nightly update. It now works, and its log names the fix if it still cannot run.
- **Updates no longer report false problems** - The update no longer reports the as-built document job as not fully updated right after moving it, and it waits briefly when that job is still busy.

## 2.4.582 · 2026-10-11 · Feature update

Export any view to PDF or Excel and show the impact PIM Manager has, with your company name kept off screen by default.

### New features

- **Export any table to PDF or Excel** - Use the new Export menu in the header to save any page that shows a table as PDF or Excel. The export shows exactly what the page shows and is audited.
- **Impact counters on a new overview** - The new Counters overview shows activations, standing access made eligible, standing-access hours removed, approvals, reviews and more, with how each is counted.
- **Company name hidden on screen by default** - The Dashboard and Counters overview hide the company and environment name by default, also in every export, so you can safely show them in a meeting.
- **Private link between managing and managed tenants** - A managing / managed tenant pair can now connect over a private path without network peering. Built, not yet proven live; the public, signed path stays the default.
- **Hybrid worker improvements** - The hybrid worker now reaches a private-only PIM database, works with domain controllers behind a hub gateway, and can be removed cleanly with one command.

### Fixes

None in this version.

## 2.4.581 · 2026-10-11 · Feature update

Download a PDF that documents how your PIM Manager is set up, and close public access fully when you go private.

**Action needed:** On an existing environment, an Owner of the resource group runs the hosting access setup script once after the next update; the update log says so.

### New features

- **As-built document as a PDF** - Settings > Copy & tools > As-built document downloads a PDF of how this installation is configured. It is made inside your environment and never contains secrets or people.
- **Support can request the as-built document** - When you grant Invardia support the new as-built access level, support can create the same PDF on request. It is deleted after 24 hours.
- **Going private closes public access too** - Converting an environment to private now also turns off public access to the container registry, and optionally the database, once the private path is proven complete.
- **Progress during the long hosting step** - A tracked multi-tenant install now shows each part of the hosting step as it happens, instead of minutes of silence.

### Fixes

- **No false Azure SQL warning on new subscriptions** - On a new subscription, the region check now explains that Azure SQL is checked after setup registers it, instead of showing a confusing warning.

## 2.4.580 · 2026-10-10 · Feature update

Installing through Invardia needs just one sign-in.

### New features

- **One sign-in when installing through Invardia** - When Invardia's installer has already signed you in, PIM Manager's installer reuses that sign-in after checking it. The browser opens only for what is missing.

### Fixes

None in this version.

## 2.4.579 · 2026-10-10 · Feature update

Move a public environment to a private network with one guided command.

### New features

- **Convert to private with one command** - One command now runs every step of converting a public environment to private. It shows the plan first, can resume after a stop, and pauses where your network team must act.

### Fixes

None in this version.

## 2.4.578 · 2026-10-10 · Feature update

Network and custom host name setup is simpler and can be undone cleanly.

### New features

- **Hub preparation without extra tools** - The script for the hub network owner now runs on any machine with PowerShell, needs no Azure CLI, shows a plan first and never deletes anything.
- **Remove a custom host name again** - You can now take a custom host name off PIM Manager again; setup removes its binding and certificate and tells you which DNS record to delete.

### Fixes

- **Custom host name uses the right DNS zone** - The private DNS record now lands in the existing zone your name belongs to, and an already linked network is left alone.
- **More certificate formats accepted** - A Key Vault certificate in PEM format now works for a custom host name, and a public environment no longer waits 20 minutes for a certificate that cannot issue.

## 2.4.577 · 2026-10-10 · Feature update

Run the hybrid worker on your own servers and install PIM Manager in any Azure region.

### New features

- **Hybrid worker on your own server** - The hybrid worker can now run on an on-premises Windows server enabled for Azure Arc, with outbound connections only. Not yet proven on a live Arc server.
- **Deploy the hybrid worker with one command** - One command now deploys the hybrid worker in the right order, on an Azure VM or an Arc server, and pauses for the Active Directory steps.
- **Install in any Azure region** - Setup checks before anything is created that every service PIM Manager needs is offered in your chosen region, and suggests the nearest one that has them.
- **PIM Activator shows the Invardia shield** - The PIM Activator icons now show the official PIM Manager shield, from the next Activator package.

### Fixes

- **Install wizard asks fewer questions** - The install wizard no longer asks for admin account prefixes, and setup screens now say PIM Manager.

## 2.4.576 · 2026-10-10 · Feature update

You decide where your data lives, and guard alerts link straight to where you act.

### New features

- **You choose the Azure region** - PIM Manager can now be installed in any Azure region. Before anything is created, setup checks every needed service is available there and suggests the nearest region if not.
- **Guard reports link to where you act** - Each guard report now links to the page where you act on it: Approvals for a held change set, otherwise that guard's page.
- **Support sees where your environment lives** - With an install key, the status report now names your environment's public addresses, so Invardia support can reach the right pages faster.

### Fixes

- **Smaller fixes** - Active Directory DNS records are printed for you instead of written, and closing PIM Manager during setup works more reliably.

## 2.4.575 · 2026-10-10 · Feature update

Nothing that waits on you is forgotten, and you can see and revoke privileged access on a visual map.

**Action needed:** To keep the old behaviour, tick "only these reviewers (not the owners)" on the review rule.

### New features

- **A reminder when something waits on you** - SuperAdmins get one reminder mail listing everything waiting on them, each with a link. Change it under Settings > Mail & alerting > Reminders: what waits on you.
- **Delegation overview with a graph view** - All privileged permissions now shows live access as a map of people, groups, roles and scopes. Click a path, tick what to take away and press Revoke.
- **Setup needs no extra tools** - Setup and support scripts no longer need the Azure CLI or PowerShell modules, and the PIM Manager image is slimmer.
- **Your DNS stays yours** - With a custom host name, setup no longer changes your Active Directory DNS. It prints the one record to add and a command to check it.

### Fixes

- **Access reviews also ask department owners** - Department owners now always review their department; extra reviewers on a review rule join them instead of replacing them.
- **Drift Apply now applies only what you ticked** - Before, Apply now re-applied every missing and changed item. Now only the items you ticked are created or updated.
- **Mail recipients get working Reader access** - Recipients whose mail address differs from their sign-in name now get Reader access under the name they sign in with.
- **Old workload rows no longer block commits** - An old workload row without a Resource now shows as a warning instead of blocking your commits.
- **Smaller fixes** - New mail layout for alerts, auto-extend moved to Settings > Automation, a clear loading message on delegations, readable list columns and clearer revoke wording.

## 2.4.574 · 2026-10-10 · Fix-only

A new installation no longer rolls PIM Manager back by mistake.

### New features

None in this version.

### Fixes

- **No unwanted rollback during installation** - A customer installation checks the Manager directly and keeps the version you installed.

## 2.4.573 · 2026-10-10 · Fix-only

PIM Manager is reachable after setup, even after an interrupted run.

### New features

None in this version.

### Fixes

- **PIM Manager is reachable after setup** - Once sign-in protects it, setup now opens PIM Manager for access, even when an earlier run left it closed.

## 2.4.572 · 2026-10-10 · Fix-only

Customer installations check PIM Manager directly after deploying.

### New features

None in this version.

### Fixes

- **Simpler check after installation** - After deploying, a customer installation checks PIM Manager directly.

## 2.4.571 · 2026-10-10 · Fix-only

Setup steps that Azure refused now complete.

### New features

None in this version.

### Fixes

- **Setup steps no longer refused by Azure** - Restarting the app, reading registry credentials and reading the Log Analytics key during setup now work.

## 2.4.570 · 2026-10-10 · Fix-only

Setup completes the PIM Manager sign-in step again.

### New features

None in this version.

### Fixes

- **Storing the sign-in secret works** - Setup could stop while storing PIM Manager's sign-in secret because Azure refused the request. It now works.

## 2.4.569 · 2026-10-10 · Fix-only

New installations finish their PIM Manager setup steps again.

### New features

None in this version.

### Fixes

- **Setup finishes on new installations** - Closing PIM Manager and storing its sign-in secret work again on a new installation. Setup now waits when the app is still busy.

## 2.4.568 · 2026-10-10 · Fix-only

The optional mail sender step no longer stops an installation.

### New features

None in this version.

### Fixes

- **Mail sender step no longer stops setup** - The optional mail sender step no longer stops the installation because of its own waiting setting.

## 2.4.567 · 2026-10-10 · Fix-only

You can resume an installation from a different network.

### New features

None in this version.

### Fixes

- **Resume works from another network** - When you resume setup from a different internet address, the temporary database firewall rule now moves to your current address.

## 2.4.566 · 2026-10-10 · Fix-only

An installation no longer waits on Exchange to finish.

### New features

None in this version.

### Fixes

- **Setup no longer waits for Exchange** - If the mail sender cannot be set up yet, setup now continues with a warning instead of waiting, and the mail sender is set up later.

## 2.4.565 · 2026-10-10 · Fix-only

No hidden extra sign-in during setup.

### New features

None in this version.

### Fixes

- **No hidden extra sign-in during setup** - Your one sign-in now also covers the helper steps setup starts, so no hidden sign-in window waits for you.

## 2.4.564 · 2026-10-10 · Fix-only

A resumed installation finishes creating PIM Manager's apps.

### New features

None in this version.

### Fixes

- **Resumed setup creates the apps** - When you resume setup, it now finds what the earlier run created, so the Container Apps are created instead of the step failing.

## 2.4.563 · 2026-10-10 · Fix-only

Setup waits for Azure instead of failing on a new PIM Manager.

### New features

None in this version.

### Fixes

- **Setup waits while Azure prepares the Manager** - Closing a newly created PIM Manager while Azure still prepares it now waits and retries, and shows the real error if it cannot.

## 2.4.562 · 2026-10-10 · Fix-only

Installing on a brand-new Azure subscription works.

### New features

None in this version.

### Fixes

- **Setup works on brand-new subscriptions** - On a new Azure subscription, setup now switches on the Azure services it needs before it uses them.

## 2.4.561 · 2026-10-10 · Fix-only

A failed managed tenant install step tells you what went wrong.

### New features

None in this version.

### Fixes

- **Failed install steps show the real error** - On a managed tenant install, a failed step now shows its real error in the installation progress.

## 2.4.560 · 2026-10-10 · Fix-only

Setup works on Windows in any language.

### New features

None in this version.

### Fixes

- **Setup works on non-English Windows** - Setup failed on Windows in other languages with an error about identity references. It now works whatever the Windows language.

## 2.4.559 · 2026-10-10 · Fix-only

You never miss a sign-in window during setup.

### New features

None in this version.

### Fixes

- **Sign-in waits are shown in progress** - The installation progress now shows when setup waits for your browser sign-in, so a sign-in window is never missed.

## 2.4.558 · 2026-10-10 · Fix-only

One browser sign-in covers the whole installation.

### New features

None in this version.

### Fixes

- **One sign-in for every setup step** - Every script of the installation now shares your one browser sign-in, so no second prompt appears when the managed tenant build starts.

## 2.4.557 · 2026-10-10 · Fix-only

A managed tenant install asks you to sign in only once.

### New features

None in this version.

### Fixes

- **One sign-in for a managed tenant install** - The build steps of a managed tenant install now reuse your one sign-in instead of each opening a browser window.

## 2.4.556 · 2026-10-10 · Fix-only

Setup signs you in once for both Entra ID and Azure.

### New features

None in this version.

### Fixes

- **One sign-in covers Entra ID and Azure** - Setup now signs you in once in the browser for both Entra ID and Azure, with no second sign-in window.

## 2.4.555 · 2026-10-10 · Fix-only

Browser sign-in during setup works reliably and only for your own tenant.

### New features

None in this version.

### Fixes

- **Browser sign-in works reliably** - Azure sign-in during setup no longer fails with a consent error. It opens a private browser window and refuses a sign-in to another tenant.

## 2.4.554 · 2026-10-10 · Fix-only

Fewer false alarms when Microsoft is busy, lower log costs, and a simpler managed tenant install.

### New features

None in this version.

### Fixes

- **Microsoft throttling no longer sends failure alerts** - When Microsoft briefly slows a job that changed nothing, it shows as throttled and retries. You are mailed only if it stays stuck for 12 runs or 6 hours.
- **Quieter logs, lower Log Analytics cost** - Repeating messages are now logged once and then daily, so your Log Analytics bill drops. Errors are always logged, and full logs stay under Jobs > Logs.
- **Managed tenant install needs no extra tools** - A managed tenant install and its downloadable setup scripts no longer need the Azure CLI, and the admin account prefix is now optional.
- **Updates finish more reliably** - The automatic update waits for a busy engine before sizing it, records the release it applied correctly, and no longer reports a false updater problem.
- **Smaller fixes** - PIM Manager reports in to Invardia every 4 hours, every script prints its name and version first, and large tenants see less load from daily activity reads.

## 2.4.552 · 2026-10-10 · Fix-only

More setup scripts run without extra tools.

### New features

None in this version.

### Fixes

- **More setup scripts work without Azure CLI** - More setup scripts, such as the update run and the custom Manager address, now work without the Azure CLI.
- **Safer environment rebuilds** - Security improvements for rebuilding an environment and for the custom address certificate.

## 2.4.551 · 2026-10-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.550 · 2026-10-10 · Fix-only

Invardia support sees your guard alerts again.

### New features

None in this version.

### Fixes

- **Guard alerts reach Invardia support again** - Guard reports did not reach Invardia support. They arrive again, so support can see guard alerts for your environment.

## 2.4.549 · 2026-10-10 · Fix-only

Installing and updating PIM Manager no longer needs the Azure CLI.

### New features

None in this version.

### Fixes

- **Setup works without Azure CLI** - Setup and install scripts for hosting, deployment, sign-in and updates now work without the Azure CLI, using a browser sign-in, the Invardia Support app or a certificate.

## 2.4.548 · 2026-10-10 · Fix-only

Engine actions are fully audited again, and PIM Manager runs without extra PowerShell modules.

**Action needed:** Complete the browser sign-in when a setup script asks for it.

### New features

None in this version.

### Fixes

- **Engine audit events are recorded again** - Account creation, Temporary Access Pass, approval, licence and access request events from the engine were missing from the audit trail. They are recorded again.
- **No PowerShell modules, one way to sign in** - PIM Manager no longer loads Microsoft PowerShell modules anywhere it runs for you, and every sign-in follows one path.
- **Setup signs you in through the browser** - Setup scripts no longer borrow an existing Azure CLI sign-in. They use an open Invardia support session or sign you in in the browser.
- **Hybrid worker needs fewer tools** - Creating the hybrid worker's Active Directory groups and service account no longer needs the Active Directory PowerShell tools.

## 2.4.547 · 2026-10-10 · Fix-only

Older installations get the same safe defaults as new ones, without losing your own choices.

### New features

None in this version.

### Fixes

- **Alert recipients filled in when empty** - An installation with no alert recipients now gets its SuperAdmins' mailboxes on the next update. A list you set is never replaced.
- **Engine starts right after a commit** - When PIM Manager may start the engine, the update switches on the immediate start after a commit, as on new installations. Your own setting is kept.
- **Missing access is named in the update log** - The update now checks the access PIM Manager needs on its own resources and names the setup script that grants anything missing.
- **Installations ahead of their ring stay current** - Installations running ahead of their update ring now also get engine sizing, the database size rule and these checks on every update.

## 2.4.546 · 2026-10-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.545 · 2026-10-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.544 · 2026-10-10 · Fix-only

The engine is sized for your tenant even where the updater cannot read the directory.

### New features

None in this version.

### Fixes

- **Automatic engine sizing works again** - Sizing the engine for your tenant now works even when the updater may not read the directory, and the update log no longer shows count errors.

## 2.4.543 · 2026-10-09 · Fix-only

The stale-access check stays current on large tenants, and PIM Activator points users to support.

### New features

None in this version.

### Fixes

- **Stale-access check stays current on large tenants** - On large, busy tenants, the group activity behind the stale-access check now catches up run by run instead of staying old.
- **PIM Activator carries the PIM Manager name** - PIM Activator now shows it is part of PIM Manager, with a Support link, and Report bug opens the support portal. Installed browsers update in place.

## 2.4.542 · 2026-10-09 · Fix-only

The tenant data refresh reads activity for every group again.

### New features

None in this version.

### Fixes

- **Group activity is read for every group** - The tenant data refresh again reads activity for every group. The two previous versions read only some groups and reported the rest as failed.

## 2.4.541 · 2026-10-09 · Fix-only

No more alert mails when Microsoft slows down group activity reads.

### New features

None in this version.

### Fixes

- **No alert when Microsoft slows group reads** - When Microsoft slows group activity reads until they get no answer, PIM Manager keeps the last refresh and sends no alert mail.

## 2.4.540 · 2026-10-09 · Fix-only

A brief Microsoft slowdown no longer fails the tenant data refresh.

### New features

None in this version.

### Fixes

- **Tenant refresh survives Microsoft slowdowns** - When Microsoft briefly slows the optional group activity list, the tenant data refresh keeps the last result instead of failing and mailing an alert.

## 2.4.539 · 2026-10-09 · Feature update

Your Pro licence unlocks every Pro feature, the engine grows with your tenant, and the database no longer runs full.

### New features

- **Home shows your setup health** - Home now flags a critical setting that is missing or wrong, such as no alert recipient, with what to do. Pro installs can share the same report with Invardia support.
- **Licence page explains each Pro feature** - Settings > Licence now shows beside each Pro feature why it is included or what licence it needs.
- **Engine sized for your tenant automatically** - PIM Manager sizes the engine for your number of users, groups and apps at install and on every update, and raises it after an out-of-memory run.
- **Re-issued licences install themselves** - When Invardia re-issues your licence, your installation fetches and checks it within 30 minutes, with no action from you.
- **Smaller improvements** - The delegation wizard asks for a per-environment workload's target, a script sets the database tier, and support sees database space, update ring and failure causes.

### Fixes

- **Pro licence covers every Pro feature** - Features added after your licence was issued showed as "Pro - not licensed". Your edition now unlocks every current and future feature it includes.
- **The database no longer runs full** - A database raised from Basic kept a 2 GB limit and stopped accepting changes when full. Every Standard database now gets a 250 GB maximum at no extra cost.
- **Large tenants no longer run out of memory** - The list behind Reviews & controls > Revoke could stop with an out-of-memory error on very large tenants. It now completes using far less memory.
- **Removing an unapplied workload binding works** - A workload binding PIM Manager never applied can now be removed cleanly, and it disappears from Failing now.
- **Smaller fixes** - Pro is always recognised during updates, the end-of-install licence check is correct, the mail sender shows its chosen address, and install progress shows every step.

## 2.4.538 · 2026-10-09 · Feature update

Manage access for any application, find admins faster, and give your security team a full review pack.

**Action needed:** If your own policy template should stay without MFA, switch "Require MFA on activation" off before the next engine run.

### New features

- **Custom workloads, for example SAP** - Templates > Custom workloads lets you define an application PIM Manager has no connector for, with its roles. PIM Manager then maintains one Entra group per delegated role.
- **Filter admin accounts** - Admin accounts now has filter chips for type, privilege, platform, department and status, and each admin shows a High-priv or Day-to-day badge.
- **Environment report** - Operations > Environment report shows your PIM Manager setup live: identities and their permissions, Azure resources, network exposure and findings with the fix. Export it as PDF.
- **Clear choices for extras in Drift** - An item in the tenant but not in PIM Manager now offers Import into PIM, Delete or Ignore. Deleting a whole group is its own separate commit.
- **Smaller improvements** - A security review pack for your CISO, More info on every setting, per-recipient notifications, Settings > Reports, PDF export, Reader access for department owners, and a clearer daily changes mail.

### Fixes

- **Operational policy settings now take effect** - Require MFA on activation and the maximum activation and eligibility durations are now applied on top of every policy template. They never loosen a template.
- **New groups are not role-assignable by default** - Following Microsoft's guidance, a new group is role-assignable only when it needs to be. Existing groups are not changed.
- **Managed tenants keep their own groups** - A managed tenant's own groups and access are never overwritten or removed by the managing tenant, even when names match.
- **Update ring moves no longer block updates** - An environment ahead of its ring is no longer reported as a failed update, and moving an environment between rings no longer blocks its updates.
- **Smaller fixes** - Get Started > Mail sender turns green once mail works, duplicate group tags and blank naming patterns are refused, and switched-off pages stay off.

## 2.4.537 · 2026-10-09 · Feature update

You can install a managed tenant straight from Azure Cloud Shell.

### New features

- **Install a managed tenant from Cloud Shell** - You can now install a managed tenant from Azure Cloud Shell or Linux, without Windows PowerShell. On Windows nothing changes.

### Fixes

None in this version.

## 2.4.536 · 2026-10-09 · Feature update

Install any tenant with just an enrollment key, and health-check an installation whenever you want.

### New features

- **Install a single tenant with an enrollment key** - An enrollment key from Invardia now installs a single-tenant environment too, with its licence included, so no licence file is needed.
- **Managed tenants link to their managing tenant** - The managing tenant now shares its details with Invardia by itself, so tenants enrolled with a key are linked to it without manual steps.
- **Run the end-of-install check any time** - You can now run the end-of-install check on its own as a health check of an existing installation.

### Fixes

- **Forgotten offboard requests show as blocking** - An approved offboard request that was never queued now counts as a blocking item in the menu badge for 7 days.

## 2.4.535 · 2026-10-08 · Feature update

A new installation checks itself before it says done, and alerts reach someone from day one.

### New features

- **The install checks itself before finishing** - The last install step shows one table of what is in place, repairs what it can and gives the exact command for anything left.
- **Alert recipients set during install** - The install sets alert recipients to the address you give or your SuperAdmins' mail, so alerts reach someone from the first engine run.
- **Mail checked piece by piece** - Get Started > Mail sender and the Overview check each part of mail separately and show the one-line fix for each missing piece. You can skip mail for now.
- **Pro Business and Pro Enterprise shown** - The header, Licence page and Get Started show your Pro edition. Pro Business warns from 90% of its admin account limit; nothing running is ever switched off.

### Fixes

- **New Exchange organisations no longer fail mail setup** - On a brand-new Exchange organisation, the install now waits up to about an hour for Exchange to accept the send right, showing progress.
- **Smaller fixes** - Installs through the Invardia Support app now report each step to Invardia.

## 2.4.534 · 2026-10-08 · Feature update

See at a glance what waits on you, and choose how mail and the PIM Activator reach your organisation.

### New features

- **Blocking items shown in the menu** - Approvals, held change sets and other items that wait for a person now show a count on their menu entry and a line on the Overview, and clear when decided.
- **Client onboarding with or without Intune** - The Client onboarding page shows two equal ways to give admins the PIM Activator: with Intune, or one script on PCs and servers without Intune.
- **Mail via shared mailbox or your own SMTP** - Get Started > Mail sender and Settings > Mail & alerting offer a shared mailbox or your own SMTP relay. A test mail proves it works.
- **Workload prerequisites checked automatically** - PIM Manager checks its own permissions, licences and workload access daily. Entra ID roles and Intune need no onboarding when the engine has its permissions.
- **Smaller improvements** - The engine gets read access to all Azure subscriptions for Discovery, and the Review page hides PIM Manager's own identities, the Support app and break-glass accounts by default.

### Fixes

- **Commit queue shows only real blockers** - The commit queue now shows only what blocks a commit; warnings stay on Check for problems and no longer show in red.
- **Update ring shown on a fresh install** - On a fresh install, the header shows the configured update ring instead of "not recorded".

## 2.4.533 · 2026-10-08 · Feature update

You decide exactly who gets the PIM Activator, and large commits finish in seconds.

**Action needed:** On the PIM Activator page, assign a group for each channel so your admins can sign in.

### New features

- **PIM Activator: you choose who** - The PIM Activator page now gives ready-to-run commands, and you pick the group per channel. Nothing is assigned by default, so nobody signs in until a group is assigned.
- **Environment name step in Get Started** - Get Started now has an Environment name step as step 2.

### Fixes

- **Large commits are fast** - Committing hundreds of rows took minutes and could time out. It now takes seconds, and a slow commit is never wrongly reported as not saved.
- **New group policies no longer fail a run** - When a new group's PIM policy cannot be read yet, PIM Manager waits and retries instead of failing the run.
- **Smaller fixes** - Admin accounts no longer asks for a manager e-mail, as mail goes to the department's owners. The Edge for Business guide is corrected.

## 2.4.532 · 2026-10-08 · Feature update

SuperAdmins can clear all pending changes at once, and Get Started walks a new environment through setup in a clearer order.

### New features

- **Discard all pending changes at once** - A SuperAdmin can discard every pending change, including colleagues', in one step. The page shows how many and who staged them, asks for a reason and commits nothing.
- **Self-service setup for managed tenants** - You can install a managed tenant with an enrollment key from Invardia. It creates the environment and licence and links it to its managing tenant.

### Fixes

- **Get Started in a clearer order** - Naming convention is now step 1, then licence, engine permissions, mail sender and the rest. Engine permissions shows done as soon as every permission is held.
- **Templates skip roles your tenant lacks** - Templates leave out roles your tenant does not have and say which, so a commit is no longer blocked. Two Entra role names now match Microsoft's current names.
- **Smaller fixes** - Pending changes no longer lists the same item twice, Mail alerting points to Get Started, and hosting setup works in an empty Azure subscription.

## 2.4.531 · 2026-10-08 · Feature update

Missing engine permissions are now granted with one browser sign-in and no extra software.

### New features

- **Grant missing engine permissions in one step** - When the engine lacks a permission, Overview and Get Started show a download from Invardia and one command. You sign in in the browser, and it covers the Azure right too.

### Fixes

None in this version.

## 2.4.530 · 2026-10-08 · Feature update

Changes go live sooner because jobs now run side by side, and interrupted runs no longer look like failures.

### New features

- **Jobs run side by side** - Jobs for different areas, such as groups, policies or Azure, now run at the same time. Run now on a busy area is queued and says what it waits for.
- **A clearer Jobs page** - Jobs are grouped into Engine, Maintenance, Reports and Updates, with what needs attention first and one line per job with a details panel.

### Fixes

- **Interrupted runs no longer show as failures** - A run cut short by an update or restart now shows grey as interrupted and runs again. Only two interruptions in a row turn red.
- **Clearer role assignment error** - When a role is refused because the group is not role-assignable, PIM Manager now names that cause and the fix.

## 2.4.529 · 2026-10-08 · Feature update

You can now complete each setup step right inside the Get Started wizard.

### New features

- **Get Started is a real wizard** - Every Get Started step now has its own fields, with Previous, Save & exit and Save & next. A refused save stays on the step and shows the reason.
- **Demo mode for live demos** - Off by default. Visitors in a demo group can look at everything and stage changes, but nothing is saved, and a banner says it is a demo.

### Fixes

- **No double removals** - Asking to remove something that is already queued adds nothing and says "already queued".
- **Large tenants keep every snapshot** - The current assignments snapshot is no longer lost in busy tenants with ten thousand assignments.
- **Smaller fixes** - The setup scripts now name the Invardia Support app; the old wording still works.

## 2.4.528 · 2026-10-08 · Feature update

Rolling out PIM Activator is now a guided page with buttons that do the work for you.

### New features

- **PIM Activator page as guided steps** - Operations > PIM Activator now has five steps, from the Entra apps to servers, each showing whether it is done.
- **Create apps and upload to Intune** - Create / Repair and Upload to Intune work right from the page. You sign in with your own admin account; PIM Manager itself gets no new rights.
- **Edge for Business guide** - One card per extension shows exactly the fields the Microsoft 365 admin center asks for, plus the two settings to paste.
- **Edit button for external companies** - A company reads as text until you click Edit; a new company opens ready to fill in.

### Fixes

- **Mail works when addresses differ** - Mail sender setup now stores the mailbox's real mail address, so mail no longer fails when its sign-in name and mail address differ.
- **Drift Delete confirms itself** - After Delete the row reads "queued for removal", and the same item is never queued twice.
- **Smaller fixes** - PIM Activator scripts need no extra PowerShell modules, and "Delegations - edit in a table" is now called "Delegations - all rows".

## 2.4.527 · 2026-10-07 · Fix-only

The PIM Activator page now recognises one app shared by PROD and TEST.

### New features

None in this version.

### Fixes

- **One PIM Activator app for both channels** - When one PIM Activator app serves both PROD and TEST, the page now shows that TEST uses it instead of reporting the TEST app as missing.

## 2.4.526 · 2026-10-07 · Feature update

One page now shows everything needed to roll out PIM Activator.

### New features

- **PIM Activator deployment page** - Operations > PIM Activator covers the Entra apps, the settings, the Intune remediation, Edge for Business and servers without Intune, filled in for this environment.
- **Ready-made Intune remediation** - Build gives you both remediation scripts with your settings filled in, for a group, all devices or all users. Uploading needs only a browser sign-in.

### Fixes

None in this version.

## 2.4.525 · 2026-10-07 · Feature update

A new Get Started guide walks a new environment through setup, and drift mails are less frequent.

### New features

- **Get Started guides new environments** - A new Get Started menu walks you through every setup step, marks each done or open, and opens the page that does the work. A red ! shows while a required step is open.
- **Choose how often the drift mail comes** - The "Configuration drift detected" mail now goes out every two weeks by default. You can change it in Settings under Alerting.

### Fixes

- **Clearer administrative unit errors** - A role at an administrative unit whose group, unit or role cannot be found is now explained, with the fix.
- **Licence alerts reach Invardia** - The MSP licence check now reports to Invardia in a form it accepts.

## 2.4.524 · 2026-10-07 · Fix-only

Every mail now says which environment it is about, and the menus are easier to scan.

### New features

None in this version.

### Fixes

- **Every mail names its environment** - Mail subjects start with the environment's name, and every mail ends with the environment, tenant, PIM Manager version and a link to it.
- **Shorter, clearer menus** - Audit & Settings is now three menus: Templates, Operations and Settings.

## 2.4.523 · 2026-10-07 · Fix-only

Job results, guards and the daily reconcile are easier to read at a glance.

### New features

None in this version.

### Fixes

- **Jobs show ok when nothing changed** - A job that ran now shows a green ok even when it had nothing to change, instead of a yellow label that read like a warning.
- **The Guards panel clears itself** - It shows only guards that tripped in the last two hours. Older ones fold away, and there is nothing to acknowledge.
- **Daily reconcile in plain words** - The card says what it does, what the last run did, and that access PIM Manager did not create is left alone.
- **Mail setup without a certificate** - Creating the notification mailbox can now run as the signed-in account or as Invardia support.

## 2.4.522 · 2026-10-07 · Fix-only

Review current delegations now focuses on access PIM Manager does not manage, so clean-up is easier.

### New features

None in this version.

### Fixes

- **Review shows what still needs cleaning up** - Assignments PIM Manager manages are hidden by default on Review current delegations. Tick show managed by PIM Manager to see them, marked MANAGED.
- **Deleted admin accounts no longer look active** - Deleted accounts are hidden under Show removed and deleted and show no actions. Entra keeps them restorable for 30 days.
- **Setup steps as single downloads** - Setup steps can now be downloaded as single files from Invardia, starting with the step that gives Invardia support its access.

## 2.4.521 · 2026-10-07 · Feature update

You can now drop a single queued change with one click, and false guard alarms are gone.

### New features

- **Remove an entry from the change queue** - Every pending or failed entry in the change queue has a Remove from queue button. You give a reason; the entry is never applied and stays in the history.

### Fixes

- **No false removal budget alarm** - Drift no longer raises the removal budget warning on the Guards panel for items the engine never removes on its own.
- **Fresh data right after each update** - After an update, the engine refreshes its data and the drift check at its next run instead of hours later.
- **Record list no longer cut off** - The list of record types now fits the window, so you can reach the last entries.

## 2.4.520 · 2026-10-07 · Security

Group owner assignments now end after at most 180 days, in line with Microsoft's guidance.

### New features

None in this version.

### Fixes

- **No standing group owners** - The standard PIM for Groups policy now ends active owner assignments after at most 180 days. Owners PIM Manager keeps on its own groups are not affected.
- **Times shown in your local time** - Update times were shown in UTC without saying so. They now use your browser's local time.

## 2.4.519 · 2026-10-07 · Feature update

New installations are complete from day one, and Invardia support can now install PIM Manager for you.

### New features

- **Invardia support can install for you** - Invardia support can now run the installation with its Support app, for your tenant only. At least one named person becomes the PIM Manager administrator.

### Fixes

- **New Pro installations update themselves** - A new Pro or trial installation now gets its nightly update from Invardia from day one, on ring 3 by default.
- **Install key in place within minutes** - The installation stores the install key Invardia issued, or claims it within five minutes instead of up to six hours.
- **Managing and managed tenant setup completes** - This setup now also registers the licence, gives Invardia support its access and sets up Pro updates.
- **New managed tenants no longer report failures** - A new managed tenant says "nothing to apply" while nothing is published for it yet, instead of failing.
- **Smaller fixes** - The health check runs on brand-new installations, hand-run updates respect Invardia's rings, and Invardia's contact details and edition wording are corrected.

## 2.4.518 · 2026-10-06 · Fix-only

Admin accounts is easier to read, so you never press a button for the wrong person.

### New features

None in this version.

### Fixes

- **One clear band per admin** - Admin accounts now separates each admin with a divider and shading, and shows the admin's name above their own buttons.

## 2.4.517 · 2026-10-06 · Fix-only

The daily reconcile now cleans up access you removed in PIM Manager, within strict safety rules.

### New features

None in this version.

### Fixes

- **Daily reconcile now removes leftovers** - Items PIM Manager granted and you later removed are now removed when all five safety rules hold, never admin accounts. Set the removal mode to report to keep report-only.

## 2.4.516 · 2026-10-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.515 · 2026-10-06 · Feature update

You can now undo commits, restore from backups, pause the daily reconcile and release guards under full control.

### New features

- **Undo any commit** - Commit history & undo shows every commit with who, when and what changed. A SuperAdmin can undo any commit, an Admin their own, through the normal approvals.
- **Back up and restore your configuration** - A daily backup and Back up now keep your configuration for 90 days, never secrets. A SuperAdmin restores the rows they pick as a normal, undoable change.
- **Pause the daily reconcile** - A SuperAdmin can pause it with a reason and an optional end time, shown on Home and Jobs. Commits and Run now keep working.
- **See and release guards** - Guards shows what each protective guard is holding. A SuperAdmin can release that exact plan, with a reason, for one run or up to 24 hours.
- **Remove from PIM on Admin accounts** - Removes every delegation of an admin and disables the account, but keeps it.

### Fixes

- **Clear rules for deleting admin accounts** - A SuperAdmin or Admin may delete any admin; a delegated operator only admins at or below its own level and tier.
- **Self-approval covers disable and offboarding** - With self-approval on, a disable or offboarding commits directly and is recorded as self-approved.
- **Results recorded per item** - Each commit's result in the tenant is now recorded per item: created, updated, removed, already present or failed.

## 2.4.514 · 2026-10-06 · Fix-only

Deleting an admin stays each tenant's own decision.

### New features

None in this version.

### Fixes

- **Central admins never deleted in managed tenants** - A managed tenant only disables a central admin marked as deleted. Deleting an account stays each tenant's own decision.
- **Pro updates follow your environment's ring** - Pro updates now match the ring set in your environment, and an update for another ring is refused.

## 2.4.513 · 2026-10-06 · Feature update

SuperAdmins can now delete admin accounts and import administrators safely.

### New features

- **Delete admin accounts** - A SuperAdmin can delete an account on Admin accounts by typing DELETE. It goes through the offboard approval, and break-glass accounts are never deleted.
- **Import administrators from a file** - Admin accounts > Import administrators shows the format and offers a template. Every line is previewed as new, overwrite, skip or invalid before anything is staged.

### Fixes

- **Duplicate a group more safely** - Only group types are offered, groups are listed by name, and a name whose tag already exists is refused while you type.
- **Moving an admin between groups works reliably** - Admins load first and are listed by name, and a destination that does not exist or already holds the admin is refused.
- **Clearer auto-disable controls** - The "Account auto-disable date" controls change the day the account is disabled, not when its delegations expire.

## 2.4.512 · 2026-10-06 · Fix-only

Admin accounts now have their own menu, so they are easier to find.

### New features

None in this version.

### Fixes

- **A new Admin accounts menu** - A new Admin accounts menu, left of Access, holds Admin accounts & TAP and Invite a guest or consultant.

## 2.4.511 · 2026-10-06 · Feature update

Every configuration change is now recorded in full, laying the ground for undo.

### New features

- **Every change is recorded** - Every configuration change is now recorded with before and after, who made it and who approved it. The record can never be changed.
- **Admin accounts in the delegations table** - Admins are listed first, each with Remove all delegations and Disable & remove delegations, staged in Pending changes.

### Fixes

- **External Companies shows departments** - The sponsor department list now loads the first time the page opens, and says so when no department is defined yet.

## 2.4.510 · 2026-10-06 · Security

Restores from backup are for SuperAdmins and are fully audited.

### New features

None in this version.

### Fixes

- **Restore from backup is SuperAdmin only** - Restoring a table from a backup needs the SuperAdmin role. The audit trail lists what the restore changed and who did it.
- **Job schedule in your local time** - Next pull and next publish times now use your browser's time zone.
- **Discovery has its own menu item** - "Discovery: create what is new" is now a normal item under Access.

## 2.4.509 · 2026-10-06 · Fix-only

PIM Manager now only ever removes access it manages itself.

### New features

None in this version.

### Fixes

- **PIM Manager removes only what it manages** - A full reconcile with removal now removes only items PIM Manager manages. Everything else is reported as unmanaged and left alone.
- **Hand-assigned Entra roles are left alone** - A role someone assigned by hand to the same user is no longer read, so it can never be removed.
- **Workload removals are applied** - Deleted app role, Defender XDR and Intune rows are now applied, and app roles no longer show as new on every run.
- **Offboarding touches only PIM Manager groups** - Offboarding removes an admin only from groups PIM Manager manages. Other memberships are reported, not removed.
- **Smaller fixes** - Group retirement refuses a name that several live groups share, and a Defender XDR or Intune assignment shared with others is never deleted.

## 2.4.508 · 2026-10-05 · Feature update

You can now clean up a group's delegations in one step, with or without deleting the group.

### New features

- **Remove a group's delegations** - Per row or for a selection, remove every delegation and keep the group, or also delete the group in Entra ID. Both are staged in Pending changes.

### Fixes

None in this version.

## 2.4.507 · 2026-10-05 · Fix-only

Group tables now show the group first, so they are quicker to read.

### New features

None in this version.

### Fixes

- **Group tables show the group first** - On group tables such as Departments, the group's name, description and tag come first, then the sponsoring department.

## 2.4.506 · 2026-10-05 · Fix-only

After an update you keep your staged changes and reload when you are ready.

### New features

None in this version.

### Fixes

- **"A new version is available"** - After an update you see a calm bar with a Reload button instead of "Session expired". Your staged changes are kept and put back after the reload.

## 2.4.505 · 2026-10-05 · Fix-only

Every time PIM Manager shows is now in your own time zone.

### New features

None in this version.

### Fixes

- **Times in your own time zone** - Every page now shows times in your browser's time zone, daylight saving included. Prints made as evidence name the time zone.

## 2.4.504 · 2026-10-05 · Feature update

External companies and their consultants now have their own page with built-in reviews.

### New features

- **External Companies page** - One row per external company with its contacts, sponsor department, review cadence and consultants. The contacts get the access review mail and confirm or deny each consultant.

### Fixes

- **Clearer portal sign-in field** - The request portal's sign-in field now asks for the Admin Account (UPN) or e-mail address.

## 2.4.503 · 2026-10-05 · Feature update

You can now take a group out of PIM Manager with all its delegations in one click.

### New features

- **Quick clean-up on a group row** - One button takes a group out of PIM Manager together with every delegation that names it, staged in Pending changes.

### Fixes

- **Records grouped more clearly** - Records are grouped as Direct groups, Indirect groups, Who gets what and Other records, and the delegations view lists more group types.

## 2.4.502 · 2026-10-05 · Feature update

You can now enable or disable admin accounts directly, and the request portal is easier to use.

### New features

- **Enable and disable admins** - Admin accounts has Enable and Disable per row or selection. Disable & remove delegations keeps the account but takes its access away on the next run.
- **Your name and support mail on the portal** - Settings > Access requests (RFA) sets the company name and support e-mail the request portal shows.

### Fixes

- **Request portal finds more people** - The portal finds admins and consultants by admin account, contact e-mail or forward address, and sends the PIN where they read mail.
- **Smaller improvements** - The Stop managing dialog says Stop managing instead of Delete, and the portal's sign-in page and header are clearer.

## 2.4.501 · 2026-10-05 · Fix-only

Removing a delegation now takes the access away within minutes.

### New features

None in this version.

### Fixes

- **Removals go live on the next run** - A removed delegation is now taken away by the next run, minutes after the commit. Earlier removed rows that kept their access show as extras on Drift.
- **Permission templates moved** - Permission templates now live under Audit & Settings > Workload templates, next to the template packs.

## 2.4.500 · 2026-10-05 · Fix-only

Approval counts are correct again, and menus and the admin wizard are easier to use.

### New features

None in this version.

### Fixes

- **Expired approvals no longer count** - Requests past their 72-hour expiry no longer count on the Approvals badge or the Overview.
- **Admin wizard asks key questions first** - Step 1 starts with the admin type, Company shows only for consultants, and dates are simple dropdowns of common choices.
- **Clearer menus** - Departments & owners sits next to External Companies, Workload templates has its own page, and Discovery is one menu entry.
- **Access requests page in cards** - The page is laid out in cards and picks the admin for an IT override from a list.

## 2.4.499 · 2026-10-05 · Feature update

The audit trail is protected and names the real person behind every change.

### New features

- **Audit retention** - The Audit page shows how long rows are kept. By default every row is kept; a SuperAdmin can set a period of 13 months or more.
- **Delegated administrators see their audit** - Delegated administrators can now open Audit and see their own actions and events about what they own.
- **Three more safety alerts** - You are alerted when definitions disappear while live items remain, when a Pro licence no longer covers MSP, and when drift exceeds the removal budget.
- **Request portal easy to find** - The menu has Access requests (RFA portal) and Consultants & companies, with the portal link and a Copy button.

### Fixes

- **The audit trail cannot be edited** - Audit rows are protected from change, even outside PIM Manager. Rows only leave through the retention you set.
- **Audit names the real person** - Changes the engine makes for someone's commit now name that person and the approver, not "engine".
- **Licence and updates from Invardia on by default** - Requesting the licence and Pro updates from Invardia are now on by default. Switch them off under Settings > Features.
- **Smaller fixes** - More numbers follow your number format.

## 2.4.498 · 2026-10-05 · Feature update

Menus are quicker to use, numbers follow your format, and you can print the audit trail as evidence.

### New features

- **Menus open on hover** - On a desktop, pointing at a menu opens it and arrow keys move between menus. Touch screens still open a menu with a tap.
- **Numbers in your regional format** - Choose Automatic, Danish, English US, English UK or German in the status line. Your browser remembers the choice.
- **Print the audit trail as evidence** - Print as evidence on the Audit page prints the filtered trail with who printed it, when and the filter used.

### Fixes

- **Exports are audited** - Exporting or printing the audit trail is now itself recorded in the audit trail.

## 2.4.497 · 2026-10-05 · Security

Stronger protection for Pro updates.

### New features

None in this version.

### Fixes

- **Stronger checks on Pro updates** - Every Pro update download is checked before it is applied.
- **Accessible auto-extend field** - Screen readers now announce the auto-extend lead-days field.

## 2.4.496 · 2026-10-05 · Feature update

You now hear about every time a safety guard protects your data.

### New features

- **See every safety guard that steps in** - When a guard holds something to protect your data, you get a mail, it shows under Jobs, and it is recorded in the audit trail.

### Fixes

- **Status telemetry on by default** - Status telemetry to Invardia is now on by default. You can switch it off under Settings > Features.
- **Clearer AD group creation errors** - When the hybrid worker cannot create new AD groups, the message now names the missing right and the group to grant it to.

## 2.4.495 · 2026-10-04 · Fix-only

Emergency access reaches Active Directory in seconds, however many servers you have.

**Action needed:** On a hybrid worker installed before this version, run the hybrid worker setup's Layout step once.

### New features

None in this version.

### Fixes

- **Critical AD groups sync in seconds** - The hybrid worker keeps critical groups such as Domain Admins in sync within about 20-30 seconds, however many servers you have.
- **New AD accounts and groups within seconds** - A new or changed AD admin account or AD group is created or updated in Active Directory within seconds of the commit.
- **Server groups sync in parallel** - Per-server admin groups are read in parallel batches, adjustable under Settings > Hybrid AD & workloads.
- **Job timing counts from the finish** - A job is next due its interval after it finished, never while it is still running. The Jobs page says so.

## 2.4.494 · 2026-10-04 · Feature update

On a managed tenant, access sent by the managing tenant is now clearly marked and protected from change.

### New features

- **Central access marked read-only** - On a managed tenant, everything from the managing tenant is marked CENTRAL and read-only on the Access map and Review current delegations. Central admins can still get local access.

### Fixes

- **AD placements in one place** - The admin account OUs moved to Settings > Hybrid AD & workloads, next to the OU for new AD groups.
- **Smaller fixes** - The environment name examples are now generic.

## 2.4.493 · 2026-10-04 · Fix-only

It is now clear how to prove mail works, and old failures no longer linger on the Overview.

### New features

None in this version.

### Fixes

- **Clear steps to prove mail works** - The permission banner now points to Settings > Mail & alerting > Send test alert, which needs at least one alert recipient.
- **Environment name card easy to find** - It is now the first card under Settings > Naming & accounts.
- **Old failures are cleared** - The Overview no longer shows failures from an earlier run after every definition was removed.

## 2.4.492 · 2026-10-04 · Feature update

Each environment now shows its own name, so several open PIM Managers are easy to tell apart.

### New features

- **Name each environment** - A SuperAdmin sets the name under Settings > Environment name. It shows at the top of every page and in the browser tab.
- **Restore configuration after a rebuild** - A restored backup can be copied into a running environment. It shows a plan first, pauses the engine and never overwrites existing definitions.

### Fixes

- **No false Azure blocked warning** - Without Azure resource delegations, missing Azure rights no longer show as blocked.

## 2.4.491 · 2026-10-04 · Feature update

The hybrid worker is better protected, and PIM Manager can now report status and take Pro updates from Invardia.

**Action needed:** On a hybrid worker installed earlier, run the hybrid worker outbound setup once; it keeps the same address.

### New features

- **Status reports to Invardia (optional)** - PIM Manager can report job results hourly and its version daily, so support sees a failure before you call. Switch it on under Settings > Features.
- **Pro updates from Invardia (optional)** - A Pro installation can take signed releases for its ring from Invardia, checked before anything moves. Switch it on under Settings > Features.
- **Ready script for the hub network owner** - For a private installation, setup writes the script the hub network team runs to create their side of the connection.

### Fixes

- **Safer database administrator group** - Setup now only makes a role-assignable group the database administrator. Otherwise it keeps the current one and says how to recreate the group.
- **Hybrid worker without a public address** - The hybrid worker now only connects outward, and nothing can open a connection to it.
- **Admin updates no longer fail after removals** - A run whose changes were already made no longer fails on its follow-up steps; you get a warning instead.

## 2.4.490 · 2026-10-04 · Fix-only

Setup now always works in the right Azure subscription when a tenant has several.

### New features

None in this version.

### Fixes

- **Setup uses the right subscription** - In tenants with several Azure subscriptions, updates and rollbacks during setup now always use the installation's own subscription.
- **Private DNS zone in the right place** - With the hub network in another subscription, the private DNS zone is now created next to the hub.

## 2.4.489 · 2026-10-04 · Feature update

Your Pro licence can now arrive and renew by itself.

### New features

- **Licence arrives by itself (optional)** - When no Pro licence is installed or yours ends within 30 days, PIM Manager can request and install it from Invardia. Switch it on under Settings > Features.

### Fixes

- **Licence page wording corrected** - The Licence page no longer calls a licence without a tenant valid for any tenant.

## 2.4.488 · 2026-10-03 · Feature update

Licences now work only in their own tenant, and installing PIM Manager takes one guided command.

### New features

- **Guided installation (preview)** - Install PIM Manager with one command from Azure Cloud Shell, signed in as yourself. It checks everything first, reports every step and can resume.
- **Grant or remove Invardia support access** - One command gives the Invardia Support app read-only or setup access, and the same command takes it back.

### Fixes

- **Licences bound to their tenant** - A licence now works only in the tenant it names. Every licence issued so far names its tenant, so you have nothing to do.
- **Access request portal deploys completely** - Deploying the access request portal now also completes its registration and its mail permission.
- **Smaller fixes** - Setup works from Linux and Azure Cloud Shell, and copying settings between environments can keep newer settings.

## 2.4.487 · 2026-10-03 · Fix-only

Licences from Invardia's new signing key are accepted, and existing licences keep working.

**Action needed:** Install this version before you install a licence file from the new Invardia signer.

### New features

None in this version.

### Fixes

- **Licences from the new Invardia signer accepted** - PIM Manager now accepts licences signed by Invardia's new licensing key. Every licence already issued keeps working.

## 2.4.486 · 2026-10-03 · Feature update

Ticketing systems can now switch an admin account on for a set time.

### New features

- **Ticketing systems can enable admins (Pro)** - A ticketing system can enable a disabled admin account for a set time, read the status and cancel it. A proposed change waits for an administrator.

### Fixes

- **One database admin group per tenant** - Environments in one tenant share one database admin group again. Each still keeps its own sign-in app, administrators group and mailbox.

## 2.4.485 · 2026-10-03 · Fix-only

Several environments in one tenant now stay fully separate.

### New features

None in this version.

### Fixes

- **Each environment gets its own sign-in app** - A second environment in the same tenant no longer takes over the first one's sign-in app. Each gets its own app, groups and mailbox.
- **Mail sent from the right mailbox** - Each environment's permission to send notification mail now covers only its own mailbox.
- **Setup with several subscriptions** - Setup now targets the right subscription, stops with the real reason when Azure refuses, and no longer rolls back a healthy deployment.
- **Smaller fixes** - AI assistant sign-in now finishes on deployed environments, and the edition lists are corrected.

## 2.4.484 · 2026-10-03 · Feature update

An AI assistant on the managing tenant can now see your managed tenants, read-only.

### New features

- **AI assistant sees managed tenants (preview)** - On the managing tenant, an AI assistant can list the managed tenants and see what each one receives. It never changes anything.

### Fixes

None in this version.

## 2.4.483 · 2026-10-03 · Security

Security improvements for the AI assistant connection.

**Action needed:** If you use the AI assistant connection, re-run its sign-in setup once after the update.

### New features

None in this version.

### Fixes

- **Stronger sign-in for AI assistants** - The AI assistant connection uses your sign-in and stays off by default.
- **AI assistants find the sign-in** - AI assistant clients can now discover how to sign in by themselves.
- **Ticketing connectors show every field** - A connector set up from the live access request description now shows all request fields.

## 2.4.482 · 2026-10-02 · Feature update

An AI assistant can now work in PIM Manager on your behalf, within your own role and approvals.

### New features

- **AI assistant connection (Pro, preview)** - An AI assistant can read PIM Manager, stage changes and commit them, signed in as you, within your role and the normal approvals. Nothing is ever activated.

### Fixes

- **Access request portal gets updates** - The access request portal now updates with the rest of PIM Manager, and a failed update is shown clearly.

## 2.4.481 · 2026-10-02 · Feature update

Ticketing systems can now propose access changes that an administrator reviews before anything happens.

### New features

- **Ticketing systems propose changes (Pro)** - ServiceNow or another system can propose adding an admin to a PIM group. It becomes a pending change that an administrator reviews and commits.

### Fixes

None in this version.

## 2.4.480 · 2026-10-02 · Feature update

Environments can be switched to internal-only, ticketing systems connect easily, and managed tenants cost less to run.

### New features

- **Switch an environment to internal-only** - An existing environment can now be rebuilt as internal-only while keeping all its data. It shows a plan first and only applies when told.
- **Ticketing system connectors (Pro)** - Ready guides connect ServiceNow, Power Automate and Logic Apps to access requests. A retried request with the same ticket never creates a second one.

### Fixes

- **Lower cost for unchanged managed tenants** - A managed tenant with nothing new now stops in seconds, cutting its daily running cost sharply.
- **Smaller fixes** - Rebuilds restore the permissions of recreated identities and list leftovers to remove by hand, and the access request portal setup needs no manual step.

## 2.4.479 · 2026-10-02 · Feature update

You can define your own rings and grant short-term group access, and the hybrid AD sync now heals itself.

### New features

- **Define your own deployment rings** - Name, add or remove up to ten rings under Settings > Deployment rings. Hovering a ring shows which managed tenants it reaches.
- **Short-term access to another group (Pro)** - In the request portal a consultant can ask for short-term membership of another group. The department approves, and it ends automatically, after 24 hours by default.
- **Bulk actions on Admin accounts** - Select several accounts to link them to a company or department, change the auto-disable date or reset their access.

### Fixes

- **Hybrid AD sync no longer stalls** - The sync can no longer stop for hours unnoticed. Watchdogs restart it, and Settings shows whether each worker job is working.
- **Same initials no longer block commits** - The new-admin wizard now refuses an account name already in use, before anything is staged.
- **Commits explained in plain words** - The commit dialog lists every change in plain words, and a refused commit explains why and offers buttons to fix it.
- **Smaller improvements** - Settings are grouped in categories, some menu items moved, a single-administrator tenant can allow self-approval, and access keys can last up to 10 years.

## 2.4.478 · 2026-10-02 · Feature update

You can act on many administrators at once and handle requests to enable admin accounts.

### New features

- **Act on many administrators at once** - Select administrators to link them to a company or department, or queue a new Temporary Access Pass or a sign-out everywhere for each.
- **Access requests page (Pro)** - Approve or deny requests to enable a disabled admin account for a set time, end a window early, or grant an IT override of up to 31 days.
- **Request portal for consultants (Pro)** - Consultants sign in with a one-time PIN to ask for access, and ticketing systems can send requests too. Deploying the portal is a separate step.

### Fixes

None in this version.

## 2.4.477 · 2026-10-02 · Feature update

You can now watch every committed change until it is live, and commits are faster.

### New features

- **Watch your changes go live** - After you commit, a panel follows each change until it is live in Entra ID or Azure, or shows why it is waiting or failed.

### Fixes

- **Faster commits** - A commit now saves only what really changed, so a small change in a large list commits much faster.

## 2.4.476 · 2026-10-02 · Fix-only

Setup and update messages now tell you exactly what happened and what to do.

### New features

None in this version.

### Fixes

- **Updater shows the real version** - The update log now shows the running version, or says why it is unknown, instead of a long code.
- **Clear reason when Azure refuses setup** - When a policy blocks public network access, setup stops with Azure's own message and points to the private endpoint.
- **Mail sender setup stays time-bound** - Setup explains how to assign Exchange Administrator manually and time-bound, and flags an assignment that runs longer as standing privilege.
- **Smaller fixes** - Clearer guidance for signed-in setup on Azure VM hosts, and managed tenants name the version they pulled.

## 2.4.475 · 2026-10-01 · Fix-only

Managed tenants cost less to run because they no longer redo work when nothing changed.

### New features

None in this version.

### Fixes

- **Lower running cost for managed tenants** - A managed tenant no longer re-applies an unchanged set on every pull; it records unchanged and stops. Central changes still apply on the next pull.
- **No double runs** - Scheduled runs no longer repeat minutes after a change already covered the same areas.

## 2.4.474 · 2026-10-01 · Feature update

The Access map shows a group's real path, and you can change many rows in one step.

### New features

- **Filter Access map columns** - Filter each column by All, Assigned or Not assigned to find your way through hundreds of groups.
- **Change many rows at once** - Select rows in a delegation table and set Policy, Duration, Type or Auto-extend for all of them in one step.

### Fixes

- **Access map shows the path** - Selecting a group now shows its real path with the lines. Possible link targets appear only while you drag or when you switch them on.

## 2.4.473 · 2026-10-01 · Feature update

A Community installation can now move to Pro without reinstalling.

### New features

- **Upgrade Community to Pro in place** - Register a Pro licence on the Licence page and Pro features switch on at once. One command then adds automatic Pro updates.

### Fixes

- **Pro shown only when it unlocks** - A licence for another tenant, or one that is not Pro, is now refused when you register it.
- **"Managing tenant" and "managed tenant"** - These names replace the old MSP wording everywhere you read them. Nothing you stored changes.
- **New group roles no longer fail** - A new role-assignable group's first eligibility now shows as waiting and applies on the next run, instead of failing.
- **Smaller fixes** - Create Discovered Resources now sits right under Create access.

## 2.4.472 · 2026-10-01 · Feature update

Nobody loses access by accident, and owners see each month what will be extended.

### New features

- **Monthly list of upcoming extensions** - Department owners get a monthly list of permissions about to be extended, and can Approve or Deny on My people. No answer means extended.

### Fixes

- **Nobody loses access by accident** - Permissions with an empty auto-extend setting were not extended. They now follow a default that is on; FALSE still means never.
- **Extended 14 days before ending** - Extension now happens 14 days before the end instead of 30, adjustable from 1 to 90 days.
- **Access reviews decide extensions** - A person kept in their department's review is extended; one removed in the review is not.
- **Smaller improvements** - Auto-extend is now a picker in the grid: TRUE, FALSE or empty for the default.

## 2.4.471 · 2026-10-01 · Feature update

You can now hide unmanaged admin accounts you do not care about, and no requested run is lost.

### New features

- **Ignore unmanaged admin accounts** - On Admin accounts, Ignore hides an unmanaged account for everyone, with an optional reason. Stop ignoring brings it back.

### Fixes

- **Requested runs are never lost** - Two runs queued at the same moment, such as Run now during a change, no longer overwrite each other.
- **New group memberships no longer fail** - Adding a member right after PIM Manager creates a group now shows as waiting and applies on the next run.
- **Smaller fixes** - The unmanaged accounts box stays closed until a new account appears.

## 2.4.470 · 2026-10-01 · Fix-only

Drift now shows every extra item, and Admin accounts always shows department owners.

### New features

None in this version.

### Fixes

- **Drift shows every extra** - Drift now lists every extra item. An area over the removal limit says its removals would be held for review.
- **Department owners shown correctly** - Admin accounts no longer says a department has no owners after you opened Reports or Look up a role.
- **Smaller fixes** - The connectivity check reaches Azure again, a hand-set registry name is cleaned up, and a repeated message is fixed.

## 2.4.469 · 2026-09-30 · Fix-only

PIM Manager now carries the Invardia logo, and the documentation is up to date.

### New features

None in this version.

### Fixes

- **New Invardia PIM Manager logo** - The header shows the Community or Pro logo for your edition, and the browser tab shows the Invardia shield.
- **Documentation up to date** - Every screenshot was refreshed, and the documentation describes the hybrid worker and the MSP features as they are now.

## 2.4.468 · 2026-09-30 · Fix-only

A stopped run no longer holds up the next one, and wizards can never overwrite your data by mistake.

**Action needed:** Re-run the hosting access setup once so the scheduler can check its own runs.

### New features

None in this version.

### Fixes

- **Stopped runs no longer delay the next** - After the platform stopped a run, the next runs waited up to 15 minutes. Now they take over at once.
- **Wizards never stage against an empty list** - If a list failed to load, a wizard now says so and stages nothing, so your existing rows can never be replaced.
- **Drift shows hand-made roles in new areas** - Areas you have not defined yet now list their live extras, marked "This area has no definitions yet". PIM Manager never removes them on its own.
- **Fuller Entra ID reference template** - The template now has 76 groups and 168 role links, including 37 task groups and three more role groups.
- **Faster Home page** - The Home page and the job history load faster.

## 2.4.467 · 2026-09-30 · Fix-only

The hybrid worker separates its privilege tiers, and importing an unmanaged admin answers at once.

**Action needed:** Re-run the Active Directory setup with the server account and servers location, then re-run the hybrid worker configuration with both account names.

### New features

None in this version.

### Fixes

- **One hybrid worker account per privilege tier** - Group and membership work now runs as one managed service account and server onboarding as a second. Rights go to each account's permission group, never to the account itself.
- **Import on unmanaged admins responds at once** - Import on the unmanaged-admin list now shows "Importing..." straight away and shows any errors. An imported account shows "Staged" until you commit it.
- **Server permission groups land in your L2 unit** - Discovery now places a server's permission group in your L2 administrative unit.

## 2.4.466 · 2026-09-30 · Fix-only

The live view of the PIM for AD sync now shows data, and settled Remove rows are cleared again.

### New features

None in this version.

### Fixes

- **The hybrid sync live view shows data** - The live view of the continuous hybrid sync stayed empty. The hybrid worker now sends its live data while the view is open.
- **Remove rows with nothing live are cleared** - A Remove row that found nothing live in the tenant stayed in place for good. It is now cleared once the second check confirms there is nothing to remove.

## 2.4.465 · 2026-09-30 · Feature update

You set your own Active Directory naming for PIM for AD, and you can watch the sync as it happens.

### New features

- **Your own naming for PIM for AD** - Settings > Hybrid Active Directory sets how PIM groups, admin accounts and per-server groups map to your Active Directory. A preview shows the names the hybrid worker will use.
- **A live view of the hybrid sync** - Jobs > hybrid-ad-sync > Live view follows every pass: members per group, time left in AD against the PIM activation, and every add, correction and removal.

### Fixes

None in this version.

## 2.4.464 · 2026-09-30 · Fix-only

Committed removals always take effect, and the hybrid worker copes with protected groups and existing servers.

### New features

None in this version.

### Fixes

- **A committed removal always does its job** - A removal committed seconds after the access was given could be cleared before it acted. It is now kept until a second check, ten minutes later, confirms nothing is left.
- **Protected AD groups no longer fail hourly** - Groups that Active Directory protects, such as Domain Admins, keep their own name and description. The hybrid worker reports that difference instead of failing every hour; membership is unaffected.
- **Servers set up earlier are recognised** - Discovery now says when creating a server's group adopts the group your earlier PIM for Active Directory scripts made, instead of making a new one.
- **Clearer message when the worker lacks rights** - The hybrid worker now tells "no access" on a server apart from "unreachable", and names the exact group to add its account to.

## 2.4.463 · 2026-09-29 · Fix-only

A new admin gets the first Temporary Access Pass straight away instead of up to half an hour later.

### New features

None in this version.

### Fixes

- **The first Temporary Access Pass arrives immediately** - A new admin's first pass was delayed 10 to 30 minutes because Entra ID needs a few seconds after creating the account. PIM Manager now waits briefly and retries in the same run.
- **Server onboarding without a hybrid worker** - Without a hybrid worker and no groups marked for Active Directory, server onboarding no longer shows "not implemented". It reports that there is nothing to onboard.

## 2.4.462 · 2026-09-29 · Feature update

You cannot miss whether a commit worked, and new department groups commit reliably.

### New features

- **Commit results in the middle of the screen** - A failed or refused commit now shows a red box listing the errors and exactly what was and was not saved. A successful commit shows a green summary.

### Fixes

- **New department groups commit reliably** - A new group for a department that already had an owner entry could be refused while its assignments were saved, blocking later commits. Existing data is corrected automatically during the update.
- **Commit all saves definitions first** - Commit all now writes definitions before assignments, so a definition that cannot be saved stops the commit before anything that depends on it is written.

## 2.4.461 · 2026-09-29 · Feature update

The hybrid worker can onboard your Windows servers, and the Jobs page shows at once if the worker has stopped.

### New features

- **Server onboarding on the hybrid worker** - Discovery offers each Windows server without a PIM group; Create stages its per-server group. The hybrid worker then adds that group to the server's local Administrators and never removes anyone.
- **The hybrid worker on the Jobs page** - Every on-premises AD job shows where it runs: on the worker (green), plan-only (amber) or worker not seen (red). A stopped worker is visible at once.

### Fixes

- **Clearer rules for custom Manager names** - A custom Manager name is optional. On an environment reachable from the internet it must be a public subdomain you own; private names are refused with the options.
- **Smaller improvements** - The hybrid worker's setup now defaults to a 4 GB virtual machine.

## 2.4.460 · 2026-09-29 · Fix-only

The hybrid worker's plan is now easy to review before you let it change anything.

### New features

None in this version.

### Fixes

- **The hybrid worker log lists every change** - The worker now writes one line per group or member it would change, or changed, with the reason. The continuous sync writes a new plan only when it changes.
- **Quieter handling of nested groups** - A group that is a member of a PIM group is still skipped, now without an error line in the worker log on every pass.

## 2.4.459 · 2026-09-29 · Fix-only

The hybrid worker can work with Active Directory groups again.

### New features

None in this version.

### Fixes

- **Hybrid worker group work runs again** - In the previous version every Active Directory group step of the hybrid worker failed, so the group mirror and membership sync could not run. Nothing was changed in AD; both work now.

## 2.4.458 · 2026-09-29 · Feature update

PIM now reaches your on-premises Active Directory, granting AD access only while someone has activated it.

### New features

- **The hybrid worker for on-premises AD** - A small domain-joined Windows server creates your admin accounts in Active Directory and puts people who activate a PIM group into its AD twin within seconds. This is a Pro preview.
- **See the plan before it changes anything** - The hybrid worker has a plan-only mode that shows what it would change, and it updates itself to the version your ring approves.
- **Import all permission templates at once** - Templates now has Import all, plus a quick-start template with the Entra ID role groups, imported with your own naming convention.
- **Create discovered resources in one place** - Access > Create Discovered Resources takes you straight to the new resources Discovery found, ready to create.
- **Your own host name for the Manager** - The setup script can give the Manager a custom host name, and mail links use it once configured.

### Fixes

None in this version.

## 2.4.457 · 2026-09-28 · Fix-only

The Manager is noticeably faster on Home, Jobs, Commit and Audit, and large reads from Microsoft are throttled less.

### New features

None in this version.

### Fixes

- **Home and Jobs load much faster** - Home now loads in 1 to 3 seconds instead of 4 to 6, and the Jobs page in about 0.7 seconds.
- **Recent changes on Commit appear instantly** - The recent configuration changes on the Commit page now load in a quarter of a second instead of about seven.
- **The Audit tab is faster** - The Audit tab reads the before and after details only for the entries on screen, so it is about a third faster.
- **Fewer slow-downs from Microsoft on large reads** - When Microsoft starts slowing PIM Manager down, it now asks for less at a time. Large reads hit far fewer limits and finish sooner.

## 2.4.456 · 2026-09-27 · Fix-only

Importing an unmanaged admin now brings their group memberships with them.

### New features

None in this version.

### Fixes

- **Import brings back an admin's memberships** - Import of an unmanaged admin offered only the account. It now reads the admin's current PIM group memberships and offers a row to keep each one.

## 2.4.455 · 2026-09-27 · Feature update

You can take admins out of PIM Manager or bring existing ones in, and manage Administrative Units from Drift and Discovery.

### New features

- **Stop managing an admin** - On Admin accounts or the Access map, Stop managing takes an admin out of PIM Manager. Nothing changes in Entra ID; use Mark for manual removal to also remove the access.
- **Import admins PIM Manager does not manage** - Admin accounts now lists admin accounts that exist in the directory but not in PIM Manager. Import stages the admin and the access they hold today for Review & commit.
- **Keep Administrative Units from Drift** - An Administrative Unit found in the tenant but not in PIM Manager can now be kept from the Drift page. PIM Manager never deletes an Administrative Unit.
- **Administrative Units in Discovery** - New Administrative Units appear in Discovery, and Create stages their definition.
- **Create an Administrative Unit card** - A new card defines an Administrative Unit and can give a group Entra roles inside it. Giving a group Entra roles can now be limited to chosen units.

### Fixes

- **Import administrators accepts its own example** - Import administrators now accepts the format its example shows: sign-in name, display name and department, without a header line.

## 2.4.454 · 2026-09-27 · Fix-only

Removing one access in a review really removes it, and the Manager stays responsive.

**Action needed:** If you committed a one-access removal with version 2.4.453, remove it again, or use Delete on the Drift page.

### New features

None in this version.

### Fixes

- **Removing one access in a review works** - In the previous version, removing one access in a review left the membership in the tenant. Once committed, PIM Manager now removes exactly that membership.
- **The Manager stays responsive** - The permission check on Overview is now reused for five minutes instead of running on every visit, so other pages no longer wait. Verify permissions still checks at once.
- **Faster audit trail and Pending changes** - The audit trail prepares its summaries only for entries on screen, and Pending changes no longer holds up a commit.
- **Fewer slow-downs on large reads** - When Microsoft asks PIM Manager to slow down, it now pauses between batches, so large drift reads finish with far fewer retries.

## 2.4.453 · 2026-09-27 · Feature update

Reviewers can remove a single access, you can act on drift directly, and the drift mail follows your schedule.

### New features

- **Remove one access in a review** - In a department access review, tick the access a person no longer needs and choose Remove. Only that access is staged for removal; the account keeps the rest.
- **Unanswered reviews can request removal** - A review rule can now request removal for people still undecided after the reminders. A PIM administrator approves or denies each request; by default undecided people keep access.
- **Delete, Keep or Ignore on Drift** - On the Drift page, an extra item can be deleted after commit, kept so PIM Manager manages it, or ignored in one click. Ignored items can be re-added.
- **Drift mail on your schedule** - The drift alert mail now goes out monthly by default. A SuperAdmin can change it to daily, weekly or quarterly on the Drift page.
- **Access reviews are per department only** - A group's review cycle no longer creates a Microsoft Entra access review per group. Reviews created earlier stay in Entra ID until you remove them.

### Fixes

None in this version.

## 2.4.452 · 2026-09-27 · Security

Every approval covers exactly one change set, and automated test runs are clearly labelled in the audit trail.

### New features

None in this version.

### Fixes

- **Stronger protection for approvals** - Each approval covers exactly the policy changes that were reviewed.
- **Automated runs are named in the audit trail** - Automated test runs are now recorded as that automation, acting as the signed-in account, instead of under a person's name. A hosted Manager always records the real signed-in person.

## 2.4.451 · 2026-09-26 · Fix-only

A managed tenant's first pull no longer reports a failure for something that is only waiting.

### New features

None in this version.

### Fixes

- **No false failure on the first pull** - On a managed tenant's first pull, a new group's membership waits a moment for the group. The pull is now recorded as successful and says what is waiting.

## 2.4.450 · 2026-09-26 · Fix-only

Access reviews show each person's real access, and nobody can review their own account.

### New features

None in this version.

### Fixes

- **Reviews list each person's access** - When an admin was defined by a short account name, the review showed no access for them. It now shows the full sign-in name and the access they hold.
- **No reviewing your own admin account** - A reviewer can no longer decide on their own admin account. Another reviewer or a SuperAdmin decides it.

## 2.4.449 · 2026-09-26 · Fix-only

Reviewers who sign in with an admin account now receive their review mails.

### New features

None in this version.

### Fixes

- **Review mails reach admin-account reviewers** - Admin accounts have no mailbox, so review and reminder mails now go to the account's forward address or its department's owners.

## 2.4.448 · 2026-09-26 · Feature update

Department access reviews now run inside PIM Manager, reviewing people rather than groups, with no extra Microsoft licence.

### New features

- **Reviews cover a department's people** - Each round lists every admin account of the department with the access it holds. Reviewers choose Keep or Remove per person on My people.
- **Two approvers, parallel or serial** - In parallel both decide and any Remove wins. In serial approver 1 decides first and approver 2 has the final word.
- **Unanswered reviews are chased** - After the due date reviewers get a weekly reminder three times, then alert recipients are told and the round closes. Undecided people keep their access.
- **Senior administrators can override** - A senior administrator can decide any open person on the Access reviews page. Every decision is recorded in the audit trail.
- **Remove always goes through approval** - Remove never takes access away directly. It raises a removal request that a PIM administrator approves.

### Fixes

None in this version.

## 2.4.447 · 2026-09-26 · Feature update

Access reviews now run per department on rules you set, and departments without an owner are flagged daily.

### New features

- **Review rules per department** - On Access reviews, Review rules sets how often each department is reviewed, for how long, by whom and with one or two approvers. A department can also opt out.
- **Departments without an owner are reported** - A department without an owner is reported to the alert recipients every day until someone names an owner.

### Fixes

None in this version.

## 2.4.446 · 2026-09-26 · Feature update

Discovery becomes one simple list you can act on in a click, and commits are no longer reported as failures while they roll out.

### New features

- **Discovery is one list: Create or Ignore** - Discovery lists what is in your tenant but not yet in PIM Manager. Create or Ignore one item, several, or a whole kind in one click.
- **Create stages a permission group** - Create turns an Azure scope or Power BI workspace into a permission group named by your convention, ready in Review & commit. Nothing is granted to anyone.
- **See and re-add ignored items** - The Ignored view lists ignored items with who ignored them and when, and Re-add brings one back.

### Fixes

- **No alerts while a commit rolls out** - For 45 minutes after a change, a failed run or drift is not emailed, giving the commit time to finish. Changes waiting for your approval are still reported at once.
- **Duplicate Defender XDR roles are removed** - Duplicate Defender XDR roles are now removed on the next run, also when a group is already bound to one of the copies.

## 2.4.445 · 2026-09-26 · Fix-only

You get fewer and clearer alert emails.

### New features

None in this version.

### Fixes

- **The same drift is not emailed repeatedly** - An unchanged drift report is sent once, then at most daily while it lasts. A change is sent at once; repeated identical job failures work the same way.
- **Drift reports name what they found** - An Azure assignment that PIM Manager does not manage is now reported with the account or group and the role, instead of a blank.
- **Duplicate Defender XDR roles are cleaned up** - When Defender XDR answered slowly, a custom role could be created twice. PIM Manager now waits for it and removes its own unused extra copy; your roles are never removed.

## 2.4.444 · 2026-09-26 · Fix-only

Setup and engine runs no longer fail on short Microsoft delays.

### New features

None in this version.

### Fixes

- **Mailbox setup waits out a Microsoft delay** - Right after its permission is granted, Microsoft can refuse the mailbox check once. Setup now retries for a few minutes before reporting that mail cannot be sent.
- **New accounts and groups no longer fail runs** - A role or PIM policy for an account or group created moments earlier is now treated as a short wait that the next run completes, not as a failure.
- **The Community updater finds your installation** - Test runs no longer leave a saved deployment behind, so the Community updater always finds your own installation.

## 2.4.443 · 2026-09-26 · Feature update

Azure delegation levels follow your management-group layout, Community users see what Pro adds, and protection for delegated administration is stronger.

### New features

- **Azure levels follow your management groups** - The Create wizard sets an Azure permission group's level from where its scope sits in your management-group tree. The preview says where the level came from.
- **Community shows what Pro adds** - In Community, every Pro page is listed in the menu, dimmed and marked PRO, with a comparison and a way to buy or register Pro.
- **Update Community with one command** - The Community update script now pulls the latest release and re-runs your deploy with its original settings. Without the apply option it only shows the plan.

### Fixes

- **Changing access review reviewers works** - Changing who reviews an access review is now accepted by Microsoft, and PIM Manager checks the result.
- **Emergency overrides end on time** - An emergency override now ends on time even when other work is running, and approval is put back on the next run.
- **New installations set up their mailbox** - The one-command deploy no longer stops at the notification mailbox step. An older deploy identity gets the missing right automatically on its next deploy.
- **Stronger protection for delegated administration** - Security hardening for delegated administrators, staged changes, break-glass accounts and managed tenant selection. MSP management is now always part of Pro.
- **Smaller fixes** - Staged edits are no longer lost, dates keep their exact value, mail links use the Manager's own address, and the daily target check reports unreadable subscriptions correctly.

## 2.4.442 · 2026-09-25 · Fix-only

Access review decisions and reviewer changes are no longer refused on a correctly set-up environment.

### New features

None in this version.

### Fixes

- **Access review decisions are always applied** - Access review decisions and reviewer changes are now carried out by the engine, which checks they took effect. The review buttons are no longer refused.

## 2.4.441 · 2026-09-25 · Fix-only

Checks on acknowledged warnings and imports work as intended.

### New features

None in this version.

### Fixes

- **Warning and import checks work fully** - Acknowledging a warning now gets the same full check the engine applies, and the import check uses your tenant's roles, groups and scopes as intended.

## 2.4.440 · 2026-09-25 · Fix-only

A new Community installation now finishes, exactly as the README describes.

### New features

None in this version.

### Fixes

- **Community installations finish** - A new Community installation no longer stops half-way. It now completes and checks itself: the Manager runs, the page answers behind sign-in and the engine job exists.
- **The README install command works** - The install command in the README now names who may sign in to the Manager, which is required. A dry run tells you if it is missing.

## 2.4.439 · 2026-09-25 · Feature update

Department owners can manage Azure access on their own resources without a central administrator.

### New features

- **Department owners delegate on their resources** - Give a department its Azure scopes, and its owners can create, change and commit the department's Azure permission groups at level 3 and below. This is part of Pro.
- **Clear limits for department owners** - Owners cannot touch other departments, level 2 or above, or tier 0, and every refusal is in the audit trail. A department with no Azure scopes gives no Azure rights.

### Fixes

None in this version.

## 2.4.438 · 2026-09-25 · Feature update

Department owners can confirm, extend or ask to remove their people's access, with an optional regular review by mail.

### New features

- **Keep, Extend or Remove on My people** - Department owners can confirm a person's access, extend it, or request its removal on My people. A PIM administrator approves removals, and the page shows who is due for review.
- **A regular owner review by mail** - The new owner review job mails each department's owners their people with a link to My people. Turn it on under Jobs; it runs every 90 days by default.

### Fixes

None in this version.

## 2.4.437 · 2026-09-25 · Fix-only

Managed tenants carry out removals, renames and session revokes from the managing tenant again.

### New features

None in this version.

### Fixes

- **Managed tenants act on central decisions** - A managed tenant ignored every removal, rename and session revoke from the managing tenant as expired. They are now carried out; only decisions older than 30 days are ignored.

## 2.4.436 · 2026-09-25 · Feature update

Removing an administrator on the managing tenant now reaches exactly the managed tenants you choose.

### New features

- **Choose where a removal applies** - When you remove a replicated administrator or row on the managing tenant, the Manager asks whether to remove it in every managed tenant, chosen ones, or none.
- **Managed tenants remove the administrator too** - A managed tenant now removes the administrator together with their memberships. Before, only the memberships were removed.

### Fixes

- **Offboarding still reaches every tenant** - An auto-disable date set on the managing tenant still reaches every managed tenant the administrator is in, without asking. Removals from the last 30 days are applied after this update.

## 2.4.435 · 2026-09-25 · Feature update

Department owners can extend their people's access before it ends, without waiting for an administrator.

### New features

- **My people: extend access before it ends** - The new My people page shows department owners when each person's access ends. They can extend it, up to a year ahead by default, and every extension is audited.
- **A reminder two days before access ends** - Owners get a reminder two days before a person's access ends, and the mail opens My people at that person.

### Fixes

- **Central removals reach managed tenants** - Removals, renames and session revokes from the managing tenant now reach managed tenants. Removals recorded in the last 30 days are delivered after this update.

## 2.4.434 · 2026-09-25 · Fix-only

A central session revoke is carried out exactly once in each managed tenant.

### New features

None in this version.

### Fixes

- **Session revokes are never done twice** - A managed tenant now records a central session revoke the same way on every PowerShell edition, so it is never carried out twice.

## 2.4.433 · 2026-09-25 · Feature update

One session revoke on the managing tenant now signs an administrator out of every managed tenant, which matters most when someone leaves.

### New features

- **One revoke reaches every managed tenant** - When you revoke an administrator's sessions on the managing tenant, the Manager asks whether to revoke them in managed tenants too. Each tenant then does so without its own approval.

### Fixes

- **Revokes are reliable and safe** - Each tenant carries out a revoke once, and removing the administrator right after no longer cancels it. Break-glass accounts are never revoked.

## 2.4.432 · 2026-09-25 · Feature update

Changes that someone started but never committed no longer go unnoticed.

### New features

- **A daily reminder of uncommitted changes** - A new daily job finds staged changes and queued actions waiting over a day, with who started them. The list is mailed to your alert recipients with a link to Pending changes.
- **You control the reminder** - Switch the mail off under Alerting. A SuperAdmin can change the interval or turn the job off on the Jobs page.

### Fixes

None in this version.

## 2.4.431 · 2026-09-25 · Feature update

You learn when a delegation points at an Azure resource or role that no longer exists.

### New features

- **A daily check of delegation targets** - A new daily job checks that the Azure resources, scopes and roles your delegations use still exist. Missing ones are listed at the top of Coverage & gaps; you decide what to remove.
- **Mail when something disappears** - New findings are mailed once to your alert recipients. You can switch the mail off under Alerting and change the schedule on the Jobs page.

### Fixes

None in this version.

## 2.4.430 · 2026-09-25 · Feature update

Every mail takes you straight to the right page, drift shows exactly what differs, and you can ignore a finding with a reason.

### New features

- **Every mail opens the right page** - Every PIM Manager mail now has an "Open in PIM Manager" button that opens the page it is about. Mails that carry a sign-in credential have no link.
- **Drift shows what differs** - A changed drift finding now shows the field with its current and desired value. The drift alert mail lists the findings themselves, not only counts.
- **Ignore a drift finding** - An Admin can ignore a drift finding with a reason. It leaves the counts, the page and the mail, and ignored findings are listed separately and can be un-ignored.

### Fixes

- **Review now works in reminders** - The "Review now" button in the review reminder mail now works.

## 2.4.429 · 2026-09-25 · Feature update

PIM Manager now only touches what you define, and held policy changes come with a spreadsheet your change board can approve.

### New features

- **A spreadsheet for your change board** - A large policy change held for approval now comes with an Excel file listing every setting's current and new value. Download it from Approvals with Download for change board.

### Fixes

- **Only what you define is changed** - Policies are now changed only for groups you define or roles your assignments name. Policies on other groups and roles are left exactly as they are.
- **An empty environment changes nothing** - When you have defined no admins, groups or assignments, the engine skips every step and writes nothing.

## 2.4.428 · 2026-09-25 · Feature update

Administrators share one list of Pending changes, cannot overwrite each other, and can require a second approver.

### New features

- **Pending changes shared by every administrator** - Every administrator now sees the same Pending changes, updated every few seconds, with who staged each change. Your browser's earlier changes join the shared list automatically.
- **Rows are locked while staged** - When a colleague has staged a change to a row, nobody else can change it until it is committed or discarded. You are told who holds it.
- **An optional second approver** - A SuperAdmin can require that sensitive changes, or all changes, are committed by a different administrator than the one who staged them.

### Fixes

- **Cancel all pending discards only yours** - Cancel all pending now discards only your own changes; your colleagues' changes stay. A commit asks first when it includes colleagues' changes.

## 2.4.427 · 2026-09-25 · Fix-only

The permission check no longer falsely reports a missing mail sender.

### New features

None in this version.

### Fixes

- **No false "no mail sender" warning** - After the Manager restarted, the permission check on Overview could say no mail sender was configured. It now reads the sender first.
- **Clearer wording for mail problems** - A problem that only affects mail is no longer described as the engine missing required permissions.

## 2.4.426 · 2026-09-25 · Fix-only

Commits no longer fail with a false "another administrator" message, and the permission check stops raising false alarms.

### New features

None in this version.

### Fixes

- **Commits no longer blame another administrator** - When the engine's own work changed rows under you, Commit was refused and you had to reload. It now re-applies your edits and commits, asking only when your rows really changed.
- **Correct Azure result in the permission check** - The permission check on Overview now reads the Azure roles the engine actually holds, including inherited ones, so it no longer reports a false blocker.
- **Mail status in the permission check** - Mail now counts as working when the latest real alert was delivered, and failing when the latest attempt failed, instead of always "not verified".

## 2.4.425 · 2026-09-25 · Fix-only

Access map lines stay in place, and admins scheduled for later no longer cause false failures.

### New features

None in this version.

### Fixes

- **Access map lines stay in place** - Clicking Remove access or Give access twice threw the lines across the board. The map now redraws its lines once the layout has settled.
- **No false failures for future admins** - Memberships for an admin scheduled for a later date were reported as missing from the tenant. They now wait and are applied right after the account is created.

## 2.4.424 · 2026-09-25 · Feature update

The permission check now works on hosted environments and hands you a ready script to fix what is missing.

### New features

- **A ready script to fix permissions** - When the engine lacks a permission, the Overview banner shows a ready-to-run PowerShell script with a Copy button. A Global Administrator runs it once.

### Fixes

- **The permission check works when hosted** - On hosted environments the check always said permissions could not be checked. It now checks the engine's permissions and says why if it cannot run.
- **Access map shows the whole path** - Selecting a permission group on the Access map now lights its whole path, from the people through to the permissions.

## 2.4.423 · 2026-09-24 · Fix-only

Held policy changes stay visible for approval, and Reset TAP always responds.

### New features

None in this version.

### Fixes

- **Held changes stay visible under Approvals** - After anyone opened Access reviews, Approvals stopped showing held policy changes until a restart. They now stay visible and can be approved.
- **Reset TAP always answers** - Clicking Reset TAP before the list had loaded did nothing. It now finds the admin anyway, or says so if the admin cannot be found.

## 2.4.422 · 2026-09-24 · Fix-only

Renaming a group now renames it in Entra ID, and access reviews get the permission they need.

**Action needed:** Grant the hosting permissions again so the new access review permission takes effect.

### New features

None in this version.

### Fixes

- **Group renames reach Entra ID** - A rename still created a second group in the previous version. The engine now renames the group it already has.
- **Access reviews get the right permission** - The deployment now grants the access review permission Microsoft requires, which also covers reading and changing other reviews. Reviews are then created and mail their reviewers.
- **Reset TAP explains when it cannot work** - Without a mail sender, Reset TAP in Accounts & TAP is now disabled and says why: a pass is only ever sent by mail.

## 2.4.421 · 2026-09-24 · Fix-only

Renames no longer leave unmanaged copies behind, access reviews can be created, and two misleading failures are gone.

**Action needed:** Remove by hand in Entra ID the old copy of any group you renamed on an earlier version.

**Action needed:** Grant the hosting permissions again so access reviews can be created.

### New features

None in this version.

### Fixes

- **A rename renames instead of copying** - Renaming a group or Administrative Unit created a second one in Entra ID, leaving the old one unmanaged. The engine now renames the existing object, keeping its members and roles.
- **Access reviews can be created** - Every run that created an access review failed for lack of permission. The deployment now grants a permission to create reviews of group membership.
- **A new admin's pass no longer fails runs** - When the pass job ran before the new account existed, the run failed. It now waits and issues the Temporary Access Pass on its next run.
- **Clear answer when guests are blocked** - If your tenant allows no guest invitations, PIM Manager now stops at once and names the External collaboration setting to change.

## 2.4.420 · 2026-09-24 · Fix-only

Revokes are confirmed, new accounts no longer fail runs, and Pending changes and times are easier to read.

### New features

None in this version.

### Fixes

- **A revoke is checked, not assumed** - A sign-in session revoke is now confirmed instead of recorded as not verifiable. A revoke for an account deleted in the meantime now completes as done.
- **New accounts no longer fail the run** - A role given to an account created minutes earlier is now shown as waiting and applied on the next run, instead of failing the whole run.
- **Pending changes says what a change is** - Each changed row leads with its name, and a group deletion says it will be deleted in Entra ID on the next run.
- **Times are shown correctly** - Queued changes could show times hours off. Every time is now shown in one format in UTC.
- **Smaller fixes** - The Home permission banner no longer hangs, screens use the menu's names, help text is readable, and a first deployment into an empty tenant no longer looks stuck.

## 2.4.419 · 2026-09-23 · Fix-only

An environment with a private container registry can update itself every night again.

**Action needed:** Build the first update to this version on your private build pool by hand; after that the environment updates itself.

### New features

None in this version.

### Fixes

- **Nightly updates work with private registries** - With public registry access turned off, every nightly update failed and the environment stayed on its old version. Updates now build on your own private build pool.

## 2.4.418 · 2026-09-23 · Fix-only

Selecting rows in All records no longer hides them behind a tall help table.

### New features

None in this version.

### Fixes

- **The action table no longer buries rows** - Selecting a row in All records opened a help table so tall it covered your selection. It now uses the full width and stays a few lines tall.

## 2.4.417 · 2026-09-23 · Fix-only

The Access map is visible again at every window width.

### New features

None in this version.

### Fixes

- **The Access map is back** - With something selected, the toolbar pushed the Access map out of view. The toolbar now wraps and the map always keeps room to show.

## 2.4.416 · 2026-09-23 · Fix-only

Admins who have not signed in yet no longer receive a new Temporary Access Pass every day.

### New features

None in this version.

### Fixes

- **No more daily Temporary Access Pass mails** - Each admin now gets one Temporary Access Pass. When it expires nothing happens automatically; click Reset TAP for that admin to send a new one.

## 2.4.415 · 2026-09-22 · Feature update

Approvers can always see exactly what they approve, and greyed-out buttons explain themselves.

### New features

- **Approval requests list what they authorise** - Requests raised from a refused Review & Save now list the staged changes in plain words. The manual Raise a request form requires the same list, pre-filled where possible.
- **Copying settings between tenants is documented** - The Naming conventions card now shows the command that copies a setting to another tenant. It is a dry run unless you ask it to apply.

### Fixes

- **Greyed-out buttons say why** - Commit selected now shows on the button itself why it is off, instead of in a paragraph above the table.
- **"Already authorised" needs nothing from you** - The panel of changes your managed tenants will receive now says they are done and travel on the next publish. You only act to cancel a mistake.

## 2.4.414 · 2026-09-22 · Feature update

You can now take a delegation away or delete a group from the Manager, and the four removal actions are clearly defined.

### New features

- **Take a delegation away** - A delegation row now has a remove button that takes that exact access away on the next run, then clears the row.
- **Delete a group from the Manager** - Each group row has a bin that deletes the group in Entra ID after commit. It is refused while anyone still has access through it, and names who.
- **Four actions, clearly explained** - Stop managing, Remove, Revoke and Delete are defined once and shown wherever you choose. Each confirmation repeats what survives.

### Fixes

- **Access map removals really remove access** - Removing a link on the Access map deleted only the row and left the access in place. It now stages the removal that takes the access away.
- **Revoke explains it is temporary** - The revoke screen now says a revoked access comes back on the next run unless you also remove the delegation.
- **Smaller fixes for Windows PowerShell 5.1** - On Windows PowerShell 5.1, PIM Manager's own administrators group no longer shows as drift, and misspelt admin names get their suggestion list again.

## 2.4.413 · 2026-09-22 · Fix-only

Managed tenants create administrators again, and administrators sent by your provider are no longer reported as missing.

### New features

None in this version.

### Fixes

- **Managed tenants create administrators again** - In the previous version the administrator job on a managed tenant failed every run, so sent administrators were never created. It runs again.
- **Provider administrators are no longer flagged** - Pending changes reported delegations naming your provider's administrators as errors on a managed tenant. They now count as defined; truly undefined accounts are still reported.
- **Admin naming comes from tenant settings** - A tenant's own administrator naming setting now wins over the deployment value, and any disagreement is noted in the job log.

## 2.4.412 · 2026-09-22 · Feature update

Every administrator your provider publishes now reaches the managed tenant, whatever their name looks like.

### New features

- **Copy a setting between tenants** - A new setup script copies a setting, such as naming conventions or a schedule, to another tenant. It backs up the target first and refuses tenant-specific settings.

### Fixes

- **Admins are no longer withheld by name** - A managed tenant's naming setting could silently drop published administrators. Every published admin is now sent, and a naming mismatch is only reported.
- **Sent administrators are managed normally** - The engine now recognises centrally sent administrators whatever they are called, so they are managed like any other and never recreated in a loop.
- **Pull results shown on Job schedule** - The explanation of each pull, such as how many administrators were sent or excluded, is now kept and shown on Job schedule.

## 2.4.411 · 2026-09-22 · Feature update

Approvers see exactly what they approve, and a managed tenant can tell its provider's rows from its own.

### New features

- **Approvals list each assignment** - A revoke approval now shows one readable line per assignment it covers. Raised from the revoke screen, it is filled in for you.
- **See where each row came from** - On a managed tenant, every replicable record type now has a Source column, from the managing tenant or local, with counts in the header.

### Fixes

- **Fix buttons update the status at once** - Every fix button and Fix all auto-fixable errors now updates the error count and Save gate immediately, so you no longer switch Block-Save off to commit.
- **Clearer replication wording** - Replication wording no longer suggests a value missing from the picker, and rows carried along only as a dependency no longer need a ring.

## 2.4.410 · 2026-09-22 · Feature update

Replicated delegations reach the managed tenants they should, and several dead ends in daily work are gone.

### New features

- **Admins follow the delegations that need them** - An admin account can be set to "Only where a delegation needs this admin", so it is created in a managed tenant exactly where a replicated delegation names it.
- **Set replication and ring in bulk** - Tick rows in All records and use Set replication to... and Move to ring... in the selection bar.

### Fixes

- **Unpublished delegations are listed, not dropped** - A replicated delegation whose admin is not replicated was silently dropped. It is now listed as not published, with the fix in the sentence.
- **Replicated rows must name a ring** - A row set to replicate with an empty ring reached nobody. Saving such a row is now refused.
- **Cloning a row no longer blocks commits** - A cloned row now gets its own group tag. Existing duplicates are listed, with Show me these rows and a one-click fix.
- **Waiting items no longer fail jobs** - An item waiting for a group created in the same cycle is now reported as waiting, not as a failed job. It becomes a failure if it still waits hours later.
- **Smaller fixes** - Removing an assignment updates the status at once, an already-removed Azure assignment counts as done, and the Access map, Commit selected and Backups / Undo are clearer.

## 2.4.409 · 2026-09-22 · Fix-only

On the Access map, giving and removing access are now separate buttons you cannot confuse.

### New features

None in this version.

### Fixes

- **Give and remove are separate buttons** - Give access is blue and Remove access is red, and each list shows only that direction's choices. A click can never do the opposite of what you pressed.
- **Staged changes are easy to tell apart** - A staged addition is amber and says "staged add"; a staged removal is red, struck through and says "staged remove".
- **The selection bar stays in view** - The bar showing your selection and its buttons now sticks to the bottom of the screen, tinted blue while giving and red while removing.
- **Clearer link names** - Links now use the record names shown elsewhere, for example "Open Service groups in All records".

## 2.4.408 · 2026-09-22 · Feature update

Administrators with spaces or accents in their name can sign in again, and you can remove a delegation right on the Access map.

### New features

- **Remove a delegation on the Access map** - Click an existing link on the Access map, confirm by name, and the removal is staged until you commit it on Review & Save. Click again to undo.

### Fixes

- **Sign-in works for every name** - Administrators whose display name contains a space or an accented letter could not sign in. Install this version and sign-in works; nothing changes in your tenant.
- **"Cannot be deleted" names the blockers** - Deleting a group still in use now lists each delegation in plain words and opens exactly those rows, so you can remove them first.
- **Search finds group tags** - Review current delegations now finds group tags too. When nothing matches, it explains the difference and offers to search the Access map.
- **Clearer audit trail entries** - A sign-in is now one readable sentence instead of fields reading "(none)".
- **PIM Manager's own group is not drift** - The administrators group the deployment creates for PIM Manager itself is no longer reported as drift. The page says what was left out.

## 2.4.407 · 2026-09-22 · Feature update

You can now see both update schedules in one place, and every managed tenant can pull on demand.

### New features

- **Both schedules on one page** - The Job schedule page now shows the daily software update beside the definitions pull, with its timing, its ring and where to change it.

### Fixes

- **Run pull now on every managed tenant** - Before, only locally hosted managed tenants offered Run pull now. Every managed tenant now shows its pull schedule and the button.
- **Clearer replication label** - An empty replication value now reads "No replication to managed tenants (default)" instead of "(blank)". Your data is unchanged.

## 2.4.406 · 2026-09-22 · Feature update

Removals and renames you decide once on the managing tenant now reach every managed tenant.

### New features

- **Remove a row in managed tenants too** - When you remove a replicated row, you can choose to remove it in the managed tenants as well. Each tenant removes it on its next pull, without separate approvals.
- **Renamed groups stay one group** - Renaming a group now renames it in the managed tenants instead of creating a second group. A rename onto a name a tenant already uses is refused.
- **See and cancel before publishing** - Every authorised removal or rename is listed on Pending changes with what, where and who decided it. You can cancel it before it is published.

### Fixes

None in this version.

## 2.4.405 · 2026-09-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.404 · 2026-09-22 · Fix-only

A group that still grants access can no longer be deleted by accident.

### New features

None in this version.

### Fixes

- **Groups in use cannot be deleted** - Deleting a group is refused while anything still uses it. You are told how many rows use it, so you can remove them deliberately first.

## 2.4.403 · 2026-09-22 · Feature update

You can rename groups safely, and the replication choice is simpler.

### New features

- **Rename a group or administrative unit** - In All records you can rename a group or administrative unit, including its tag. Every row that uses it is updated in the same change when you commit.

### Fixes

- **Deleting a group shows what else goes** - Before, deleting a group left rows pointing at nothing. You now see exactly which rows use it and can remove them together or cancel.
- **Replication is a simple two-way choice** - Choose Replicate to managed tenants or No replication. The old Follow option meant the same as No replication and is gone; what is sent is unchanged.

## 2.4.402 · 2026-09-22 · Fix-only

New Microsoft Entra roles no longer add needless work to your Pending changes.

### New features

None in this version.

### Fixes

- **New Entra roles are reported, not queued** - A newly found built-in Entra role is now reported in the discovery mail instead of being queued. Uncovered roles are listed as gaps on Coverage & gaps, with a proposal.

## 2.4.401 · 2026-09-22 · Feature update

You can undo a link on the Access map, and Pending changes is faster and easier to read.

### New features

- **Undo a staged link** - On the Access map, Ctrl+click a staged link again, drop on it again or press the x to take it back. Committed links must be revoked instead.

### Fixes

- **No duplicate links** - Repeating a click can no longer stage the same link twice, and repeated messages no longer stack up.
- **Pending changes loads faster** - Discarded entries are loaded only when you tick Show discarded. The counts still cover everything, and failed entries are always shown.
- **Pending changes in plain words** - Entries now say what they do, for example cataloguing a named Entra ID role, instead of showing a technical key.
- **Discovery follows your policy** - Role discovery now respects the Discovery policy you set. With flag, it only reports what it found and queues nothing.

## 2.4.400 · 2026-09-21 · Fix-only

Linking on the Access map works even after you select someone.

### New features

None in this version.

### Fixes

- **Link targets stay on screen** - Selecting a person or group used to hide every box you could link it to. Those boxes now stay visible, faded, and light up as you point at them.

## 2.4.399 · 2026-09-21 · Fix-only

A link made by dragging on the Access map now shows up straight away.

### New features

None in this version.

### Fixes

- **Dragged links show on the map** - A link made by dragging was added but not drawn. It now shows the dashed line and staged marking, exactly like Ctrl+click.

## 2.4.398 · 2026-09-21 · Fix-only

The Access map draws its lines to the right boxes again.

### New features

None in this version.

### Fixes

- **Access map lines connect correctly** - After you selected a person or group, lines could appear to connect the wrong rows. They are now redrawn whenever the board moves.

## 2.4.397 · 2026-09-21 · Feature update

You can see at a glance what you have changed on the Access map but not yet committed.

### New features

- **Uncommitted links are marked** - Both ends of a link you have added but not committed are marked in amber with the word staged. The mark disappears once you commit on Review & Save.

### Fixes

None in this version.

## 2.4.396 · 2026-09-21 · Feature update

Linking people, groups and permissions on the Access map is quicker.

### New features

- **Link with Ctrl+click** - Select a person or group, then hold Ctrl and click each target to add a link. A plain click still only selects, so nothing is linked by accident.
- **Link by drag and drop** - Drag a box onto another box on the Access map. Only boxes that can accept it light up.
- **Link buttons in the toolbar** - Give access, Add people, Add permissions and Give to a group now sit in the toolbar, named for what you selected. Every link is still committed on Review & Save.

### Fixes

None in this version.

## 2.4.395 · 2026-09-21 · Feature update

Picking what to link on the Access map is faster and nothing is written until you commit.

### New features

- **Pick links from a searchable list** - When you start a link on the Access map, the candidates appear in a list you can filter by name or tag. Click entries to add them, then press Done.
- **See what is already linked** - Items the selection already has are shown as already linked rather than hidden, so a missing group really is missing.
- **Links wait for Review & Save** - Each pick becomes a pending change shown as a dashed line. You commit it on Review & Save, and it is backed up first and applied in your tenant straight away.

### Fixes

None in this version.

## 2.4.394 · 2026-09-21 · Feature update

You can now give people and groups access straight from the Access map.

### New features

- **Grant access from the Access map** - Select a person, a group or a permission group and add people, groups or permissions to it. Nothing reaches your tenant until you commit on Review & Save.
- **The map only adds** - Nothing can be removed from the Access map, so it stays safe to show a reviewer. Linking needs the Admin role; removing access stays on Maintenance & Revoke.

### Fixes

- **Direct role assignments are kept** - Saving the table of directly assigned roles can no longer drop rows.

## 2.4.393 · 2026-09-21 · Feature update

Settings take effect at once and can be copied between environments.

### New features

- **Copy settings to another environment** - Settings > Copy settings exports the sections you pick to a file. On the other environment you see each setting as current and new, and only ticked ones are written.
- **Sort, filter and resize the grid** - Click a column header to sort, type in the filter box to narrow the rows, and drag a column edge to change its width.

### Fixes

- **Saved settings apply straight away** - Switching a feature off in Settings used to need a restart of PIM Manager. It now applies the moment you save.
- **Smaller improvements** - Admins are named one consistent way in Who gets which group, the wizards say PIM policy instead of Group policy, and record types show how many changes are pending.

## 2.4.392 · 2026-09-21 · Fix-only

Job status is always current, commits no longer fail after a template import, and fewer policy changes wait for approval.

### New features

None in this version.

### Fixes

- **Jobs clear themselves when they recover** - A job shows as failing only while its latest run failed. There is nothing to acknowledge, and Jobs, Overview and the menu count always agree.
- **Commit all works after a template import** - Commits could fail after importing a template pack. Commit now runs once, and the import skips groups that already exist and tells you which.
- **Fewer policy approvals** - A policy nobody has ever changed, such as one on a group you just created, gets its template without needing approval. Policies someone set are still held.
- **Temporary Access Pass lasts 8 hours** - When no lifetime is set, a Temporary Access Pass lasts 8 hours, not 48 as the previous release said, and never longer than your tenant allows.
- **Smaller fixes** - Defender XDR roles no longer show as changed on every run, error messages are clearer, template packs can be imported from Settings, and some labels were corrected.

## 2.4.391 · 2026-09-21 · Feature update

Temporary Access Passes last longer, central admins can be managed on managed tenants, and failures are easier to spot.

**Action needed:** To allow the full 48 hours, raise the maximum in Entra ID > Authentication methods > Temporary Access Pass.

### New features

- **Longer Temporary Access Pass** - When no lifetime is set, a Temporary Access Pass now lasts up to 48 hours, never longer than your tenant allows. A new one is issued until the admin registers their own sign-in method.
- **Central admins on managed tenants** - Reset Temporary Access Pass, Revoke sessions and Access now work for a central admin replicated to a managed tenant.
- **Create an admin from Create access** - The Create access page has a card that opens the same wizard as + New admin.

### Fixes

- **Failures are easy to see** - Engine logs & errors shows a red count of failed runs and lists them first. Jobs lists failing jobs first.
- **Smaller fixes** - Admin mail on managed tenants reaches the alert recipients, department owners show at once on Admin accounts, and rejected policy changes show more detail.

## 2.4.390 · 2026-09-21 · Feature update

You approve held policy changes once, in one place, and the approval holds.

### New features

- **Approve all held policy changes** - The Approvals page lists every held policy change for groups, Entra roles and Azure roles, with one Approve all button. The policy jobs start straight after.

### Fixes

- **An approval sticks** - An approval used to expire as soon as anything new appeared. It now covers later runs unless they weaken something you have not approved.
- **Clearer approval screens** - Approved changes show as applying on the next run, and each weakening policy is listed with its change in plain words.
- **Admin names checked without case** - Admin names now match your naming convention regardless of upper or lower case, and the warning shows the expected name.

## 2.4.389 · 2026-09-21 · Feature update

Held policy changes send one mail instead of many, and you approve them where you read them.

### New features

- **Approve from the Approvals page** - The mail now points to Reviews & controls > Approvals, which always shows the current held change with Approve this change set at the top.

### Fixes

- **One mail per held change** - A held policy change used to send a mail on every run. It now mails once, again only if it gets weaker or once a day while it stands.
- **Shorter Policy templates page** - The Policy templates page has a one-line introduction, folded help and one card per default template.

## 2.4.388 · 2026-09-21 · Feature update

Rings now work the same way everywhere, from dev to test to broad.

### New features

- **One ring order everywhere** - Replication rings now run like update rings: 0 is dev, 1 is test, 2 is broad. Existing rings are converted once, so everyone keeps reaching exactly what they reached.
- **Tags live on the deployment ring** - The Managed tenant registry page has a Deployment rings card where you name each ring and narrow it with a tag rule. Existing admin tags are kept and shown.

### Fixes

- **Older managed tenants keep working** - A managed tenant on an older version converts the old ring numbers itself.

## 2.4.387 · 2026-09-21 · Feature update

Policy templates are easy to read and change, and imports can never remove a SuperAdmin.

### New features

- **See every policy template setting** - Opening a policy template lists every setting with its value. Settings that cannot be changed here are shown with the reason.
- **Edit policy templates with dropdowns** - A SuperAdmin can press Edit to change durations, what activation asks for and who is notified. A change to many policies waits for your approval.
- **See where a template is used** - Used by lists every delegation that uses the template, including those that get it as the default, with the total first.

### Fixes

- **Imports protect SuperAdmins and break-glass** - An import can never overwrite or remove SuperAdmins or Break-glass accounts. Every admin now needs a sign-in name, filled from the tenant's domain when missing.

## 2.4.386 · 2026-09-21 · Feature update

Held policy changes are where you expect them, and more group names follow your naming pattern.

### New features

- **Held changes on the Approvals page** - A held policy change is now listed at the top of Reviews & controls > Approvals, with each setting change and the Approve button.

### Fixes

- **Clones follow your naming** - A cloned group is named by your current group pattern, and Re-add definition suggests the name your pattern gives.
- **Administrative unit groups use their pattern** - Once you change the administrative unit group pattern, permission groups granted inside an administrative unit are named by it. With the default, nothing changes.

## 2.4.385 · 2026-09-21 · Feature update

Group and admin names follow your full naming convention, and held policy changes show their impact before you approve.

**Action needed:** If you saved Settings > Naming conventions on 2.4.382 to 2.4.384, check that your admin word and tenant common name are still set.

### New features

- **See a held change's impact** - The approval panel compares each policy's current and new settings, marks each as tightening, loosening or neutral, and groups policies that get the same change.
- **More naming values are settings** - Prefixes, administrative units and service names that were built in are now in Settings > Naming > Group naming values, with new variables you can use.
- **Easier naming page** - The naming page has wider fields, dropdowns and explanations. The admin wizard offers your own admin types and environments.

### Fixes

- **Names use your whole pattern** - Group names used to keep only the role part of your pattern. Every variable is now filled, and empty ones disappear cleanly. Existing groups keep their names.
- **Clearer mails and job results** - Held-change mails explain what happened in plain words, one mail per change. Job results and naming saves are also more reliable.

## 2.4.384 · 2026-09-21 · Feature update

Policy template durations can be changed, and the records screens use plain names and clear buttons.

### New features

- **Change policy template durations** - Each policy template now has editable maximum durations for activation, eligible and active assignments. Your next update asks you to confirm before rolling the change.

### Fixes

- **Records have plain names** - Record types are now named for what they hold, such as Who gets which group or Administrator accounts.
- **An Edit button on every row** - Edit is now the main row action and takes you straight to the first field.
- **Delete is now Stop managing** - Removing a row never removed access, so the button now says Stop managing and points you to the way to actually remove access.
- **Smaller improvements** - The record search explains what it searches, the template rollout page uses plain words, and one menu entry is renamed to match its page.

## 2.4.383 · 2026-09-20 · Fix-only

Automatic updates can no longer change your activation policies without an operator agreeing first.

### New features

None in this version.

### Fixes

- **Automatic updates protect your policies** - An overnight update that would change the activation policy baseline now stops and reports what would change. Normal updates are unaffected.
- **Admin account domain list works** - On tenants with many verified domains, the picker showed one long option. It now lists each domain separately.
- **Records tables show all rows** - Long tables were cut off at the window height with no way to scroll. All rows are visible again.
- **Admin accounts uses the full screen** - The Admin accounts table now fills wide displays instead of sitting in a narrow column.

## 2.4.382 · 2026-09-20 · Feature update

PIM Manager never removes an assignment you did not ask to remove, and naming and licences are fully in your hands.

**Action needed:** If a row asks for a type that is not live, the first run creates it; mark the one you do not want for removal and commit.

### New features

- **Register your licence in Settings** - Settings > Licence has Register a licence: pick the file or paste its contents. A file that does not verify is refused and nothing is stored.
- **Name admin accounts your way** - Settings > Naming has an admin word and a tenant short name, so one pattern serves every tenant. PIM Manager now always recognises its own admin accounts.
- **Pick the admin account domain** - Settings > Admin account domain now lists your verified domains, shows how many were found and offers Re-read when the list is empty.
- **Copy button in the run log** - The run log has a Copy button that copies the whole log, and Live tail explains itself.

### Fixes

- **Eligible and Active can coexist** - Before, asking for one assignment type replaced the other. PIM Manager now creates what a row asks for and leaves the rest alone.
- **No changes from an incomplete read** - When reading your tenant fails part-way, that area is now left untouched for the run instead of being planned from partial data.
- **Committed removals are never dropped** - A removal whose target could not be seen is now kept and retried, instead of being treated as done.
- **Naming is never guessed** - If your naming settings are missing, PIM Manager stops and names the missing setting instead of falling back to defaults that would rename accounts.
- **Smaller fixes** - The removal-blocked mail is rewritten in plain words, licence and edition checks are corrected, and options that cannot work on a single tenant are locked off.

## 2.4.381 · 2026-09-19 · Fix-only

Defender XDR role assignments are created again, and template imports no longer offer duplicate groups.

### New features

None in this version.

### Fixes

- **Defender XDR role assignments work** - Microsoft refused every new Defender XDR role assignment. They are now created, and the next run assigns every group that was waiting for its role.
- **Templates reuse existing groups** - Importing a permission template from Templates now reuses groups you already have instead of offering duplicates, and the card says how many it reuses.

## 2.4.380 · 2026-09-19 · Feature update

Groups are always created, permission templates can be imported by script, and the Pro edition is introduced.

**Action needed:** Run the workload prerequisite script once for Intune, Defender XDR and Power BI, or their new role assignments wait.

**Action needed:** If you use managed tenants or any Pro feature, install your Pro licence before upgrading.

### New features

- **Groups are always created** - A permission group is created even when its workload is not ready. Only a new workload role assignment waits until that workload's prerequisites are green, and the GUI shows where.
- **Import permission templates by script** - You can import template packs into one or many environments by script. It adds only what is missing, reuses existing groups and takes a snapshot first.
- **The Pro edition** - Single-tenant essentials stay free. Coverage & gaps, extra connectors, Access reviews, managing and managed tenants and more need a Pro licence; Settings > Licence shows your status.
- **Microsoft Sentinel option** - The workload prerequisite script can now enable Microsoft Sentinel on a dedicated, empty security workspace, if you choose.

### Fixes

- **Defender XDR role assignments fixed** - Defender XDR role assignments now include what Microsoft requires, and new custom roles are found correctly after creation.

## 2.4.379 · 2026-09-19 · Feature update

Policy templates are consistent for every kind, can be renamed, and can be chosen wherever you delegate.

**Action needed:** Do not roll this environment back to an older version after upgrading; always upgrade forward.

### New features

- **Standard and approval templates per kind** - PIM for Groups, Entra ID roles and Azure roles each have a Standard and a RequireApproval template. Azure roles keep exactly the same rules as before.
- **Rename policy templates safely** - A SuperAdmin can rename any template on the Policy templates page. Rows keep working, because they refer to the template, not its name.
- **A default template per kind** - The Policy templates page sets one default for groups, Entra ID roles and Azure roles. A row without a template uses its kind's default.
- **Template picker in every wizard** - Every delegation wizard and grid now lets you pick a policy template, showing only templates of the right kind.
- **Smaller improvements** - Template packs can only be imported once their workload prerequisites are green, the prerequisite script can enable Microsoft Sentinel, and several workload checks read correctly.

### Fixes

None in this version.

## 2.4.378 · 2026-09-19 · Feature update

One page now shows what is delegated and what is not across every workload, and Defender XDR roles are managed end to end.

### New features

- **Coverage & gaps page** - Reviews & controls > Coverage & gaps shows what is covered and what is a gap across Entra ID, Intune, Defender XDR, Power BI and Azure, with ready proposals to stage.
- **Defender XDR roles managed for you** - PIM Manager creates Defender XDR custom roles named like their group, corrects their permissions and assigns them with the right data sources.
- **Workload readiness at a glance** - Template cards, wizards and Coverage & gaps show a green, amber or red chip for each workload's prerequisites, with the step to take.
- **Managed tenant registry and overview** - On the managing tenant you register and edit managed tenants on a page, and a replication overview shows exactly what each tenant receives.
- **Smaller improvements** - Policy templates page, all three policy types in every wizard, a new Intune template, Defender and Intune discovery, and warnings for groups missing their workload role.

### Fixes

- **Azure permission groups are created** - Groups made by the Azure wizards were never created in the tenant. The group and its assignment are now added together.
- **Not checked is never in sync** - Drift now shows an area that was skipped or could not be read as not checked, with the reason, instead of counting it as in sync.
- **Your naming convention everywhere** - Discovered resources, template imports and retired groups now follow your own group naming pattern.
- **Defender XDR discovery works** - Defender XDR roles are read correctly, and a failed read shows as a failed job instead of no roles.
- **Replication preview matches for admins** - An admin without a management mode stays on the managing tenant and is shown that way in the preview.

## 2.4.377 · 2026-09-19 · Feature update

Admin accounts use each tenant's own domain, and the engine now follows your naming conventions.

### New features

- **Admin account domain per tenant** - Settings > Admin account domain lists this tenant's verified domains. Admins replicated to a managed tenant use that tenant's own domain.
- **Wizards show replication on managed tenants** - On a managed tenant, each create wizard notes that the row is local to this tenant and not replicated.

### Fixes

- **The engine follows your naming** - Naming set in Settings was shown in PIM Manager but not used by the engine. The engine now uses the same settings.
- **Imported v1 admins are recognised** - Memberships of imported v1 admins were refused as not defined and blocked Commit. They are now matched correctly.
- **Revoke works for any Entra role assignment** - Revoking an Entra role assigned outside PIM used to fail. Revoke now checks how the role is held and removes it the right way, or explains why not.

## 2.4.376 · 2026-09-19 · Feature update

Replicated groups reach your managed tenants again, and PIM Manager is easier to navigate.

### New features

- **Every menu item opens its own page** - Manager access & roles, Emergency access (Break-glass) and Mail templates are now separate pages. Review standing access is renamed Review current delegations.
- **See what a template adds** - Each permission template card has a Show button listing every new permission with a tick box. Import stages only the ticked ones.
- **Activation policy in Start here** - The Delegate a permission - Start here wizard now asks which activation policy the delegation uses.
- **v1 imports are checked first** - Importing v1 files is validated before anything is written, and the import never deletes and refuses conflicting rows unless you choose otherwise.

### Fixes

- **Replicated groups reach managed tenants** - Groups set to Replicate to managed tenants could reach no tenant. They now reach every tenant their ring and tags allow.
- **Smaller fixes** - Replication options and rings use plain words, menu badges count only work that needs you, and role-assignable is set correctly for Entra role groups.

## 2.4.375 · 2026-09-19 · Feature update

Break-glass changes need two people, the emergency override works, and PIM Manager is tidier.

**Action needed:** Make sure each environment has at least two SuperAdmins to change Break-glass accounts in PIM Manager.

**Action needed:** To use the emergency override, set a passphrase once per environment with the provided operator script.

### New features

- **Break-glass changes need two SuperAdmins** - Changing Break-glass accounts now raises a request with your justification. A different SuperAdmin approves or rejects it within 72 hours.
- **Emergency override works** - The emergency override card explains what happens and shows whether a passphrase is set. It switches off approval on chosen groups; nothing is granted.
- **Departments & owners has its own page** - Departments & owners is now a page under Access instead of being buried in Settings.

### Fixes

- **Smaller improvements** - All records has a compact list with a filter and full-width table, and two unused settings were removed.

## 2.4.374 · 2026-09-19 · Fix-only

A new admin who has not yet set up sign-in no longer blocks every change.

### New features

None in this version.

### Fixes

- **Missing sign-in methods no longer block commits** - An admin without a strong sign-in method used to block every commit. This is now a warning on Validate, so you can keep working.

## 2.4.373 · 2026-09-19 · Security

Disabling an admin always needs a second person, and Azure access is granted through PIM only.

**Action needed:** If you moved log or sync folders away from the defaults, make sure PIM Manager can still write there.

### New features

None in this version.

### Fixes

- **Disabling an admin needs two people** - A grid change that would disable an admin is now held for an offboard approval. The rest of your commit is saved as normal.
- **Azure access is always PIM-eligible** - The Azure workload connector now creates PIM-eligible assignments instead of permanent ones.
- **Security hardening** - Stronger protection for the product itself, and a managing tenant can now publish a signed stop instruction to its managed tenants.
- **Smaller improvements** - New environments use scheduled jobs by default, and outdated hosting guidance was removed.

## 2.4.372 · 2026-09-18 · Feature update

You decide how often managed tenants update, and reminder mail is safe to leave on.

**Action needed:** After upgrading, set the interval you want on the Job schedule page; the default is daily.

### New features

- **Set how often managed tenants update** - The Job schedule page lets you switch the managed-tenant pull or the publish on or off, set an interval from 5 minutes to a day, and run it now.
- **Changes publish on commit** - Committing a replicated change on the managing tenant starts a publish, so managed tenants can pick it up within minutes.

### Fixes

- **Escalation mail is safe to leave on** - Escalation mails follow your alert settings, never arrive as a backlog after upgrade, and send at most one reminder per stage to the sponsor department's owners.
- **One role per workload delegation** - A delegation with several workload roles kept only the last one silently. It is now refused with a clear message.
- **Smaller fixes** - Any whole number is a valid replication ring, ring labels are clearer, and jobs that do not apply show as skipped.

## 2.4.371 · 2026-09-18 · Fix-only

No more false removal alarms, and managed tenants receive updates again.

### New features

None in this version.

### Fixes

- **No false removal alerts** - The nightly read-only check sent removal alerts about runs that could not remove anything. It now only logs the finding; nothing was ever removed.
- **Managed-tenant pull works again** - Managed tenants refused every pull after the previous release. The pull works again, and a stop instruction you configure is still checked strictly.
- **Approved updates are found again** - The update tools reported nothing approved even when a version was. They now read the ring correctly.

## 2.4.370 · 2026-09-18 · Security

A full review of the product makes every safety feature dependable and keeps your access and data safe from accidental loss.

**Action needed:** When you create a new Manager, configure its sign-in and choose who may use it: named people or groups, or all member users.

### New features

None in this version.

### Fixes

- **Stronger protection for the Manager** - Security hardening across the Manager, its sign-in, MSP baselines and PIM Activator.
- **Two admins can no longer overwrite each other** - A commit made on data that changed since you loaded it is refused. You are offered a reload that keeps your staged edits.
- **Break-glass works as promised** - While an emergency override is active, approval is switched off on the scoped groups and restored afterwards. Manage Break-glass accounts in Settings; PIM Manager never disables them.
- **Safety alerts are really sent** - Removal budget, account-disable and policy mass-change alerts are now sent, and a failed send is recorded. A disable date in the past now asks for approval first.
- **Smaller fixes** - Saving departments keeps all their settings, quick-fixes act on the right row, access-review screens show real data, and updates never move an environment backward.

## 2.4.369 · 2026-09-18 · Feature update

Screens now tell you clearly what they did, so a successful action never looks like a lost one.

### New features

- **See your update ring in the Manager** - The header shows which update ring the environment is on. Jobs has an Updates & ring panel with the running version, the approved version and the last update run.

### Fixes

- **Revoke selected reports what it staged** - Review standing access now shows how many rows were staged and which were refused, with the reason. Nothing is revoked until you commit.
- **Your commit shows up in the queue** - The change queue now opens with recent commits included. A committed change shows as saved, and the engine applies it on its next run.

## 2.4.368 · 2026-09-18 · Fix-only

Automatic updates never move an environment to an older version, and the ring you choose is the ring you get.

**Action needed:** If an environment has been running on a ring you did not intend, re-run the deployment naming the ring you want.

### New features

None in this version.

### Fixes

- **Updates never go backward** - The nightly update refuses to move an environment to an older version and names both versions. A deliberate rollback must be switched on for that environment.
- **Your chosen ring is applied and verified** - The update ring you choose at installation is now used and checked after deployment, instead of a default ring.
- **Clearer setup and edition documentation** - The README describes the six supported setups, explains the release ring versus the replication ring, and sets out the Community and Pro editions.

## 2.4.367 · 2026-09-17 · Feature update

Service providers publish a signed baseline from their own cloud, with no management server and no expiring links to renew.

**Action needed:** Update every managed tenant and pin the provider's key before the provider's first cloud publish, and redeploy the baseline jobs with this version.

**Action needed:** Before building a brand-new pair, do the two preparation steps listed in the build guide.

### New features

- **Baseline published from the provider's cloud** - A scheduled job in the managing tenant's Azure builds and signs the baseline with a key that never leaves its key vault. No management server is needed.
- **Deploy as a signed-in administrator** - The one-command build can now run on your own sign-in instead of a certificate-based deployment identity.
- **Private-only deployments supported** - The managing tenant and each managed tenant can run with no public entry point, reading the baseline through a private connection.

### Fixes

- **Managed tenants trust only the pinned key** - Each managed tenant accepts a baseline only from the provider key it is set up with. Several keys can be pinned, so keys change without a gap.
- **No expiring read link any more** - Managed tenants read the signed baseline over the network, so nothing in the access path expires or needs renewing.
- **Smaller fixes** - The one-command build completes on a new pair, the Manager says why a baseline is not verified, and a check without directory rights reports not checked.

## 2.4.366 · 2026-09-16 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.365 · 2026-09-16 · Feature update

You can require approval for permission delegations, and existing delegations are easy to find and edit.

### New features

- **Activation policy for permission delegations** - When you create an Entra ID or Azure permission group in the wizard, you can pick its activation policy, including one that needs approval. Use default changes nothing.
- **Edit delegations in a table** - Access now has Delegations - edit in a table, where you change an existing delegation's duration or policy and then commit.

### Fixes

None in this version.

## 2.4.364 · 2026-09-16 · Feature update

PIM Manager never deletes an account, and never disables one just because it is missing from your definitions.

**Action needed:** If you use a managing tenant, update it and every managed tenant to this version or newer.

### New features

- **Disable date on Admin accounts** - You can see and edit each admin's disable date on the Admin accounts screen, with a flag when it has passed or falls within 14 days.
- **Sponsor department on Admin accounts** - Admin accounts shows each admin's sponsor department, with its owners on hover, and flags a missing department or missing owners.

### Fixes

- **PIM Manager never deletes a user account** - Offboarding disables the account, revokes its sessions and access, and sends the notice. The account stays until a person deletes it; Flag for deletion is now Mark for manual removal.
- **Missing accounts are reported, never disabled** - An admin account absent from your definitions is listed on each run but never disabled. Disabling it is your decision.
- **Admin mail goes to department owners** - Mail about an admin, including the Temporary Access Pass, goes to the owners of their sponsor department. If none is found, PIM Manager says what to set instead of mailing nobody.

## 2.4.363 · 2026-09-15 · Feature update

One command builds a managing or managed tenant, and every Entra admin gets a Temporary Access Pass.

**Action needed:** Build the managing tenant first, then each managed tenant.

### New features

- **One command builds an MSP pair** - A single command builds a managing tenant or a managed tenant step by step. It shows the plan first and ends by listing the steps that need a person.

### Fixes

- **Every Entra admin gets a Temporary Access Pass** - The create TAP setting can no longer turn the pass off in any setup. Validation flags a "no" and offers a one-click fix.
- **The Manager gets only read permissions** - A deployment now gives the Manager only its read-only set of permissions.
- **Smaller fixes** - The full deployment now uses your database admin group name and troubleshooting identity, and can create and fill that group itself.

## 2.4.362 · 2026-09-15 · Fix-only

Held policy changes show as needing approval, and managed tenants run without secrets and report removals before making them.

**Action needed:** Re-deploy the pull job for each managed tenant without an engine secret to move it onto its own identity.

### New features

None in this version.

### Fixes

- **Held policy changes show as needing approval** - A run stopped by the policy mass-change safety check now shows amber as needs approval on Jobs and Home, never as failed, and raises an alert.
- **Admin settings reach managed tenants unchanged** - Settings such as create TAP and provisioning dates now travel with each admin to managed tenants exactly as the managing tenant set them.
- **Managed tenant pull runs without a secret** - A managed tenant's scheduled pull now runs as its own managed identity, with the permissions it needs.
- **Removals are reported before they happen** - Admins that stop reaching a managed tenant are reported as would remove, and removed only when you allow it, within the removal limit.
- **Smaller fixes** - The weekly read-link renewal signs in with certificates only, joining the database admin group waits for the directory, and re-deploying the pull job works again.

## 2.4.361 · 2026-09-15 · Feature update

Nightly updates keep running and bring every database change with them, and the database can be administered by a group.

### New features

- **Database administered by a security group** - A setup step makes a security group the database's Entra ID administrator, with the environment's own identities as members. New deployments set this up automatically.

### Fixes

- **The nightly updater repairs its own settings** - When the updater is missing its database details, it takes them from the Manager and keeps them, instead of refusing every release.
- **Clear message when the updater cannot sign in** - The message names the updater's identity and the group to add it to. It still never rolls a release it could not check.
- **Database additions reach existing installations** - Each update now applies the shipped database changes, so new settings are present on existing installations. An update that would remove data is refused.

## 2.4.360 · 2026-09-15 · Feature update

On the managing tenant you choose, per admin and per group, exactly which managed tenants receive it.

**Action needed:** If a managed tenant's sync relied on stale rows being removed automatically, run it with removal explicitly allowed.

### New features

- **Choose which managed tenants receive each item** - On the managing tenant, every admin, membership, group and binding can say whether it replicates, and to which tenants by ring, tag or name.
- **See how many tenants it reaches** - The Create wizards and the grid show "This will reach: N of M tenants" before you commit, with the names on hover.

### Fixes

- **MSP settings show only where they matter** - A single tenant no longer shows sync settings, and a managed tenant shows read-only which admins it received.
- **Groups arrive with their memberships** - Department, project and cross-org groups are now sent along with the memberships that need them, and items kept local stay local.
- **Removals are reported first** - A row that stops reaching a managed tenant is reported as would remove and removed only when you allow it.
- **Smaller fixes** - The managing tenant's view of which tenants an admin reaches is accurate, and admin assignments have a Target column in the grid.

## 2.4.359 · 2026-09-15 · Feature update

The Community edition now installs from GitHub into your own tenant in one step.

### New features

- **Install the Community edition from GitHub** - Clone the repository and run the one-step deploy to set up the Manager, engine and database in your own Azure subscription, with Microsoft Entra sign-in. See Getting started.

### Fixes

- **Community install completes without the updater** - Without a release feed the deploy skips the updater and tells you how to update: pull the latest version and run the same command again.
- **A missing smoke test no longer rolls back** - A deploy without its automated smoke test is now recorded as unverified instead of being rolled back.
- **Smaller fixes** - Sign-in consent is granted reliably, creating the deploy identity works on a busy directory, and the documentation and screenshots are refreshed.

## 2.4.358 · 2026-09-14 · Fix-only

Engine jobs run again in hosted environments.

**Action needed:** If a hosted environment runs version 2.4.357, update it to this version.

### New features

None in this version.

### Fixes

- **Engine jobs run again** - On the previous version, engine jobs in hosted environments stopped before applying anything. They run normally again, and their output is still kept for Logs.

## 2.4.357 · 2026-09-14 · Feature update

Job logs show what each run actually did, and jobs that recovered stop showing as failing.

### New features

- **Logs show the full run output** - The Logs button on Jobs shows everything a run checked and changed, with warnings and errors. Live tail shows progress while an engine job runs.

### Fixes

- **Run now works for every scheduled check** - Run now on the convergence check and discovery jobs queues them for the scheduler instead of reporting not implemented.
- **Recovered jobs no longer show as failing** - Earlier failures of a job that has since recovered show under History. Ack clears all standing failures of a job in one click.

## 2.4.356 · 2026-09-14 · Fix-only

Drift items now name the person and group they concern, so you can act on them at a glance.

### New features

None in this version.

### Fixes

- **Drift items show names** - Drift now names the person and group instead of showing ids. Names appear after the next drift check.
- **Smaller fixes** - No more double listings in Drift, and stray text above the Access wizards is gone.

## 2.4.355 · 2026-09-14 · Feature update

Drift has its own fast page, menus are tidier, and queued actions apply without waiting for a long run.

### New features

- **Drift: live vs desired has its own page** - Find it under Reviews & controls. It opens instantly, shows counts per area with the differences per row, and Check now queues a fresh check.

### Fixes

- **Menus make more sense** - Daily operations joins Reviews & controls, and Manager access, the emergency override, template packs and mail templates are now sections in Settings.
- **Queued actions apply during long runs** - A committed Temporary Access Pass re-issue or session revoke is applied between engine steps instead of after the whole run.
- **The badge counts only what needs you** - Pending changes lists pending entries first. The red badge counts pending or failed entries, and committed ones waiting for the engine show in blue.
- **Smaller fixes** - Review standing access hides deleted principals by default, the Access map groups related groups together, and a group created in a run is used in that run.

## 2.4.354 · 2026-09-14 · Fix-only

The faster membership check now sees every existing membership.

### New features

None in this version.

### Fixes

- **Faster checks miss no membership** - Some older group nestings were re-checked one by one, though nothing was changed. PIM Manager now confirms them, and every removal, against the group itself.

## 2.4.353 · 2026-09-14 · Fix-only

Committed changes now reach your tenant in minutes instead of waiting for a full engine pass.

### New features

None in this version.

### Fixes

- **Only what changed runs** - A committed change starts only the engine steps for the kind of data you changed, not every step for the whole tenant.
- **The engine starts right away** - Commit and Run start the engine immediately, and a run in progress picks up new commits as soon as its current step finishes.
- **Smaller improvements** - Faster admin and nesting checks, and every admin now shows a type on Admin accounts.

## 2.4.352 · 2026-09-13 · Fix-only

Reviewing standing access opens instantly and no longer slows the Manager for everyone else.

### New features

None in this version.

### Fixes

- **Standing access opens instantly** - Review standing access, Revoke and the expiring-access tile now use a snapshot taken every 2 hours, and show its time. Before, each opening took minutes.
- **Refresh and revoke update the snapshot** - Refresh queues a new read, and a revoke queues one automatically. A revoked row shows revoke queued until it is gone.

## 2.4.351 · 2026-09-13 · Fix-only

Several Manager screens work smoothly again, from committing to creating a new admin.

### New features

None in this version.

### Fixes

- **Commit all includes queued actions** - Commit all now also commits queued actions such as a Temporary Access Pass re-issue or a revoke.
- **New admin and Give access work again** - Both buttons work again, and Role lookup finds roles such as Exchange Administrator on the hosted Manager.
- **Wizards help avoid duplicates** - The Entra role picker hides roles that already have a delegation group, and Workload suggests workloads already in use.
- **Smaller fixes** - Dialogs open on top, the change queue can show recent commits, and informational notes no longer raise the yellow banner.

## 2.4.350 · 2026-09-13 · Fix-only

Policy errors now name the role and scope they concern.

### New features

None in this version.

### Fixes

- **Policy errors name the role and scope** - A failing Azure resource or PIM for Groups policy in Engine logs & errors now names its role, scope and template instead of showing empty fields.

## 2.4.349 · 2026-09-13 · Security

Every policy change and revoke is fully audited, and initial passwords are never shown or saved.

### New features

None in this version.

### Fixes

- **Policy changes audited rule by rule** - The audit trail records each policy rule's value before and after, its template, and whether an approved mass-change plan applied it.
- **Revokes and passes audited as they happen** - Revokes, Temporary Access Pass resets and session revokes record who asked, what was done to whom, how it was verified and the outcome.
- **Initial passwords never shown or saved** - Creating an admin from the setup tools never shows or keeps a password. Onboard the admin with a Temporary Access Pass.
- **Smaller fixes** - A refused commit stays on Pending changes with its blocking errors and fixes, and template rows with a placeholder subscription are not offered for import.

## 2.4.348 · 2026-09-13 · Fix-only

Delegations now reach your tenant as you chose them, and errors name the real groups and roles.

**Action needed:** Use the one-click Set to Eligible fix that validation offers for any existing Active nesting of that kind.

### New features

None in this version.

### Fixes

- **Eligible delegations are written Eligible** - Wizards wrote group nestings as Active, which Entra ID refuses for role-assignable groups, so those delegations never arrived. They are now Eligible.
- **New delegations get their policy at once** - A new group's PIM for Groups policy is applied straight away. Changes to policies someone already set are still guarded.
- **Errors name the group, role and scope** - Engine errors say which group, role and scope they concern, with a link to that scope's PIM policies in the Azure portal.
- **Engine changes in the audit trail** - Every membership, role assignment and account change the engine makes is recorded with the real person, group, role and scope.
- **Smaller fixes** - Run now queues engine jobs and says so, missing engine permissions turn the Home banner red, and Commit counts a fix you just staged.

## 2.4.347 · 2026-09-13 · Fix-only

Your staged changes are no longer lost when the page reloads or the Manager restarts.

**Action needed:** Before updating an environment that runs an older version, commit or note your pending changes.

### New features

None in this version.

### Fixes

- **Staged changes survive a reload** - Pending changes are kept in your browser and put back after a reload, on top of any colleague's commit. The page asks before you leave with uncommitted changes.
- **Discarded entries hidden by default** - Tick Show discarded to see who discarded queue entries and why.

## 2.4.346 · 2026-09-13 · Fix-only

Engine runs finish faster, so your changes reach the tenant sooner.

### New features

None in this version.

### Fixes

- **Faster engine runs** - Scheduled runs spend far less time saving state, handle Microsoft throttling in one go, and reuse lookups. Revokes and the drift check always use fresh data.

## 2.4.345 · 2026-09-13 · Fix-only

Large PIM for Groups policy changes are always held for approval, and group policy updates are much faster.

### New features

None in this version.

### Fixes

- **Safety brake covers group policies** - Large or weakening PIM for Groups policy changes are now always held for approval, exactly like Entra role and Azure resource policies.
- **Faster group policy updates** - Group policy updates send only what changed, so large policy alignments run many times faster.
- **Governance opens quickly** - The drift check runs only when you click Check for drift (slow), so opening Governance no longer slows the Manager.

## 2.4.344 · 2026-09-13 · Fix-only

Home loads instantly and no longer slows the Manager for other users.

### New features

None in this version.

### Fixes

- **Home loads instantly** - The Expiring access and Pending access reviews tiles load only when you click Load live data (slow).

## 2.4.343 · 2026-09-13 · Fix-only

The Manager stays fast and stable when many people use it at once.

### New features

None in this version.

### Fixes

- **Stable under heavy use** - The Manager no longer runs out of database connections, and its database sign-in renews on time under frequent use.
- **Home no longer freezes the Manager** - The expiring-assignments tile reuses a recent result, so opening Home does not block other users.

## 2.4.342 · 2026-09-13 · Fix-only

Moving from v1 leaves every PIM policy exactly as it was.

### New features

None in this version.

### Fixes

- **PIM policies identical to v1** - The standard policy templates for Entra roles, Azure resource roles and PIM for Groups carry v1's exact values. The PIM for Groups member activation maximum is back to 8 hours.

## 2.4.341 · 2026-09-13 · Feature update

Updates move only to approved versions, group policies get the safety brake, and on-premises AD admins work as in v1.

### New features

- **On-premises AD admins work as in v1** - On-premises AD admins are created and kept up to date in Active Directory, named by your naming settings. Their initial password is mailed and never stored.
- **Choose which managed tenants get each admin** - On a managing tenant, each admin says whether it is synced to managed tenants, optionally narrowed to tagged tenants. The Manager shows the tenant's mode.
- **See what naming patterns produce** - Settings shows the result of each naming pattern as you edit it.

### Fixes

- **Updates follow the approved release** - Each environment moves only to the version its ring approves, and the nightly update refuses to roll when it cannot check the database first.
- **Every cloud admin gets a Temporary Access Pass** - A Temporary Access Pass is issued to every cloud admin. On-premises AD admins use a password.
- **Remove rows revoke the access** - Marking a delegation for removal revokes it, eligible and active, before removing the row. A held or failed removal keeps its row.
- **Safety brake for group and role policies** - Group and Entra role policy changes now have the same safety brake as Azure policies.
- **Smaller improvements** - Faster runs, clearer permission errors, mail sent as the environment's own identity, everything kept in the database, and templates gaining new settings without losing yours.

## 2.4.340 · 2026-09-13 · Fix-only

Long scheduled runs no longer overlap with the next one.

### New features

None in this version.

### Fixes

- **Scheduled runs no longer overlap** - A run that takes longer than its 15-minute turn now keeps its turn, and stops making changes if another run has taken over.

## 2.4.339 · 2026-09-13 · Fix-only

Assignments that exist as both eligible and active are kept unless you decide otherwise.

**Action needed:** To trim leftover types, turn on the Remove type leftovers setting after reviewing what it would remove.

### New features

None in this version.

### Fixes

- **Both assignment types are kept** - An assignment that is both eligible and active is no longer trimmed automatically, as in v1. Changing a row between eligible and active still replaces the old type.

## 2.4.338 · 2026-09-13 · Feature update

PIM Manager is ready to replace v1, managing Azure resource policies and the full admin lifecycle.

**Action needed:** Make sure the Manager can reach its database before updating, as it no longer starts without it.

### New features

- **Azure resource PIM policies are managed** - Durations, MFA, justification, notifications and approval come from your policy templates. Approval that is already on is never removed.
- **A safety brake on policy changes** - A run that would change many policies or weaken protection changes nothing and shows the plan for approval in Jobs, Engine logs & errors.
- **Full admin lifecycle** - Admin accounts are created when due and kept in step. Offboarding runs on its own schedule, and disabled admins stay disabled.
- **Workload roles applied** - Defender, Intune, enterprise application, Power BI, Power Platform, Business Central, Azure DevOps and Azure roles in your data are applied, with exemptions.

### Fixes

- **Your changes are carried out** - Removals, eligible and active switches, duration changes and auto-extend are applied. Bulk removals are held for review.
- **Manager needs its database to start** - Settings, access and templates now live only in the database, and templates upgrade automatically when unchanged.
- **Smaller improvements** - Temporary Access Passes respect a start date, reminders and reports have real content, Pending changes shows real names, and audit times are correct.

## 2.4.337 · 2026-09-12 · Fix-only

Entra role policies are enforced again, and saving an admin reports correctly.

### New features

None in this version.

### Fixes

- **Entra role policies enforced again** - The policy job failed on every run after the previous version. Entra role PIM policies are enforced again.
- **Saving an admin reports correctly** - A save that worked no longer shows as failed, on the admin screen and two other save screens.
- **Smaller fixes** - The Manager column shows the manager, the admin list no longer stalls, the department list loads, and group tags no longer warn as badly named.

## 2.4.336 · 2026-09-12 · Feature update

Failed jobs explain what went wrong and offer a reviewed one-click fix.

### New features

- **Engine logs & errors page** - Jobs now has its own Engine logs & errors page with recent runs, full logs and a Failing now list showing each item, why, and what to do.
- **One-click fixes, still reviewed** - Failing items offer Remove this row or Make it Eligible. The fix goes to Pending changes and applies only when you commit.
- **Project and Cross-org groups** - Direct groups have new Project and Cross-org types. Department and Process groups are created by the engine.

### Fixes

- **Entra role assignments work again** - Entra role assignments made by the scheduled engine are applied again.
- **Re-issued passes are delivered** - A Temporary Access Pass re-issued from the queue is mailed to the account owner's office email. If mail cannot be delivered, the existing pass is left untouched.
- **Smaller fixes** - Jobs run on their configured schedule, validation gives definite results, Admin accounts fields are clearer, and the admin word no longer loosens name checks.

## 2.4.335 · 2026-09-12 · Feature update

Queued changes are easy to see, and the admin screen opens without waiting.

### New features

- **Choose the admin word in account names** - You can set the word used for admin accounts, for example "adm" instead of "admin".
- **New direct groups ask their type** - Creating a direct group asks whether it is a role, organisation, department, process or resource group.

### Fixes

- **Queued changes show a counter** - Pending changes shows a counter that updates at once, and within a minute for changes queued by other admins. Three menu entries for the queue are now one.
- **Admin list appears at once** - Temporary Access Pass status is checked per admin with Check, and Edit sits on the admin's own row.
- **Passes go to the forwarding address** - A Temporary Access Pass is mailed to the admin's forwarding address, not their manager. Values that are not email addresses are refused.

## 2.4.324 · 2026-09-10 · Fix-only

Administrators can no longer be locked out, and updates bring the database with them.

### New features

None in this version.

### Fixes

- **Administrators are recognised again** - Valid administrators could be treated as read-only users. They, and delegated access profiles, are recognised correctly again.
- **Updates bring the database with them** - Each update brings the database up to date first and never removes data. If the database cannot be updated, the update stops.
- **Protection against data loss** - Replacing all records of one kind with nothing is refused, with a count of what would be removed. Deliberate clearing still works.
- **Every check offers a fix** - Each check has a working fix or says what to do, and five gained one-click repairs. Wizard fields now suggest values.
- **Smaller fixes** - Jobs that just ran are not shown as overdue, successful updates are not reported failed, and empty access reviews no longer send reminders.

## 2.4.323 · 2026-09-10 · Fix-only

An update that has to be undone can always be undone.

### New features

None in this version.

### Fixes

- **Rollback always works** - Each update keeps what it needs for a rollback, and a rollback is confirmed against what is actually running.
- **Healthy updates are not failed** - An update is no longer failed over a version-number mismatch when the environment runs exactly what was deployed.
- **Fix all fixes all of them** - "Fix all auto-fixable errors" now fixes every one, including assignments to an undefined administrative unit, and names anything it cannot repair.

## 2.4.308 · 2026-09-10 · Feature update

Each environment can now build and install its own approved updates, with no build machine or administrator needed.

### New features

- **Environments build their own updates** - An environment fetches its approved version, builds it in its own Azure and updates itself. It stays off until configured.

### Fixes

- **Failed builds are reported** - An environment that cannot fetch or build its approved version says so and stops, instead of reporting success.

## 2.4.307 · 2026-09-10 · Fix-only

Admins whose names differ only in capitals now show their access.

### New features

None in this version.

### Fixes

- **Access board ignores capitalisation** - The Access board now matches sign-in and group names regardless of capitals, so nobody wrongly looks as if they have no access.
- **Unmatched names are reported** - A name that matches nothing is now reported instead of silently dropped.

## 2.4.306 · 2026-09-10 · Fix-only

Importing your data is reliable and safe to repeat.

### New features

None in this version.

### Fixes

- **Imports complete reliably** - Imports no longer run out of database connections. A file that fails is undone whole, so running the import again is safe.
- **Failed files are named** - A failed file means a failed import, naming every file that failed and how many were imported.

## 2.4.305 · 2026-09-10 · Fix-only

The nightly update now updates every part of the environment and leaves your own work alone.

### New features

None in this version.

### Fixes

- **Every part of the environment is updated** - The nightly update finds every PIM Manager component that is deployed and updates them all. A component left behind fails the update.
- **Your own work is left alone** - Anything else in the same resource group is left untouched, and skipped items are reported with the reason.

## 2.4.304 · 2026-09-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.303 · 2026-09-10 · Fix-only

Automatic updates no longer undo each other overnight.

### New features

None in this version.

### Fixes

- **Updates no longer undo each other** - A new version is marked as approved only after a clean build, so the nightly update and the build no longer pull in opposite directions.
- **Smaller fixes** - A failed save of the approved version is reported at once, and the updater cannot be installed on a version too old to run it.

## 2.4.302 · 2026-09-10 · Fix-only

The nightly update runs again instead of stopping at once.

### New features

None in this version.

### Fixes

- **The nightly update runs again** - The updater stopped immediately because it could not find its own program files. It runs again, and names anything missing if that ever happens.

## 2.4.301 · 2026-09-10 · Fix-only

Installing the updater stops early with a clear message when a version is missing.

### New features

None in this version.

### Fixes

- **Installer checks the version exists** - Before creating anything, the update installer checks that both the version it installs and the one it would upgrade to exist, and stops clearly if not.

## 2.4.299 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.298 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.297 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.296 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.295 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.294 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.293 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.292 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.291 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.290 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.289 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.288 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.287 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.286 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.285 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.284 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.283 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.282 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.281 · 2026-09-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.280 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.279 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.278 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.277 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.276 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.275 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.274 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.273 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.272 · 2026-09-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.271 · 2026-09-01 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.270 · 2026-09-01 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.269 · 2026-09-01 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.268 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.267 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.266 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.265 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.264 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.263 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.262 · 2026-08-31 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.261 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.259 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.258 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.257 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.256 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.255 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.254 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.253 · 2026-08-30 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.252 · 2026-08-27 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.251 · 2026-08-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.250 · 2026-08-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.249 · 2026-08-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.248 · 2026-08-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.247 · 2026-08-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.246 · 2026-08-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.245 · 2026-08-07 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.244 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.243 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.242 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.241 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.240 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.239 · 2026-08-06 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.238 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.237 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.236 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.235 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.234 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.233 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.232 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.231 · 2026-06-22 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.230 · 2026-06-19 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.229 · 2026-06-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.228 · 2026-06-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.227 · 2026-06-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.226 · 2026-06-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.225 · 2026-06-18 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.224 · 2026-06-17 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.223 · 2026-06-17 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.222 · 2026-06-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.221 · 2026-06-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.220 · 2026-06-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.219 · 2026-06-15 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.218 · 2026-06-14 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.217 · 2026-06-14 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.216 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.215 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.214 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.213 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.212 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.211 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.210 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.209 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.208 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.207 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.206 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.205 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.204 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.203 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.202 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.201 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.200 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.199 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.198 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.197 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.196 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.195 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.194 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.193 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.192 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.191 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.190 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.189 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.188 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.187 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.186 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.185 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.184 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.183 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.182 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.181 · 2026-06-13 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.180 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.179 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.178 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.177 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.176 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.175 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.169 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.168 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.167 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.166 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.165 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.164 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.163 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.162 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.161 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.160 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.159 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.158 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.157 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.156 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.155 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.154 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.153 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.152 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.151 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.150 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.149 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.148 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.147 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.146 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.145 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.144 · 2026-06-12 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.143 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.142 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.141 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.140 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.139 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.138 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.137 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.136 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.135 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.134 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.133 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.132 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.131 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.130 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.129 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.128 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.127 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.126 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.125 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.124 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.123 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.122 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.121 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.120 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.119 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.118 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.117 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.116 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.115 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.114 · 2026-06-11 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.113 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.112 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.111 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.110 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.109 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.108 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.107 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.106 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.105 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.104 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.103 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.102 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.101 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.100 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.99 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.98 · 2026-06-10 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.97 · 2026-06-09 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.96 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.95 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.94 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.93 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.92 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.91 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.90 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.89 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.88 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.87 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.86 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.85 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.84 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.83 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.82 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.81 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.80 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.79 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.78 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.77 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.76 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.75 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.74 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.73 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.72 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.71 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.70 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.69 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.68 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.67 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.66 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.65 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.64 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.63 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.62 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.61 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.60 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.59 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.58 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.57 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.56 · 2026-06-08 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.55 · 2026-06-04 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.54 · 2026-06-04 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.53 · 2026-06-04 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.52 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.51 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.50 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.49 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.48 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.47 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.46 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.45 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.44 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.43 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.37 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.36 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.35 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.34 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.33 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.32 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.31 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.30 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.29 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.28 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.27 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.26 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.25 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.24 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.23 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.22 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.21 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.20 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.19 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.18 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.17 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.16 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.15 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.14 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.13 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.12 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.11 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.10 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.9 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.8 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.7 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.6 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.5 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.4 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.3 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.2 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.1 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.4.0 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.3.2 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.3.1 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.3.0 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.2.1 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.2.0 · 2026-06-03 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.7 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.6 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.5 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.4 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.3 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.2 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.1 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.1.0 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 2.0.0 · 2026-06-02 · Feature update

The first version of the PIM Manager toolkit, with a visual editor for your delegation model and the PIM Activator.

**Action needed:** Grant the engine identity the permission to manage user authentication methods, and re-save your admin definitions to use Temporary Access Passes.

### New features

- **See and edit your delegation model** - PIM Manager shows your delegation model as a graph or grid, and shows every difference before you commit.
- **PIM Activator for bulk activation** - An Edge extension lets you activate several PIM for Groups memberships at once.
- **One-step engine setup** - The engine's app registration is set up in one step.
- **Safer new accounts** - Each new account gets its own random password, with an optional Temporary Access Pass, and WhatIf mode is reliable.

### Fixes

None in this version.

## 1.0.2 · 2026-06-02 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 1.0.1 · 2026-06-01 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.

## 1.0.0 · 2026-06-01 · Fix-only

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Smaller fixes and improvements** - This version contains smaller fixes and improvements.
