# Release notes — PIM4EntraPS

PIM4EntraPS is privileged-access governance for Microsoft Entra ID and Azure. It keeps administrator
accounts, PIM delegations and PIM policies in line with the desired state you manage in the PIM Manager,
and lets administrators activate their access from the PIM Activator browser extension.

This file lists what changed in each release. **Versions are listed newest first.** Recent releases are
listed one by one; older history is summarised by version range. Where an upgrade needs something from
you, the entry says so in an **Upgrade note**.

Project home: https://github.com/KnudsenMorten/PIM4EntraPS

---

<!-- next release entry goes here -->

## v2.4.445 — Fewer, clearer alert emails

- **The same drift is no longer emailed every few hours.** An unchanged drift report is sent once, then at most once a day
  as a reminder while it lasts. A change in the drift is sent at once. The same applies to a job that keeps failing in the
  same way.
- **Drift reports name what they found.** An Azure assignment that PIM does not manage used to read "group  -> Azure role
  ''". It now names the account or group and the role.
- **Duplicate Defender XDR roles are cleaned up.** When Defender answers the creation of a custom role slowly, PIM could
  create it a second time, and then refused to use either. PIM now waits for a role it has just created, and removes an
  extra copy it made itself when only one copy is in use. Roles you created, and copies in use, are never removed.

## v2.4.444 — Setup and engine fixes found by the live tests

- **The notification mailbox step waits out a Microsoft delay.** Right after its permission is granted, Microsoft can
  refuse the role check once. The step now retries for a few minutes before reporting the environment as unable to
  send mail.
- **A brand-new account or group no longer fails the engine run.** When the engine assigns a role to a principal it
  created moments earlier, Microsoft can briefly answer "not found". This is now recognised as a short wait that the
  next run completes, not as an unexplained failure. The same applies to a new group's PIM policy, which Microsoft can
  refuse to update for a few minutes after the group is created.
- **The community updater finds your installation reliably.** Test runs no longer leave a saved deployment behind, so
  `Update-PimCommunity.ps1` never has to choose between your installation and a test.

## v2.4.443 — Azure delegation levels follow your management-group layers

- **The Create wizard sets the level of an Azure permission group from where its scope sits.** It uses the Cloud
  Adoption Framework layers: the tenant root management group is L3, and each layer below it is one more. A subscription
  is one below its management group and a resource group one below that, up to L9. The preview says where the level came
  from. When the scope is not in the known tree, the wizard uses the role as before and says so.
- **Changing who reviews an access review now works.** The change was sent in a form Microsoft does not accept for
  review definitions. It now sends the whole definition with the new reviewers, and checks the result.
- **An emergency override now ends on time** when its expiry falls while other work is running. Approval is put back
  on the next run, not the one after.

### Free and Pro

- **The free edition now shows what Pro adds.** Every Pro page is listed in the menu, dimmed and marked **PRO**. Opening
  one shows a comparison of the free and Pro editions, with a button to buy Pro and a link to register a licence file.
  Pages that are free apart from one Pro function keep their notice on the page. Nothing changes on a licensed
  installation.
- **MSP is always part of Pro.** A managing (MSP) tenant can no longer be set up on the free community edition. An
  installation that an older release recorded that way now runs as a free single tenant, and says so.
- **Updates of the free edition are recognised from the installation itself.** A roll that no release ring governs is
  allowed only when the environment holds no Pro licence, and it is recorded in the audit trail. A licensed environment
  always follows its release ring.

### Deployment fixes

- **The community edition updates with one command.** `tools\setup\Update-PimCommunity.ps1 -Apply` pulls the latest
  release from GitHub and re-runs your deploy with the parameters it was installed with. A successful deploy saves
  those parameters on the machine that ran it (never a secret). Without `-Apply` it shows which version it would move
  to and the plan, and changes nothing. A clone with local changes is left alone.

- **A new installation now sets up its notification mailbox.** The one-command deploy stopped at the mailbox step
  whenever a sender address was given, and the deploy identity lacked the right to give itself the short, time-bound
  Exchange role it needs for that step. Both are fixed. A deploy identity created with an older release gets the missing
  right on its next deploy, so nobody has to grant it by hand.
- **Upgrade note:** the deploy identity now also holds `RoleManagement.ReadWrite.Directory`. Re-running
  `New-PimDeployIdentity.ps1 -GrantGraph -Apply` adds it; the deploy also adds it by itself when it is missing.

### Security and reliability fixes from a code review

- **Delegated administrators are held to their ceiling by what a change grants, not by what it claims.** An assignment
  is checked against the stored definition of every group it names and against the role or scope itself: a directory
  role is tier 0, an Azure assignment's scope must sit under the department's scopes. Columns an entity does not have
  are refused. A delegated administrator changing an admin account may only edit descriptive fields and extend the
  end date within the owner limit; removing an admin goes through the offboard approval. An offboard raised by a
  delegated administrator is checked before any approval is created.
- **Staged changes lock their rows at commit too.** A commit that changes a row another administrator has staged is
  refused, whatever the second-approver setting. With the second approver on "sensitive", direct edits are checked as
  well. A staged removal, or a change that clears a field, is no longer counted as done too early. An administrator can
  discard a colleague's staged change, with a reason that is recorded.
- **Staged edits are no longer lost** when they are made while the page is sharing earlier edits, when someone else
  staged first, or when a colleague holds one of the rows. Discard now says when it did not work.
- **Break-glass accounts are protected in every direction.** A central session revoke that names an account by
  sign-in name is checked against a break-glass list kept by object id. A managed tenant revokes sessions only for the
  central admin it holds, never for its own admin with the same name.
- **Choosing managed tenants is strict.** A tenant list with anything that is not a tenant id is refused instead of
  reaching every tenant, a rename honours the list, and cancelling an authorisation cancels only the one chosen.
- **Mail links use the Manager's own address,** never one taken from a request header.
- **The daily target check no longer reports a subscription it cannot read as deleted,** and a failed read fails the
  run instead of reporting "nothing checked".
- Smaller fixes: the owner page reads owners separated by `|`; a scoped administrator's My people actions follow
  their portal profile; pending changes, and every value the Manager saves, keep their dates exactly (a date and time
  is no longer rewritten in the server's regional format); the engine's "nothing defined" safety stop no longer
  ends the run with an error.

## v2.4.442 — The Access map is tested at every option; reviews go through the engine

- **The Access map is now checked in a real browser at every option**: every kind of box, the focus toggle, the
  overview, search, the risk overlay, removing access, three screen widths, export and print. Each time, every line
  must connect the right boxes and sit exactly on them.
- **Access-review decisions and reviewer changes are carried out by the engine.** The Manager records the decision
  and starts the engine, which applies it within moments and checks it took effect. The Manager itself no longer needs
  permission to change access reviews, so a correctly set-up environment no longer refuses these buttons.

## v2.4.441 — Two checks the Manager was silently skipping

- **Fixed: acknowledging a warning is validated in full again.** The Manager checked only that a reason and an end
  date were given; the complete check (the same one the engine applies) was never loaded. It is now.
- **Fixed: the import check reads the tenant's cached lists** (roles, groups and scopes) as intended, instead of
  skipping that step.
- The whole test suite is green again.

## v2.4.440 — The community edition installs as the README says

- **Fixed: a new community installation no longer stops half-way.** It was refused at the code step as "deployed, but
  no updater", although the community edition has no updater by design, and it then ended as failed because a check
  that is not shipped publicly could not run. A community installation now finishes, and checks itself: the Manager
  is running its latest revision, the page answers behind sign-in, and the engine job exists.
- **The install command in the README now works as written.** It names who may sign in to the Manager, which is
  required, and a dry run says so if you leave it out.
- Proven end to end on a fresh tenant: installed from the README, the engine running every five minutes, and a first
  delegation applied.

## v2.4.439 — Delegated administration: department owners manage what is theirs

- **Department owners can delegate on their own resources.** Give a department its Azure scopes (a subscription or a
  management group) in the new **AzureScopes** column. Its owners can then create and change the Azure permission
  groups of their department under those scopes — at level 3 and below — and stage and commit them themselves. They
  cannot touch another department, anything at level 2 or above, tier 0, or who owns which department. Every refusal
  is recorded in the audit trail.
- A department owner needs no Manager administrator role for this; the portal shows them as **Delegated**. An
  explicit delegated profile, where you have set one, still decides instead. Delegated administration is part of Pro.
- A department with no Azure scopes gives its owners no Azure rights at all.

## v2.4.438 — Department owners review their people

- **Keep, Extend or Remove.** On **My people** a department owner can now confirm that a person still needs their
  access (**Keep**), make it last longer (**Extend**), or ask for it to be taken away (**Remove**). A removal is a
  request: a PIM administrator approves it, and until then nothing changes. The page shows when each person was last
  confirmed and who is due for review.
- **A regular review by mail.** The new **owner review** job mails each department's owners the list of their people
  with a link to My people. It is **off** until you turn it on under **Jobs**; its interval (90 days by default) is the
  review cycle.

## v2.4.437 — Managed tenants act on the master's decisions again

- **Fixed:** a managed tenant treated every removal, rename and session revoke from the MSP master as expired and
  ignored it, even one made a minute earlier. They are now carried out; only decisions older than 30 days are
  ignored, as designed.

## v2.4.436 — Removing an administrator on the MSP master reaches the tenants you choose

- **MSP: remove an administrator everywhere, in some tenants, or nowhere.** When you remove a replicated administrator
  (or any replicated row) on the MSP master, the Manager asks whether to remove it in the managed tenants too — in
  every tenant that has it, or only in the tenants you pick. A tenant that is not chosen keeps it and reports it.
- A managed tenant now carries out the removal of an administrator, together with that administrator's memberships.
  Before, only memberships were removed and the administrator was only reported.
- An offboard (an auto-disable date) set on the master still reaches every managed tenant the administrator reaches,
  without asking — the safe default when someone leaves.
- **Upgrade note:** removals recorded on the master in the last 30 days are carried out on the next pull after this
  release, including administrators.

## v2.4.435 — My people: department owners extend access before it ends

- **New page: My people.** A department owner sees the people in the departments they own and the day each
  person's privileged access ends. If someone still needs it, the owner picks a later date (or +30 / +90 days) and
  clicks Extend — no one else needs to approve an extension. An owner can only make access last longer, never
  shorter, and at most a year ahead by default. Every extension is recorded in the audit trail.
- **A reminder two days before.** The owner now also gets a reminder two days before a person's access ends, and the
  mail's link opens My people at that person.
- **Fixed: central removals, renames and session revokes now reach managed tenants.** The MSP master could not read
+
  publish after this release, removals recorded on the master in the last 30 days are delivered and carried out.

## v2.4.434 — A central session revoke is recorded the same way everywhere

- A managed tenant now records a session revoke it has carried out under the same identity whichever PowerShell
  edition it runs on, so it is never carried out twice.

## v2.4.433 — Revoking an admin's sessions centrally reaches every managed tenant

- **MSP: one revoke, every tenant.** When you revoke an administrator's sign-in sessions on the MSP master, the
  Manager now asks whether to revoke them in the managed tenants as well. Say yes, and each managed tenant revokes
  the sessions of its own account for that administrator the next time it collects the signed bundle — no approval
  is needed in each tenant. This matters most when someone leaves.
- Each tenant carries out a revoke once, and a later revoke of the same person is carried out again. Break-glass
  accounts are still never revoked.
- Removing the administrator right after revoking no longer cancels the revoke that is on its way.

## v2.4.432 — A daily reminder of changes nobody committed

- **New daily job: pending check.**
  - It finds work that was started and never finished: changes staged under **Pending changes**, and queued actions
    such as a TAP re-issue or a session revoke, that have waited for more than a day without being committed.
  - It says who staged them and how long they have waited.
- **Mail.** The list is mailed to your alert recipients with a link to **Pending changes**. You can switch the mail off
  under **Alerting** ("Changes staged or queued more than a day ago and never committed").
- **Your schedule.** A SuperAdmin can change the interval, or turn the job off, on the **Jobs** page.
- Changes that were committed but have not reached the tenant are still checked every 30 minutes by the existing
  convergence check.

## v2.4.431 — A daily check that your delegations still point at things that exist

- **New daily job: target check.**
  - It checks that every Azure resource, resource group, subscription and management group your delegations point at
    still exists, and that the Azure roles and Entra roles they grant still exist.
  - Anything that no longer exists is listed at the top of **Coverage & gaps**, with the delegations that point at it.
    You decide whether to remove them; PIM never removes anything by itself.
  - Something PIM cannot read is shown as "could not be verified", never as gone.
- **Mail when something disappears.** New findings are mailed once to your alert recipients. You can switch the mail off
  under **Alerting** ("Delegations whose Azure resource or role no longer exists").
- **Your schedule.** The job runs daily. A SuperAdmin can change the interval, or turn the job off, on the **Jobs**
  page.

## v2.4.430 — Every mail links to the right page; drift says what differs, and findings can be ignored

- **Every PIM mail has an "Open in PIM Manager" button**, including mail templates you customised earlier. It opens
  the page the mail is about: Drift, Coverage & gaps, Admin accounts, Access reviews, Approvals.
  - The review reminder's "Review now" button now works.
  - Mails that deliver a sign-in credential carry no link.
  - A hosted Manager records its own address the first time someone signs in. You can set another address with the
    `ManagerUrl` setting.
- **Drift says what differs.** A "changed" finding now shows the field and its current and desired values, for example
  `AssignmentType: Eligible -> Active`, on the Drift page. The drift alert mail now lists the findings themselves, not
  only their counts.
- **Ignore a drift finding.** An Admin can ignore a finding, and must give a reason. It then disappears from the counts,
  the page and the drift mail. Ignored findings are listed separately, with who ignored them, when and why, and can be
  un-ignored. PIM's own changes are not affected.

## v2.4.429 — PIM only touches what you define; policy holds come with a change-board spreadsheet

- **PIM changes only what your data defines.**
  - Earlier versions applied the default policy template to every group with the managed name prefix and to every
    directory role, even when nothing in your data named them. Next to an older engine, or next to groups and roles
    managed by hand, that could overwrite policies someone else looks after.
  - A policy is now changed only for a group your data defines, or a role an assignment names.
  - Nothing can turn the old behaviour back on.
- **An empty environment changes nothing.** When your data defines no admins, groups or assignments at all, the engine
  skips every job step and writes nothing.
- **A spreadsheet your change board can approve.**
  - When a large policy change is held for approval, the alert mail now carries an Excel file with every policy and
    setting: current value, new value, and whether it tightens or loosens.
  - A summary sheet gives the totals, the reasons and how to approve.
  - The same file can be downloaded from **Reviews & controls › Approvals** (**Download for change board**).
- **Upgrade note:** when this version starts, policies on groups and roles your data does not define are no longer
  managed and are left exactly as they are. A policy change that was held only because of those groups or roles
  disappears from Approvals.

## v2.4.428 — Pending changes are shared by every administrator, locked per row, with an optional second approver

- **Pending changes are shared.**
  - A staged change is now stored in the environment's database, not only in the browser that made it.
  - Every administrator sees the same Pending changes, updated every few seconds without a reload.
  - Each card says who staged each change.
- **Locked per row.** When one administrator has staged a change to a row, nobody else can change or unstage that row
  until it is committed or they discard it. You are told who holds it.
- **Commit and discard.**
  - A commit includes every staged change, and asks first when some were staged by colleagues.
  - Committed changes leave everyone's view.
  - **Cancel all pending** now discards only your own changes; your colleagues' stay.
- **Optional second approver** (Pending changes, SuperAdmin):
  - **off** (the default): anyone may commit what they staged.
  - **sensitive**: a sensitive change must be committed by a different administrator than the one who staged it.
  - **all**: every change must be committed by a different administrator than the one who staged it.
  - A refused change stays staged and visible, so a colleague can review and commit it.
- **Upgrade note:** changes you had staged in your browser before this version are sent to the shared queue the first
  time you open the Manager.

## v2.4.427 — The permission check reads the mail sender before judging it

- **Overview › permission check no longer says "no mail sender configured" after the Manager restarts.**
  - The sender mailbox is loaded from the store when it is first needed. The permission check ran before that
    happened, so it read the sender as empty.
  - The check now loads the sender first.
- **Clearer wording when only mail is affected.** A mail problem is no longer described as the engine "missing
  REQUIRED permissions".

## v2.4.426 — Commits no longer blame "another administrator" for the engine's own work; the permission check stops false alarms

- **Pending changes › Commit re-applies your edits automatically when the stored rows moved underneath you.**
  - The stored rows can change without another person: for example, the engine clears a Remove row once it has
    applied it, or a queued change lands.
  - Your next commit was then refused with "another administrator changed …", and you had to reload the page.
  - The Manager now re-reads the changed data, re-applies your edits on top and commits, with no reload and no
    dialog.
  - You are only asked when one of your own edits touches a row that really changed. It retries once, never in a
    loop.
- **Overview › permission check no longer reports false blockers.**
  - **Azure:** it now asks Azure which roles the engine identity actually holds, including roles inherited from
    management groups. It no longer says "no Azure role-management scope" when the engine has User Access
    Administrator at the tenant root.
  - **Mail:** it now counts mail as working when the most recent real alert was delivered, and as failing when the
    most recent attempt failed. It no longer always says "not verified".

## v2.4.425 — Access map lines stay put in a Remove session; admins scheduled for later no longer raise convergence failures

- **Access map: clicking Remove access (or Give access) twice no longer throws the lines across the board.**
  - The second click drew the lines while the panel under the board was briefly short. The panel then grew back to
    the same height, so nothing redrew them.
  - The lines were scaled into the wrong box and slid into the group column.
  - The board now redraws its lines once more, after the layout has settled, and whenever its own size changes.
- **Jobs › verify-convergence no longer fails for an admin who does not exist yet.**
  - When an admin was scheduled to be created on a future date, their group memberships were planned straight away,
    for an account that did not exist yet.
  - After the grace window, the check reported them as "exist in the Manager but NOT in the tenant".
  - Those memberships now wait for the account. They are applied on the first run after the account is created.

## v2.4.424 — The permission check works on hosted environments and tells you how to fix it; the Access map keeps its lines

- **Overview › permission check now actually checks.**
  - On a hosted environment the check always said "Permissions could not be checked". The Manager could not work out
    which identity it runs as, so it never read a single permission.
  - It now finds the identity from its own sign-in token. It then checks the **engine's** identity, the one that
    applies your changes, rather than the Manager's own read-only identity.
  - When the check cannot run, the banner now says why.
- **A way to fix missing permissions.** When the engine is missing a permission, the banner now shows a ready-to-run
  PowerShell script with a **Copy** button. The script grants exactly the missing permissions to the engine identity.
  A Global Administrator runs it once. The portal cannot grant permissions itself, on purpose: an identity that can
  grant permissions could give itself anything.
- **Access map: selecting a permission group shows the lines to the people.** After you clicked a box, the pointer
  was still resting on it, and hovering only lit the lines touching that box. The lines from people to their groups
  faded almost out of sight. Hovering a box now lights its whole path, from the people through to the permissions.

## v2.4.423 — Approvals keeps its held changes; Reset TAP always answers

- **Held policy changes stay visible under Approvals.**
  - After anyone had opened Access reviews, the Approvals page stopped showing held policy changes. That lasted
    until the Manager restarted, and no held change set could be approved from the page in the meantime.
  - Opening Access reviews no longer affects the approval page.
- **Reset TAP always answers.**
  - Clicking Reset TAP in Accounts & TAP before the list below it had finished loading did nothing at all.
  - It now finds the admin anyway. If the admin really cannot be found, it says so.

## v2.4.422 — the rename works end to end; the right permission for access reviews

- **Renaming a group now really reaches Entra ID.** 2.4.421 recorded the former name, but a step that prepares the
  groups for the engine dropped it, so a rename still made a second group. The former name now reaches the engine,
  and the engine renames the group it already has.
- **Access reviews need `AccessReview.ReadWrite.All`.** 2.4.421 granted a narrower permission that Microsoft does
  not accept for creating a review. The deployment now grants the one Microsoft documents for that call. It is
  broader than the reviews PIM creates: it also covers reading and changing other reviews.
  **Upgrade note:** it takes effect when the hosting permissions are granted again. Once granted, reviews are
  created for every group with a review cycle, and they mail their reviewers.
- **Reset TAP is no longer offered where it cannot work.** In Accounts & TAP, on an environment without a mail
  sender, the button was enabled and the click was then refused. It is now disabled and says why: a pass is only
  ever mailed, so it needs the sender mailbox.

## v2.4.421 — a rename renames, and four quieter fixes

- **Renaming a group or an Administrative Unit now renames it in Entra ID.**
  - Until now, a new name reached Entra ID as a *second* group. The old group kept every membership and role it
    held, and nothing managed it any more.
  - The Manager now remembers the former name. That covers the Rename button in All records and a direct edit of
    the name. The engine then renames the group or AU it already has: the same object, with its members and roles.
  - **Upgrade note:** a group renamed on an earlier version has its old copy still in Entra ID. Remove the old one
    by hand.
- **Access reviews can be created.**
  - The engine creates a quarterly (or other) review for every group whose row has a review cycle, but it was
    only ever granted *read* access to reviews. Every such run failed with "the engine identity lacks a permission".
  - The deployment now grants the narrowest permission that creates reviews of group membership.
  - **Upgrade note:** existing environments get it when the hosting permissions are granted again. Once granted,
    reviews are created, and they mail their reviewers.
- **A new admin's Temporary Access Pass no longer fails the run.** The pass and the account are made by two jobs
  on their own schedules. When the pass job came first, the run was marked failed. It now waits for the account
  and issues the pass on its next run.
- **A tenant that allows no guest invitations gets a clear answer.** The engine used to retry the invitation three
  times and then report an unexplained failure. It now stops at once and names the External collaboration setting
  to change.

## v2.4.420 — what the new daily live test found, fixed

A new end-to-end test drives every feature against a real test tenant, both through the engine and through the Manager
in a browser. Its first runs found these, all fixed:

- **A revoke is checked, not assumed.**
  - **Sign-in session revoke:** the result is now confirmed by reading the moment from which the user's sessions are
    valid. It used to be recorded as "not verifiable".
  - **Deleted principal:** a revoke for an account or group deleted after the list was read now completes as done,
    because a deleted principal holds no role. It used to fail after three attempts. It still fails if the object is
    only temporarily not found.
- **A brand-new account or group is no longer a failed run.** A role given to a principal created minutes earlier can
  be refused while Entra ID catches up. The run now shows it as *waiting* and applies it on the next run. It used to
  mark the whole run failed.
- **Pending changes says what a change is.**
  - Each changed row leads with its name.
  - A group deletion says it "will be DELETED in Entra ID on the next engine run".
  - Small change sets open their details.
  - All records marks an edited record type as pending straight away.
- **Times are right.** On a server set to a local time zone, queued changes showed times hours off, some "applied"
  before they were requested. Every time is now stored in UTC and shown in one format, for example
  "2026-09-24 04:06 UTC".
- **The Home permission banner** no longer hangs on "Checking permissions…" when the check cannot run. It says nothing
  was checked.
- **Screens use the names in the menu.**
  - Help text now says "Pending changes" and "Review current delegations", the names in the menu.
  - Eight panels no longer squeeze their help into a thin column.
  - An empty Access map says where to start.
  - The wizard review counts every row it stages.
- **First deployment into an empty tenant** no longer looks hung while the database server does not exist yet.

## v2.4.419 — an environment with a private registry can update itself

**Nightly updates now build on your private build pool.** If your container registry has public access turned off,
the registry refuses Azure's shared build machines, and only a build pool inside your own network can build the new
image. The deployment has always recorded that pool, but the nightly updater never used it, so every nightly build
failed after a few seconds and the environment stayed on its old version. The updater now builds on the pool.
**Upgrade note:** an environment still running an older updater cannot use this until it has been updated once. That
first update has to be built on the pool by hand; after that it updates itself.

## v2.4.418 — selecting a row no longer buries the grid

**The "which one do I want?" table fits again.** Selecting a row in **All records** opens a bar with the four actions
(stop managing, remove, revoke, delete) and a short table explaining each. On most screens the table's main
column was squeezed to two or three words a line, so the table became very tall. The bar stays at the top of the
page, so that tall table covered the rows you had just selected. The table now uses the full width and stays a few
lines tall.

## v2.4.417 — the Access map is back

**The Access map is visible again.** With something selected, the map's toolbar carries four large Add and Remove
buttons. Everything was forced onto one row, so the help text was squeezed into a narrow, very tall column. That
pushed the map itself out of view at most window widths. The toolbar now wraps, the help text has its own line
under the buttons, button labels stay on one line, and the map always keeps room to show.

## v2.4.416 — a Temporary Access Pass is sent once, and again only when you ask

**No more daily TAP mails.** Since v2.4.391, when an admin's Temporary Access Pass expired before they had set up
a sign-in method of their own, the engine deleted the pass, created a new one and mailed it. Passes expire daily, so
an admin who had not signed in yet was sent a new TAP every day. The engine now issues each admin **one** pass. When
it expires, nothing happens automatically. To send a new one, click **Reset TAP** for that admin in the Manager.

## v2.4.415 — a disabled button that says why, and an approval you can actually check

**A greyed-out button now tells you why it is greyed out.** *Commit selected* on the change queue is off when
nothing on the list is waiting for you — everything shown is already applied or saved. That was explained, but in
a paragraph above the table, which is not where you are looking when the thing you clicked did nothing. The
reason is now on the button itself.

**"Already authorised" now says it needs nothing from you.** The panel listing the changes your managed tenants
will receive read like something waiting for approval. It is the opposite — those are done, they travel on the
next publish, and the only action is to cancel one if it was a mistake. It says so, and says explicitly that
*Commit selected* does not apply to it.

**An approval request now carries what it authorises — from every screen that raises one.** A request used to
be able to say only *what kind* of change and *which entity*, so the approver saw "this request does not list
its items" and was told, correctly, not to approve it. Requests raised from a refused **Review & Save** now list
the staged changes in plain words (*stop managing… / REMOVE the access… / DELETE the group… / add… / change…*,
with the fields that differ), and the manual **Raise a request** form now requires the same list — pre-filled
from your staged changes when it can be. An approver cannot consent to a target name.

**How to copy settings between tenants is now in the product.** The script that exports a setting from one
tenant and imports it into another shipped in the previous release, and nothing on any screen mentioned it. The
command is now on the **Naming conventions** card, together with the two things that make it safe to run: it is
a dry run unless you ask it to apply, and it refuses the settings that name the tenant they came from.

## v2.4.414 — delete, remove, revoke and stop managing: four words, defined once, and two of them now have a button

**🔴 You can take a delegation away.** A delegation row now has a **⊖** that removes the access it grants: the
engine takes that exact assignment away on its next run and then clears the row. Until now there was no control
for this anywhere — the ✕ only stopped managing the row, and Maintenance & Revoke acts on the live assignment
and leaves the delegation alone. Reported plainly: *"how can i remove the delegation - is that only done in the
revoke or how ?"* … *"nobody knows how to do that"*.

**🔴 Revoking alone does not make access stay away — and now the product says so.** A revoke acts on the live
assignment only; the delegation that granted it is untouched, so if it still says *Assign* the engine creates
the access again on its next run. The revoke screen now states this and points at the ⊖.

**🔴 The Access map promised something it did not do.** Removing a link there deleted the delegation row and
said *"the engine takes the access away on its next run"*. It did not: no scheduled job prunes, so a live
assignment whose row has gone is reported and left alone — which is why removals there appeared to have no
effect. The map now stages the act that really removes the access, and still draws the link struck through
with a one-click undo.

**The four words are defined once, and shown where you choose.** *Stop managing* (the row leaves, access stays),
*Remove* (the access goes), *Revoke* (the live assignment goes now, but comes back unless you also Remove), and
*Delete* (the group itself goes). Every list that offers them renders the same table, and every confirmation
repeats it, so the four can no longer be read as the same thing.

### Also in this release — "delete the group" now exists, and says what it does

**🔴 You can delete a group from the Manager.** Every group-definition row gains a bin (🗑) that deletes the
group in your directory: the directory roles it holds are removed, every member is taken out, and the group
object is deleted. It is **refused** while any delegation row or any live assignment still gives somebody
access through it — the refusal names them and offers to take you there — and the dialog tells you whether
automatic group deletion is switched on in your environment, so you are never told something was deleted when
it was not. Nothing happens until you commit.

The product has always had this act; it was driven by a `Lifecycle` flag on the definition row, and that column
was not on any grid — so it could not be set, seen or cleared from any screen. It is now on all of them.

**"Stop managing 1 row(s)" is gone, and with it the confusion.** Reported plainly: *"if i want to delete this
group, what to choose and what is the diff between delete and stop managing 1 row. noboddy understands what stop
managing 1 row means"*. Two different acts were wearing each other's words — the ✕ asked *Delete "X"?* while
deleting nothing, and the bulk button used an internal term. Now:

- **✕ / the button above the list** — *take the row out of PIM*. The group stays, everyone keeps the access they
  have, the product stops managing it. Its confirmation says exactly that, and points at the bin.
- **🗑 on the row** — *delete the group*. Cannot be undone.

A line above the list answers the question directly: which one do I want, and what survives each.

### Also in this release — two fixes that only showed up on one of the two supported PowerShell hosts

**The drift report's exclusion of our own SQL administrators group was host-dependent.** v2.4.412 leaves that
group — the one the deployment creates and the product's own identities belong to — out of the drift report,
because it is not something you can ever "fix". That worked on PowerShell 7, which is what a deployment runs, so
no report you have seen was affected; on Windows PowerShell 5.1, which this product also supports, the exclusion
did nothing at all and the group came back as drift. The same slip skipped the exclusion for any area whose
*only* drift item was that group.

**A misspelt administrator name lost its "did you mean" list**, on that same host. When exactly one close match
existed — one character wrong in a name, which is the common case — the suggestion list was dropped and the
message fell back to "add it, or delete this row". Four checks were affected, including the one that reports a
delegation naming an administrator nobody defines.

**Both had the same cause**, and it is now written down where the next reader will see it: on Windows
PowerShell 5.1 a one-element result collapses to a single object with no count, so "is there anything here?"
answered *no* for exactly one item. Both are now counted the way that works on both hosts, and the tests that
cover them run on both hosts.

**Test suite.** A batch of checks had drifted into asserting things that were deliberately changed — an old
ring order, wording this release series replaced at your request, a character budget a growing page outgrew —
and one of them named a function that does not exist. They now assert the current behaviour, so a real
regression is visible again instead of being lost among known reds.

## v2.4.413 — the administrator job runs again, and replicated administrators stop being reported as orphans

**🔴 Fixes a crash that stopped administrators being created on a managed tenant.** The change in v2.4.412 that
lets the engine read the accounts its own records name contained a PowerShell construct that throws the moment it
runs (`Argument types do not match`). The effect on a managed tenant: the administrator job failed immediately,
every run; the nine administrators sent by the provider were never created; and the access-pass job then failed
nine times with *"user not found"*, which looked like a separate problem and was not. Upgrade if you are on
v2.4.412 — the failure is silent apart from the failed job.

**Why it got past the tests, and what now stops it.** This solution already has a scanner for exactly this
construct, because it has caused three production failures before. It was not run before v2.4.412 shipped. Nothing
about the scanner changed; the release checks now include it.

**🔴 Administrators sent by your provider are recognised everywhere, not just by the engine.** On a managed tenant
the administrators your provider governs are held separately from the tenant's own — they are read-only there. The
**Pending changes** screen only looked at the tenant's own list, so every delegation that named a sent
administrator was reported as an error pointing at a missing account: eleven of them on one live tenant, all false,
each offering to either delete the delegation your provider sent or to create a local duplicate of an account your
provider owns. Both would have made things worse. Sent administrators now count as defined, while a delegation that
names an account nobody defines is still reported exactly as before.

**A tenant's administrator naming now comes from the tenant's own settings.** It was additionally passed in at
deployment time, so the two copies could disagree with nothing to reconcile them — which is how the v2.4.412
problem arose in the first place. The tenant's own setting now wins, a deployment-time value is used only if the
tenant has none, and a disagreement is written to the job log naming both values.

## v2.4.412 — a name never decides who gets replicated

**🔴 Admins are no longer withheld because their names look different.** A managed tenant's admin naming prefixes
are a *local* setting: they tell that tenant's engine which accounts in its directory are admin accounts. They were
also being used to decide **which administrators your provider is allowed to send you** — so on one live pair a
deployment string (`Admin-,admin-`) silently dropped nine published accounts, and the run reported success. That is
fixed: every admin the master publishes is sent, and a naming mismatch is **reported**, never acted on.

**The reason it existed is fixed properly.** The guard was protecting against a real failure: an account whose name
the tenant's engine cannot match is never in its live set, so it looks missing, gets recreated every run, and ends
up unmanaged. The engine now **reads the accounts its own records name**, whatever they are called — so a centrally
sent administrator is seen, managed and reconciled like any other, and nothing is recreated in a loop.

**The pull's own explanation is kept.** How many administrators were sent, what was excluded by policy or ring, how
many groups will be created — that sentence existed only in a container log that is gone minutes later. It is now
stored with the run, so **Job schedule** shows it.

**New: copy a setting from one tenant to another.** `tools/setup/Copy-PimSettings.ps1` exports a named setting
(naming conventions, a schedule) and imports it into another tenant, with a backup of the target's current value
taken first and a read-back afterwards. It **refuses** the settings that name the tenant they came from — who may
use the Manager, trust pins, store pointers — because copying those points one tenant at another's identities.

## v2.4.411 — you can see what you are approving, and a managed tenant can see what came from you

**An approval says what it authorises.** A revoke batch used to reach the approver as a label and a justification —
nothing about the assignments it covered. The request now carries **one readable line per assignment**, and the card
lists them. Raise it straight from the revoke screen and it is filled in for you. A request that carries no items
says so plainly and tells the approver not to approve what they cannot see.

**On a managed tenant you can tell your provider's rows from your own.** Every record type that can be replicated
now shows a **Source** column — *from the MSP master* or *local* — with the counts in the header line. Nothing is
editable there that was not before; it simply answers "where did this come from?", which the hidden replication
columns used to make impossible.

**Fixing a validation error updates the status immediately.** Every fix button — and *Fix all auto-fixable errors* —
re-takes the report against what your staged changes would produce, so the error count and the Save gate follow the
fix. You no longer have to switch Block-Save off to commit.

**Replication wording no longer offers a value that is not in the picker**, and only a row that really replicates
needs a ring: a row that is merely carried along as a dependency does not, and is no longer flagged.

## v2.4.410 — an admin can follow a delegation, bulk replication/ring, and several dead ends opened up

**🔴 A delegation marked "Replicate to managed tenants" no longer goes nowhere.** If the person it names was a
master-only admin, the delegation was dropped on the way out — silently. An admin account can now be set to
**"Only where a delegation needs this admin"**: the account is created in a managed tenant exactly where a
replicated delegation names it, and nowhere else. A delegation whose admin is still master-only is now **listed
as not published, with the fix in the sentence**, instead of disappearing.

**A row that replicates must name its ring.** Replicate = *yes* with an empty Ring reached nobody while looking
finished. Saving such a row is now refused, and the bulk control counts how many of your selected rows would hit
it.

**Set replication and ring on many rows at once.** Tick the rows in **All records** and use **Set replication
to…** and **Move to ring…** in the selection bar. The ring bulk action used to exist only for admin accounts.

**Cloning a row no longer breaks the next commit.** A clone copied the group tag, and the store keeps one row per
tag — so the commit was refused, for every staged change at once, long after the click. A clone now gets its own
tag. And if you already have duplicates, the refusal lists them, offers **Show me these rows**, and can **give
each row its own key** in one click.

**"Remove this assignment" now updates the status immediately.** The validation report is re-taken against what
your staged changes would produce, so the error count and the Save gate stop showing errors you have already
fixed — you no longer have to switch Block-Save off to commit.

**An Azure role assignment that is already gone is not a failure.** Re-running a cleanup (or removing something
in the portal first) reported *RoleAssignmentNotFound* as a failed action; it now reads as done.

**A job no longer fails because something it needs is created moments later.** A membership whose group is
created by the *same* cycle reported *"The group this item needs does not exist yet"* as a **failed job**, and
alerted on it every cycle. Such items are now reported as **waiting** — the run stays green and says how many
are waiting and why. A real failure beside them still fails the run, and an item still waiting hours later
becomes a failure again, because then what it waits for is not coming.

**Smaller things you asked about:** the Access map's **+ / −** signs are legible on the coloured buttons; the map
bar tells you where a group is **renamed or deleted**; an empty *Remove* list says *why* it is empty; **Commit
selected** says why it is greyed out; **Backups / Undo** scrolls itself into view; the **msp-pull** job row
explains that the definitions pull runs elsewhere and links to **Job schedule**; and a triggered engine run no
longer stretches the history table with its whole scope list.

## v2.4.409 — giving and removing are two different buttons, in two different colours

**Giving access and taking it away are no longer the same control.** 2.4.408 let you remove a delegation on the
Access map by clicking a link that already existed — but through the *same* button and the *same* list as giving,
so you could not tell, before clicking, which of the two you were about to do. Each direction now has its own
button: **➕ Give access / Add people / Add permissions** in blue, and **➖ Remove access / Remove people /
Remove permissions** in red. The list each one opens shows only that direction's candidates — giving lists what
the thing does **not** have yet, removing lists only what it **is linked to today** — so a click can never do the
opposite of the button you pressed.

**You can see which is which.** A staged addition is amber and says **"staged add"**; a staged removal is red,
struck through, and says **"staged remove"**. While a removal session is open, the highlighted column, the list
and the bar are red rather than blue. (Ctrl+click and drag still work on an existing link and still ask you to
confirm by name.)

**The selection bar no longer hides at the bottom of the page.** The bar that says what you have selected and
carries these buttons now sticks to the bottom of the screen, tinted and outlined — blue while giving, red while
removing — instead of sitting off-screen below a full-height board.

**"Open PIM-Definitions-Services in Advanced View" now reads "Open Service groups in All records"** — the record
type in the words the rest of the tool uses, and the page under the name it actually has.

## v2.4.408 — sign-in fixed for names with spaces or accents, and you can remove a delegation where you can see it

**🔴 Upgrade note — some administrators could not sign in at all.** If a person's display name contains a space or a
non-English letter, the sign-in was rejected and the browser showed
*"no authenticated principal — this app must be reached through its authentication edge"*. The authentication was
working; the check that compares the two identity headers compared an encoded value with a decoded one and concluded
they were different people. Nothing to change in your tenant — install this version and the sign-in works.

**Remove a delegation on the Access map.** You could map people to groups and groups to permissions there, but not take
one away — the board pointed you at *Review current delegations*, which lists the access that is **live in the tenant**
and never held these rows. Now the same gesture works in both directions: Ctrl+click an existing link, drop on it, or
click an **already linked** entry in the list, confirm by name, and the removal is staged — drawn red and struck through
— until you commit it on **Review & Save**. Click it again to take it back.

**"Cannot be deleted" now names what is in the way, and takes you there.** Deleting a group that is still used said
only *"PIM-Assignments-Groups: 1"*. It now lists each delegation in words — who is in the group, which permissions it
gets, which Entra role it holds — says these are delegation rows rather than live assignments, and offers to open
exactly those rows, filtered, so you can remove them first.

**Searching *Review current delegations* now understands group tags**, not only the display name the live assignment
carries, so a search by tag stops coming back empty. And when nothing matches, the page explains the difference between
a live assignment and a delegation instead of a bare "no rows", and offers to look for the same text on the Access map.

**The audit trail stops saying "(none)".** A sign-in has nothing before it, so every field read
*"role: (none) → SuperAdmin; mode: (none) → hosted"*. A login is now one sentence — *signed in as SuperAdmin (hosted
Manager, role from sql ManagerAccess)* — and any other event that records a state simply states it.

**PIM's own SQL admin group is no longer reported as drift.** `grp-pim-sql-admins` is created by the deployment and
holds the identities the solution runs as, so it appeared as an extra object that could never be resolved. It is left
out of the counts, and the page says how many items were left out and which object they were.

## v2.4.407 — both schedules on one page, Run now on every managed tenant

**You have two schedules, and now you can see both.** The **definitions pull** (how often a managed tenant fetches
the configuration from the master) has always been editable on the Job schedule page. The **software update** — which
builds and rolls the new version — is a separate, daily schedule that belongs to the deployment, and it was not shown
anywhere. It is now listed beside the pull, with its cron, its ring and where it is changed. It stays read-only here,
because it is set with the job, not on this page.

**Run pull now works on every managed tenant.** It only appeared on locally-hosted managed tenants; a centrally-hosted
one had no pull row at all — no cadence, no button — and the request was refused. Both kinds are managed tenants and
both now show it. A tenant whose type was never recorded is recognised from the fact that it pulls.

**"(blank)" in the replication column now reads "No replication to managed tenants (default)"**, which is what blank
has always meant. Nothing was rewritten in your data: the value stays empty, the label says what it does.

## v2.4.406 — revoking and renaming now reach the managed tenants

Removing a row that is replicated to your managed tenants asks one question: **also remove it in the tenants that
already have it?** Say yes and each tenant removes it on its next pull — no approval in 25 places, because the
decision was made once, here. Say no and it simply stops being published: the tenants keep what they have and report
it, as before.

**Renaming a group tells them too.** A rename used to arrive as a *new* group, with the old one left behind. The
tenants now rename the group they already have. A rename onto a name a tenant already uses is refused rather than
merging two groups.

**You can see and undo it.** Every authorised removal or rename is listed on **Pending changes** — what, where, and
who decided it — with an ✕ to cancel it before it is published.

Everything else is unchanged: a tenant still never removes something merely because it stopped arriving, and a
configuration published with no such authorisations is byte-for-byte what it was before.

## v2.4.405 — groundwork for revoking and renaming across managed tenants

A managed tenant deliberately does **not** remove something just because it stopped arriving — it reports it and waits,
because "it was revoked" and "the publish failed" look the same from there. That means a revoke you make centrally
cannot reach the managed tenants by simply disappearing, and a rename sent as a new name arrives as a **second** group
rather than a renamed one.

This release adds the missing piece: the master can state, inside the signed configuration it publishes, exactly which
removals and renames it authorised. A managed tenant then removes precisely those and nothing else, and applies a
rename to the group it already has instead of creating another one. A rename onto a name the tenant already uses is
refused rather than merging two groups.

**Nothing changes yet:** the capability is in place and fully tested, but it is not switched on — publishing,
pulling and the "also remove in the managed tenants?" prompt are wired in the next release. A configuration published
today is byte-for-byte what it was before.

## v2.4.404 — a group that is still in use cannot be deleted

Deleting a group is now **refused** while anything in PIM still uses it, instead of offering to delete those rows with
it. You are told how many rows use it and of which kind, and to remove them first — emptying a group decides somebody's
access, so it is done deliberately, on those rows. Both what you have configured and the live PIM assignments in the
tenant are checked, and the confirmation tells you whether that live check could run.

## v2.4.403 — rename a group, delete one safely, and a replication choice with two answers

**Rename a group or an AU from All records.** The rename action changes the name, the description **and the tag** —
and because the tag is what every other row uses to address the group, every one of those rows is updated in the same
change: memberships, group nesting, Entra role bindings, AU-scoped bindings, Azure and workload rows. A tag that
another group already uses is refused, and so is an empty one. Nothing is written until you commit.

**Deleting a group now tells you what else goes.** Removing a group used to leave the rows that pointed at it behind,
addressing something that no longer exists. You are now told exactly what uses it — "used by 3 other row(s):
memberships 1, nesting 1, role bindings 1" — and can remove them together, or cancel and change nothing.

**The replication choice is two answers, not three.** *Follow* is gone. It meant the same as *No replication*: a row
that something replicated depends on is sent either way, automatically. The choice is now **Replicate to managed
tenants** or **No replication — master tenant only**, blank meaning no replication. Nothing about what is actually
sent has changed.

**Pulling from the master more often** is a setting, not a new feature: on a managed tenant, Job schedule → the pull
job → set the interval (minimum 5 minutes, 30 for a half-hourly pull). It was already there, defaulting to daily.

## v2.4.402 — new Entra roles are reported, not queued

Discovering a new built-in Entra role used to add an entry to the change queue. Nothing in the product ever used those
entries, so they were work for you and nothing else. A newly-appeared role is now simply **reported** — it is written
to the audit trail and included in the discovery notice mail — and every role that no permission group grants is
already listed as a **Gap** on **Coverage & gaps**, with a proposal for how to cover it. That is where to look.

Because of that, **Entra role** is no longer listed under the auto-create policy on the Discovery page: auto-create
means "stage a delegation group for a newly-found resource", and nobody creates a role Microsoft ships. The page now
says where new roles show up instead.

## v2.4.401 — undo a link, a faster Pending changes page, and discovery obeys its own policy

**Undo a link you did not mean.** Ctrl+click a staged link again to take it back, drop on it again, or press the **×**
that appears on a box you have staged to the selected one. A link that is already committed is refused with the
reason — removing that one is a revoke, not an undo. The pick list marks a staged entry *staged — click to undo*.

**The same link cannot be staged twice.** The check now reads what is actually staged rather than what the board
happens to show, so repeating a click can never produce two identical rows. Repeated messages no longer stack up
either — you get one.

**Pending changes loads faster.** The page read every queue entry, including discarded history, and each entry
carries the full detail of the change it made. Discarded entries are now fetched only when you tick *Show discarded*,
and the counts still cover everything, so the page still tells you how many are hidden. Failed entries are never
hidden.

**Queue entries say what they are.** A row discovered in your tenant used to read *"Add PIM-Catalog-ServiceRoles row
entra|124577f8-…"*. It now reads *"Catalogue the Entra ID role 'Attribute Assignment Administrator' — found in the
tenant and not yet in PIM's catalogue (cataloguing it grants nobody access)"*. The technical key is still shown
underneath for support.

**Discovery honours the policy you set.** With *Entra role* set to **flag — log it, do nothing**, role discovery was
still queueing every role it found (on a tenant with no baseline, that is all of them). It now reports what it found
and queues nothing, and the job says which policy it used — so "nothing queued" is never confused with "nothing
found". Choosing *pending* or *auto* also works properly now: the engine reads the saved policy, which it previously
never loaded.

## v2.4.400 — the groups you can link to stay on screen when you select someone

Selecting a person or a group collapses the Access map to that item's path — which also removed every box you might
want to link it to, so there was nothing to Ctrl+click or drag onto. Boxes you can link the selection to now stay
where they are, drawn faded and dashed, and light up as you point at them. The path you selected is still the thing
that stands out.

## v2.4.399 — a link made by dragging now shows up like every other one

Dropping one box on another did add the link, but the board did not redraw — so the dashed line and the amber
**staged** marking did not appear, and the only way to see the change was to open Review & Save. Linking by dragging
now leaves exactly the same visible trace as Ctrl+click: both boxes marked, the line drawn, and a line of text saying
what was staged and where to commit it. The marking stays while you look at other parts of the map.

## v2.4.398 — the lines on the Access map point at the right boxes again

Selecting a person or a group drew the connecting lines before the detail bar at the bottom had finished re-drawing.
That bar changes height with what you select, and the recent linking work made it taller — so the board shifted under
lines that had already been drawn, and they appeared to connect the wrong rows. The lines are now drawn again once the
bar is in place, and redrawn whenever it changes height (opening the pick list, a staged note appearing).

## v2.4.397 — you can see which boxes have an uncommitted link

On the Access map, both ends of a link you have added but not yet committed are now marked in amber, with the word
**staged** on the box — the same amber as the dashed line between them. It tells you what you have changed in this
session at a glance, even when the other end of the line is scrolled away. The mark disappears by itself once you
commit on **Review & Save**.

## v2.4.396 — link by Ctrl+click or by dragging, and the buttons are where the other buttons are

**Ctrl+click.** Select the source — a person, or a group — then hold **Ctrl** (⌘ on a Mac) and click each target: the
groups that person should be in, or the permissions that group should have. Each click adds one link and says so, and
your selection stays put so you can keep clicking. A plain click still only selects, so nothing is linked by accident.

**Drag and drop.** Drag a box onto another box. Only the boxes that can accept it light up, so you cannot drop a
person onto a permission by mistake.

**The buttons moved to where you look for them.** *Give access*, *Add people*, *Add permissions* and *Give to a group*
now sit in the toolbar next to Risk overlay and Export CSV, named for whatever you have selected, and they lead the
detail bar instead of trailing it. They open the searchable list, which now scrolls into view when it opens.

However you do it — Ctrl+click, drag, the list, or clicking the highlighted column — it is the same change: a staged
link, shown as a dashed line, committed on **Review & Save**.

## v2.4.395 — pick what to link from a searchable list

**A list to pick from.** When you start a link on the Access map, the candidates now appear as a list under the board:
type to filter by name or tag, click an entry to add it, keep clicking to add more, then press Done. Clicking the
highlighted boxes on the board still works — it is the same list, shown two ways.

**You can see what is already linked.** Candidates the selected item already has are listed and marked *already
linked* rather than hidden, so a group that looks missing really is missing.

**Nothing is written by the board.** A pick becomes a pending change — the Pending changes badge updates and the new
link is drawn as a dashed line — and **Review & Save** is where it is committed. The commit is backed up first and
applied in one transaction, and the engine then applies it in your tenant on its next run, which the commit starts
straight away.

## v2.4.394 — map people into groups, and groups into permissions, straight from the Access map

**The Access map now maps.** It showed who can reach what; it could not connect anything. Select a person and choose
**+ Assign to a direct group** to put them into a job role, department, organisation or project group. Select one of
those groups and choose **+ Add people**, or **+ Add permissions** to give the group a permission group's permissions.
Select a permission group and choose **+ Give this to a direct group**. Either end of a link works, so you can start
from the person, the group or the permission — whichever you are looking at.

The column you can pick from lights up, and each click adds one change, shown at once as a dashed line on the board.
Nothing reaches your tenant until you commit on **Review & Save**, exactly as with every other change. Permissions that
carry a directory role are added as eligible, because Entra does not allow them any other way; everything else is added
as active.

**Nothing is removed from this board.** The map only adds, so it stays safe to hand to a reviewer. Removing access is
still done on Maintenance & Revoke. Adding a link needs the Admin role; a Reader is not offered the buttons.

**A directly assigned role keeps its identity.** "Who gets which role directly" rows are now identified by person, role
and assignment type, so saving that table can no longer drop them.

## v2.4.393 — settings apply at once, copy settings between environments, sort and filter the grid

**A saved setting takes effect straight away.** Switching a feature off in Settings, such as the second-approver policy,
used to take effect only after the Manager restarted. It now applies the moment you save.

**Copy settings to another environment.** Settings › Copy settings exports the sections you pick (naming, filters,
alerting, features, policy and mail templates, job schedule and more) to a file. On another environment, importing the
file shows every setting as current → new, and only the settings you tick are written. Who may use the Manager,
approvers, break-glass accounts, the licence, deployment rings and the admin account domain are never copied.

**Sort, filter and resize in the grid.** Click a column header to sort, type in the filter box to show only matching
rows, and drag a column's right edge to change its width. The list of record types shows how many changes are pending
instead of "mod".

**One way to name an admin in "Who gets which group".** Admins are stored by their UPN. Names written without a domain
are converted the next time you commit that table. Memberships replicated from an MSP master keep the plain name, because
each managed tenant adds its own domain.

**"PIM policy" in the wizards.** The policy fields are labelled "PIM policy" instead of "Group policy", so they are not
confused with Windows Group Policy.

## v2.4.392 — jobs heal themselves, commits no longer fail after a template import, fewer false policy holds

**Jobs show their real state.** A job is failing only while its latest run failed. The next run that doesn't fail clears
it by itself, so there is nothing to acknowledge and the Ack button is gone. The Jobs page, the Overview tile, Engine logs
& errors and the menu count now always agree. An earlier failure that a later run cleared is marked "healed".

**Commit all works after a template import.** Two causes of failed commits are fixed. Pressing Commit all twice could run
two commits at once, and the second one tried to empty a record type. Commit now runs once, and the server refuses a
request that carries no rows. Importing a pack could also add a second row for a group that already had one. The import
now skips rows whose group already has a row and tells you which ones it skipped.

**Fewer policy approvals.** A policy nobody has ever changed, such as the policy of a group you just created, gets its
template the first time without counting toward the approval limits. Policies someone has set are still held for approval
as before.

**Defender roles stop showing as changed on every run.** A permission that a wildcard in the same role already grants no
longer counts as a difference.

**Temporary Access Pass lifetime.** When no lifetime is set, a TAP lasts 8 hours (not 48, as v2.4.391 said), and never
longer than the tenant allows.

**Clearer messages.** A TAP that cannot be delivered is explained in one sentence with one fix. A held run lists three
items and a count instead of every item. A policy change Microsoft Graph refuses shows the request ID, the rule the engine
sent and the rule as it is set now.

**Smaller fixes.** Settings › Permission template packs has an **Import…** button. A feature that is off no longer looks
locked, and ticking it says it will be enabled when you save. The Managed tenants tab is on by default on an MSP master.
The naming settings no longer show duplicated headings.

## v2.4.391 — 48-hour TAP, TAP and Revoke for central admins on a slave, and errors you can see

**Longer Temporary Access Pass.** When no lifetime is set on the admin, a TAP now lasts 48 hours instead of 4, which
is enough time to sign in and set up many tenants. The TAP can never last longer than the tenant's own TAP policy
allows. **Upgrade note:** Entra's default TAP policy maximum is 8 hours. Raise it in Entra › Authentication methods ›
Temporary Access Pass if you want the full 48 hours.

**A TAP keeps coming until the admin has signed in.** A new TAP is issued until the admin has registered a sign-in
method of their own, such as a passkey, Microsoft Authenticator or Windows Hello.

**Central admins on a slave.** A central admin replicated to a slave is a separate account in that tenant. Reset TAP,
Revoke sessions and Access now work for it there.

**Mail from slaves.** When an admin account is created or replicated and nobody else is set to receive its mail, the
mail goes to the tenant's alert recipients (Home › Alerting).

**Department owners show at once.** An owner saved on the Departments page now shows on Admin accounts straight away.

**Create an admin account from the Create access page.** The page now has a card that opens the same wizard as
**+ New admin**. The card next to it gives an existing admin access.

**Errors you can see.** The Engine logs & errors menu item shows a red count of failed runs nobody has acknowledged.
Failed runs are listed first, and the page never shows "Nothing is failing" while a run has failed. The Jobs page lists
failing jobs first, and an approved policy hold no longer shows as a blocker.

**Policy errors you can act on.** When Microsoft Graph rejects a policy rule with only "The policy rule is invalid", the
run log now also shows the rule the engine sent, the rule as it is set now, and Graph's request ID. The difference
between the two rules is the value Graph refused.

## v2.4.390 — approve all held policy changes in one go, and the approval sticks

**Approve all.** The Approvals page now shows every policy change the engine is holding — PIM for Groups, Entra
roles and Azure roles — with one summary and one **Approve all** button. After you approve, the policy jobs start
straight away.

**An approval sticks.** An approval used to cover only the exact change set you saw, so a single new group created
before the next run made it void, and the change was held again. Now an approval also covers later runs, as long as
they don't weaken anything you haven't approved. A weakening you haven't seen, such as loosening a policy someone set
by hand, is still held for you.

**Clearer screens.** An approved change shows as "approved — applies next run" on the Jobs page instead of as a
blocker. Each weakening policy is listed with its change, the WhatIf lists the affected policies one per line in
readable form, and the confirmation says in plain words what happens next.

**Admin names are checked without regard to case.** `adm-e-abcd-t0-c` now matches a convention written as
`…-T0-…`. The warning shows the name the convention expects for that row.

## v2.4.389 — one mail per held policy change, and approve it from the Approvals page

**One mail per hold, not one per run.** When a run would change more policies than it may change at once, it holds
the change and asks for approval. It used to mail on every run, and each mail named a change set that was already
out of date by the next run. Now a hold is mailed once. It is mailed again only if it starts weakening more
policies, or once a day while it still stands.

**Approve it where you read it.** The mail now points to **Reviews & controls › Approvals**, which always shows the
change set that is held now. **Approve this change set** sits at the top of the hold. Each affected policy is listed
once, in its WhatIf group; the technical rule list is folded away.

**Less text on the Policy templates page.** One line of introduction, a folded *How templates work*, and one card for
the default template per kind.

## v2.4.388 — one ring order everywhere (0 dev, 1 test, 2 broad), and tags live on the ring

**The rings now run the way you expect.** Replication rings used to run the opposite way from the software update
rings, where ring 0 already goes first. Both now use one order: **0 = dev, 1 = test, 2 = broad**. A new administrator
starts on ring 0 and reaches only the dev tenants. Promote them to ring 1 to add the test tenants, and to ring 2 to
reach every tenant. Template roll-out waves use the same order. Nothing changes for what you already have: every
stored ring is converted once on upgrade, so each administrator, group and tenant keeps reaching exactly what it
reached before.

**Tags belong to the deployment ring, not the administrator.** The Managed tenant registry page has a new
**Deployment rings** card. Name each ring there, and narrow a ring with a tag rule if you need to — for example
*test = only the tenants tagged `wave:pilot`*. The card shows which tenants are on each ring and whether they match
the rule. The tag boxes are gone from the new-admin wizard, the admin editor and the Replication section of every
wizard. They keep only Replicate and Ring. A tag already set on an administrator is kept, still applied, and shown so
you can move it to the ring.

**Managed tenants on an older version keep working.** A tenant that reads a set published before this version, or
whose pull job was set up before it, converts the old ring numbers itself.

## v2.4.387 — policy templates: every setting on show, editable with dropdowns

**See each setting.** Opening a policy template shows every setting it makes, one per line with its value, for the
policy and — on a group template — the owner's policy. Settings that cannot be changed here (approval, and anything
asked when an administrator assigns access) are shown too, with the reason.

**Edit with dropdowns.** A SuperAdmin presses *Edit* on a template and changes how long an activation, an eligible or an
active assignment may last, whether an assignment must end, what an activation asks for (MFA, a justification, a
ticket number) and who is notified by default. Only what you change is saved. Saving changes the template, not the
policies: the engine plans the change, and a change to many policies waits for your approval with its WhatIf.

**See exactly where a template is used.** *Used by* now lists every delegation — the ones that name the template and
the ones that get it as the default — and leads with the total. Templates are listed by kind, standard before
approval-required.

**Every admin has a UPN, and an import never removes a super admin.** An admin row without a user principal name is no
longer accepted: the import fills it in from the tenant's domain (or refuses without one), the Manager flags any that are
already stored instead of hiding them, and an import can never overwrite or remove the Manager's super admins or the
break-glass accounts.

## v2.4.386 — held policy changes on the Approvals page, and every group name follows your pattern

**Approvals are where you look for them.** A policy change that is held for approval is now listed at the top of
*Reviews & controls › Approvals*, with the change setting by setting and the Approve button — as well as under
*Jobs › Engine logs & errors*.

**Clones and re-added definitions follow your naming.** Cloning a group names the clone by your current group
pattern, filled with the source group's department and tier, instead of editing the source group's name. The
*Re-add definition* fix suggests the name your pattern gives.

**Groups scoped to an administrative unit follow their own pattern.** Once you change the administrative-unit group
pattern from its default, a permission group granted inside an administrative unit is named by it, with
`{AdminUnit}` and the group's role part. With the default pattern, nothing changes.

## v2.4.385 — names follow your naming conventions, and a held policy change shows exactly what it would do

**Group names use every variable in your pattern.** A group pattern such as
`grp-e-PIM_{Department}_{Role}-T{Tier}{Platform}` used to keep only the role part: the tier, the department and
the environment suffix were dropped, and an empty department left a double underscore behind. Every variable is
now filled from what the wizard knows, and one you leave empty disappears cleanly with its separator. Patterns
that only use the role part give exactly the names they gave before, and existing groups keep their names.

**The values that were built in are now settings.** The tag prefix and administrative unit of each group type,
the administrative units of permission groups, the service names at the start of a permission-group tag and the
name of an administrative unit the wizard creates are all in *Settings › Naming › Group naming values*, with
the old values as defaults. Permission groups follow your permission-group pattern once you change it from the
default. New variables: `{GroupTypePrefix}`, `{ShortName}`, `{Service}`, `{Name}`, `{Domain}`, and for admin
accounts `{Company}` (for example `KONS-{Company}-{Initial}-T{Tier}-c` for consultants), `{Tier}` and `{Level}`.

**Variables work inside a prefix or suffix,** such as an admin-type prefix `adm-{TenantCommonName}-`. Before,
the same setting could produce different names from one run to the next.

**The naming page is easier to use.** Wider fields, the prefix card moved above the patterns, the default admin
type and environment are dropdowns, every setting explains what it does, and the suffix column says it is
`{Platform}`. The admin wizard offers your own admin types and environments and starts on your defaults, and it
uses your display-name suffix. A saved naming change reaches the wizards without reloading the page.

**A held policy change shows its impact before you approve it.** When a run would change more policies than the
safety limit allows, the approval panel now compares each policy's current settings with the new ones, setting by
setting (*"Activation: maximum duration 8 hours → 4 hours"*), marks each as tightening, loosening or neutral, and
groups policies that receive the same change.

**Clearer job results.** A held change is reported as *needs approval* with its approval command, even when
something else in the same run fails. A role name that does not exist in your tenant names the closest real role
and the row that uses it. *Run now* shows its result on the job you pressed.

**Readable alert mails.** The mail for a held policy change now says in one sentence what happened, lists the
policies grouped by the change they would get, shows each setting as current → new, and tells you how to approve
it. You get one mail per held change instead of two, and the approval command in it is no longer cut short.

**Fixes.** Saving the naming table no longer erases the admin word and tenant common name. An admin account with
a UPN suffix no longer gets the domain twice. The alerting page no longer says no sender is configured while
alerts are being delivered.

**Upgrade note.** If you saved *Settings › Naming conventions* on 2.4.382–2.4.384, check that your admin word
and tenant common name are still set.

## v2.4.384 — the records screens stop calling themselves files, and policy templates can be edited

**Your records are called what they are.** Every record type was still named after the file it used to
live in — `PIM-Assignments-Roles-AUs` and the like — and the screen even called the list a "file list".
They now read as what they hold: *Entra roles scoped to an administrative unit*, *Who gets which group*,
*Administrator accounts*. The underlying name is unchanged and is shown if you hover, so nothing you
have scripted or exported moves.

**There is an Edit button.** You could always change a value by clicking the cell, but nothing said so
and the only thing offered was a red Delete. Edit is now the main action and takes you straight to the
first field on the row.

**"Delete" said the wrong thing, so it no longer says it.** Removing a row never revoked anything: it
takes the entry out of the desired state, and the group and the access it grants carry on exactly as
before — just unmanaged. The button now says **Stop managing**, and the confirmation explains it and
points at the way to actually remove access.

**Searching explains itself.** The box above the record list filters the *list of record types*, not
what is inside them — so searching it for a person or a role found nothing, with no hint why. It now
matches the names you can see, and when nothing matches it says which search you want and takes you
there with your text.

**Policy templates can be changed.** The templates page was read-only, so the values customers most
often want to tune — how long an activation, an eligibility or an active assignment may last — could not
be changed here at all. Each template now has editable maximum durations. Approval and sign-in
requirements stay read-only by design: one of them, if set on the eligible path, causes your directory
to reject every eligibility this product creates. Changing a duration changes what the engine enforces,
so the page says so, and your next automatic update will ask you to confirm it before rolling.

**The template rollout page speaks plainly.** *Gap*, *OutOfRing* and *Drift (extra)* are now *Missing*,
*Not due yet* and *Extra*; *Entry key* is *Required permission*; the rollout column is *Wave*, so it no
longer collides with the update ring shown on the same screen; and "behind 8" reads as "8 newer versions
approved".

**Menu wording corrected.** One menu entry promised that nothing new is created on its page, while two
of that page's four cards create groups and administrators. It is now named for what it does.

## v2.4.383 — the admin-domain list actually lists, the unattended updater checks desired state, and two layout faults

**The admin account domain is a real list again.** On a tenant with many verified domains the picker
offered a single option whose name was every domain run together, and the page said it had found one
domain. The domain list is now normalised whatever shape it arrives in, and a name that could not be a
domain is discarded rather than offered.

**The unattended update now refuses to change what the engine wants.** Updates that install themselves
overnight rebuild the product from the approved source and roll it. If that release changes the
activation-policy baseline, the engine starts applying the new policy to every managed scope within
minutes. That check existed only for updates driven from an operator''s machine. It now runs where the
update actually happens: the update stops, reports exactly what would change, and names the setting an
operator sets on that environment to accept it. An update whose policy baseline is unchanged — the
normal case — is unaffected, and a check that cannot run never blocks an update.

**Records tables show all their rows again.** A table with hundreds of rows was cut off at the height of
the window with no way to scroll. Every row was always loaded; the page simply clipped them.

**Admin accounts fits the screen it is on.** The table was pinned to a fixed width, so on a wide display
it sat in a narrow column — names, dates and buttons wrapping onto extra lines — with most of the screen
empty beside it.

## v2.4.382 — the engine never replaces one assignment type with the other, and never plans from an incomplete read

**A delegation may be both Eligible and Active, and PIM now leaves it that way.** Until this release, a
row asking for one assignment type while the other type was live was treated as a *replacement*: the
engine deleted the live assignment and created the other one. That is wrong — holding the same
delegation as Active in one place and Eligible in another is a normal, supported design, not a mistake
to be corrected. The engine now simply creates what a row asks for and leaves every other assignment
alone. **The only thing that removes an assignment is a row you marked for removal and committed.**

**No plan is ever made from a live read that did not finish.** Three places read the live state, and
each of them used to keep whatever it had managed to collect when a read failed part-way — then compare
it as though it were the whole tenant. An assignment that was simply missing from that short read looked
like something to change. All three now discard an incomplete read, say so, and leave the affected area
untouched for that run rather than acting on a half-picture.

**A removal you asked for is never quietly dropped.** A pending removal whose target could not be seen
used to count as "already done" and was deleted from your desired state — so on an incomplete read, a
removal you had committed could disappear without ever being carried out. It is now kept and retried.

**Upgrade note:** if any of your rows ask for an assignment type that is not live, the first run after
upgrading will CREATE it (and keep the existing one). Nothing is deleted. If you do not want both, mark
the one you want gone for removal and commit it.

**The "removal blocked" email is rewritten.** It now opens with the fact that nothing was changed, says
what the blocked items actually were, explains the per-run safety ceiling in plain words instead of
repeating an unexplained number, and ends with one instruction. It also renders in the right typeface —
the previous version fell back to a serif font in Outlook.

**Run log: a Copy button**, which copies the whole log including the part scrolled out of view and
confirms how many lines it took. **"Live tail"** now explains itself and is switched off, with the
reason shown, on a run that has already finished — previously it accepted the click and silently
un-ticked itself two seconds later.

**Naming is yours, and the product no longer guesses it.** Your naming conventions live in the database,
where you edit them — they are seeded once when a new environment's store is created and never overwritten
afterwards. If they are missing, the engine now **stops and says which setting is absent** instead of falling
back to built-in defaults: silently renaming the admin accounts and groups an environment already has is the
one mistake that cannot be undone. Nothing is read from a configuration file any more.

**Name your admin accounts whatever you call them.** The admin word is now a proper field in Settings →
Naming — `Admin`, `adm`, anything — and it is honoured everywhere, including the high-privilege pattern and,
importantly, the matching that decides which live accounts PIM manages. Previously a non-default word could
leave PIM unable to recognise its own admin accounts, which meant creating them again on every run.

**One naming template for every tenant.** A new `{TenantCommonName}` variable holds the short name of the
tenant (for example `EFIF` or `RIDE`), so a single pattern serves every customer instead of the name being
written into the pattern itself. Leave it blank and it disappears cleanly — existing names are unchanged.
Both fields sit together in Settings → Naming with a live example, and every supported variable is listed,
with its meaning, in the click-to-insert legend beside the pattern fields.

**Clearer labels.** The AD OU placement fields are now "AD OU (Day2Day Admins)" and "AD OU (High Priv
Admins)", and the card says plainly that it is optional and only for tenants with on-premises Active
Directory.

**Pick the admin account domain from a list.** Settings → Admin account domain offers this tenant's
verified domains as a dropdown, and it now actually has something to offer. Two separate faults left it
empty: the domain list was read from a single place that needs a permission not every deployment has
been granted, and whatever was read could never be cached, so a later page load started from nothing. The domains are now also read from the tenant's organisation record, which needs only the
permission the page already uses, the cache works, and when there is still nothing to show the page says
**why** and offers a **Re-read**. The number of domains found is shown, so an empty list reads as a fault
to fix rather than "this tenant has one domain".

**Register your licence in the portal.** Settings → Licence now has **Register a licence**: pick the
issued file or paste its contents. Previously the only documented way was a command line that needs the
deployment's own database credentials, which most customers do not have. Your file is checked against our
signing certificate **before** anything is stored — a file that does not verify is refused, nothing is
written, and the page says so. The command line is still there for whoever prefers it, and the page now
explains that the application id and certificate it asks for are **your** deployment's, not ours.

**MSP Downlink cannot be switched on where it cannot work.** On a single-tenant deployment the feature
toggle was live, so the tab could be turned on with nothing behind it. It is now locked off there, with
the reason shown; the refusal is in the server, not only in the checkbox.

**The edition page no longer says enforcement is off.** It said every advanced feature was free because
enforcement was switched off. That stopped being true when Pro enforcement shipped: the Pro features
listed under Licence are checked against your installed licence. The text now says what actually happens.

**Licensing corrections.** A licence whose edition reads "Core" no longer unlocks Pro features; Pro means
Pro. Delegated administration is a Pro capability and is now enforced wherever a delegated administrator
is resolved, not only where one is created — without a licence such a user is a reader. The Exchange
Online connector has been removed from the feature list: no version of the product applies it yet, and
listing it offered a capability that does not exist.

## v2.4.381 — Defender XDR role assignments fixed (for real), and the Templates cards adopt existing groups

**Defender XDR role assignments are created.** The v2.4.380 fix did not solve the problem: every new Defender XDR role assignment was still refused by Microsoft ("The roleAssignment field is required"). The cause was a type annotation in the request that the service rejects, even though Microsoft's own example includes it. It has been removed. Microsoft answers a successful assignment with a redirect that cannot be followed securely, so the assignment is now read back by group and role, and it counts as failed only when it cannot be found. After upgrading, the next engine run assigns every Defender XDR group that is waiting for its role.

**The Templates cards adopt existing groups.** Importing a permission template from the portal now plans exactly as the import script does. A pack group that the environment already defines, under the same name or an older tag, or in another group type, is adopted instead of being offered a second time, and the card says how many groups it adopts. Before, the portal could offer duplicates of groups the environment already had.

## v2.4.380 — groups always deployable, workload assignments held per workload, templates imported by script, Defender assignments fixed, and the Pro edition enforced

**Groups are always created; only the workload role assignment waits.**
- A permission group is created whether or not its workload is ready.
- A *new* Intune, Defender XDR, Power BI or other workload role assignment is held while that workload's prerequisites are not green (failed, incomplete or never checked). The run reports it as held, with the command to run, and it is assigned on the first run after the prerequisites turn green.
- Azure role assignments are held only when the prerequisite check ran and found a problem, never merely because it has not been run.
- Existing assignments, removals and updates are never held.
- Staging is never blocked: the Templates cards, the wizards and Coverage & gaps show an amber note where an assignment will wait.

**Import permission templates by script (infrastructure as code).**
- `Import-PimPermissionTemplate.ps1` imports named packs into an environment. It adds only what is missing, names groups by that tenant's own convention, keeps a group and its workload role together, takes a snapshot before every change and audits it. A second run changes nothing, and `-WhatIf` shows the plan.
- A pack group that the environment already defines, under the same name or under an older tag, is **adopted** instead of being defined a second time.
- `Invoke-PimTenantPrep.ps1 -Config` prepares many environments from one configuration file: the workload prerequisites with the options you choose, then the packs. One environment's failure does not stop the others, and it ends with a summary per environment.

**Defender XDR role assignments work.** An assignment now carries the directory scope Microsoft requires, and a newly created custom role is read back by name when Microsoft answers with a redirect.

**Licensing: the Pro edition.**
- **Free:** everything for a single tenant, including Entra ID roles, PIM for Groups, administrative units, Azure RBAC, Intune and Defender XDR, policies, drift, the wizards and the template import.
- **Pro, single tenant:** Coverage & gaps and discovery, the Power BI / Exchange Online / app-role / Azure DevOps / Dataverse / Business Central / Power Platform connectors, revoking current delegations, access review campaigns, the second approver, delegated administration scopes, the tier-impact report and the evidence export.
- **Pro, multi tenant:** MSP managing and managed tenants (publishing, downlink, replication and the fleet views).
- Without a valid Pro licence bound to the tenant these features are off in the engine, the jobs and the portal, which says why. **Settings › Licence** shows the licence status and the command to register a licence file. For a licence, contact mok@mortenknudsen.net.

**Workload prerequisite script.** `-EnableSentinel` (opt-in) enables Microsoft Sentinel on a dedicated, empty security workspace, registering the Sentinel resource providers first. The Power BI and Data Operations checks read the right values.

**Upgrade note.** Install your Pro licence **before** upgrading if you use MSP or any Pro feature listed above. Otherwise those features stop at the upgrade. Run the workload prerequisite script once for Intune, Defender XDR and Power BI, or their new role assignments are held.

## v2.4.379 — two policy templates per kind with stable ids, per-kind defaults, and template imports gated on green prerequisites

**Policy templates: one Standard and one RequireApproval for every kind.**
- **PIM for Groups:** `Groups_Standard` and `Groups_RequireApproval`, formerly `default` and `approval-required`.
- **Entra ID roles:** `EntraIDRoles_Standard` and `EntraIDRoles_RequireApproval`, unchanged.
- **Azure roles:** new `AzureRoles_Standard` and `AzureRoles_RequireApproval`. Azure roles used the Entra ID templates until now; `AzureRoles_Standard` has exactly the same rules, so nothing changes in your tenants.

**Stable ids, so you can rename a template.**
- **Id and name:** every template has a fixed id and a display name you can edit on the Policy templates page (SuperAdmin).
- **References:** rows refer to the id, so a rename changes nothing that is applied.
- **Old references:** `default` and `approval-required` in existing rows keep working as permanent aliases. On first start your stored templates move to the new ids, keeping your changes.

**A default template per kind, in Settings.** The Policy templates page has one default for groups, one for Entra ID roles and one for Azure roles (SuperAdmin). A row without a template uses its kind's default. The shipped defaults match what was applied before.

**A template picker wherever you delegate.**
- **Where:** every delegation wizard and the grid's PolicyTemplate column, for groups, Entra ID roles and Azure roles.
- **What it offers:** only templates of the right kind, with "Use default" showing the current default.
- **New:** the Project and Role-group wizards gained the picker, and the Departments, Organization, Projects and CrossOrg grids gained the column.

**Permission-template imports are blocked until the workload's prerequisites are green.**
- **The rule:** a pack whose workload prerequisites are red or amber (failed, incomplete, never checked, or older than 30 days) cannot be imported.
- **What you see:** the card says why and gives the command to run.
- **Packs with no prerequisite workload** are not affected.

**Workload prerequisite script.**
- **`-EnableSentinel` (opt-in):**
  - **What it does:** enables Microsoft Sentinel for the Defender Data Operations roles, on a dedicated security workspace that it creates empty when missing.
  - **Prerequisites it handles:** it registers the Sentinel resource providers first.
  - **What it refuses:** PIM's own log workspace, where Sentinel would bill every log line.
- **Power BI:** the engine identity's membership of the admin-API group is now read correctly. A managed identity was missing from the plain member list, so the check reported "not added" although it was.
- **Replication delay:** a newly created group is read back with retries.
- **Data Operations:** the permission check reads the permission id, not its display name. The guidance now says Data Operations follows Microsoft Sentinel.

**Upgrade note.** The first start of this version renames the stored group policy templates to their new ids. An environment rolled back to an older version afterwards cannot find `default` and skips group policies with a warning; it changes nothing. Upgrade forward.

## v2.4.378 — coverage and gaps across every workload, Defender roles managed end to end, and your MSP registry in the Manager

**Coverage & gaps: one page for what is delegated and what is not** (Reviews & controls).
- **Covers:** Entra ID roles, Intune, Defender XDR, Power BI, Azure subscriptions and management groups, and PIM for Groups.
- **Status:** each item is *covered*, a *gap*, an *orphan group*, an *unmanaged binding*, *wrong permissions*, an *unmanaged privileged group*, or *not checked* (with the reason).
- **Proposals:** every gap comes with a ready proposal (the group and its role, named by your own convention), all ticked. Stage the ones you want into Pending changes.
- **PIM for Groups:** groups that PIM for Groups manages but PIM does not define (for example one gating an HR application) are shown for review with what they grant, and are never adopted automatically.
- **Updates:** the page is refreshed by a scheduled check, and new gaps are mailed.

**Defender XDR custom roles, managed by PIM.**
- **Defining a role:** a Defender binding can carry the role's permissions and data sources.
- **What PIM does:** it creates the custom role named like the group, corrects its permissions when they differ, and assigns it with the right data sources. It reports a role whose live permissions differ as *wrong permissions*.
- **Defender template v3:** the Data Operations Operator and Reader groups, internal's Scope-Clients / Scope-Servers variants with their data sources, and the Security Posture Operator with posture (not security operations) permissions.
- **When a tenant is not ready for Data Operations:** a role that needs Microsoft Sentinel connected to the Defender portal says so, and names the prerequisite script, instead of a bare Graph error.

**A group and its workload role are imported together.** In a permission template, ticking a group ticks its role and the other way round, and an import never takes half of a pair. A new workload group is held back, never left without its role, while that workload's step is turned off or cannot be read.

**Defender and Intune discovery.**
- **The jobs:** new scheduled jobs read the live Defender and Intune role catalogs, and Microsoft's Defender permission catalog.
- **What they report:** new roles and new permission groups that no template covers.
- **Live orphan warnings:** a workload group with no role, and a role held by a group PIM does not define, are warnings on the drift page. A hand-made role assignment is shown for review and does not count as drift.

**Workload prerequisites.**
- **The script:** `Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr|Intune|PowerBI|AzureRbac|EntraRoles` checks each workload's prerequisites. It fixes what an API can fix and gives the exact portal step for what only a person can do.
- **In the Manager:** every template card, the workload wizards and Coverage & gaps show a chip: green when the prerequisites were checked OK, amber when never checked or stale, red when something is missing. Each chip carries the command to run.

**Managed tenant registry and replication overview** (MSP master).
- **Managed tenant registry:** a page to register and edit your managed tenants (name, the master's copy of the ring, tags, enabled), instead of a setup script. The script and the page now share one writer.
- **Replication overview:** lists every direct group, permission group, nesting, role binding and admin you replicate, with the tenants each one reaches. It is computed by the same plan every tenant runs. Filter it by tenant to see exactly what one customer gets.

**Policy templates.**
- **The page:** Audit & Settings → Policy templates lists every activation policy in plain words, with the delegations that use it.
- **The delegations table:** it now has a policy column, so a delegation can be switched to a template that needs approval.
- **Owners on Azure delegations:** these now take effect.

**Fixed: Azure permission groups were never created.** The Azure wizards added the Azure role assignment without the group's own definition, so the engine could never create the group. The group definition and its assignment are now added together, as in v1. *Check for problems* now warns about an Azure delegation whose group is defined only by a discovered-resource row, because the engine never creates that group.

**All three policy types in every wizard.**
- **What the wizards now offer:** you choose the group's activation policy, and for an Entra or Azure delegation also the Entra role or Azure role activation policy. Each list shows only the policies of its own type.
- **In the delegations table:** all three can be changed for existing delegations.

**Also in this release:** workload groups stay connected to their workload, and "not checked" is never "in sync" (below).


**A workload group and its role belong together.**
- **The warning:** a group meant for Intune, Defender XDR or another workload now gets a warning when its role in that workload is not set up. It appears in *Check for problems* and on the engine job.
- **The same check runs the other way:** a workload role given to a group that PIM does not define is flagged too.
- **When the Intune or Defender step is turned off:** the engine says so, naming each group that is left without its role.

**Intune template, version 2.**
- **Contents:** the six classic roles plus Endpoint Privilege Manager, Endpoint Privilege Reader, Intune Role Administrator and Multi Admin Approval Policy Manager, on the WDP plane.
- **Levels:** managers and administrators L3, operators L4, readers L5.
- **Each group comes with its role:** every group ships together with its Intune role assignment, so an import never creates a group that holds nothing.
- **Not included:** Cloud PC, Windows Autopatch and Organizational Messages roles. They are not Intune roles (they use their own role systems), so they were left out rather than shipped as groups that could never receive their role.

**"Not checked" is never "in sync".**
- **On the drift page:** an area that was skipped (the feature is off) or could not be read (no permission) now shows *not checked* with the reason, instead of counting as in sync.
- **In the engine:** an Intune or Defender read that is refused now fails that area rather than planning changes on a blind read.

**Your naming convention, everywhere.**
- **The fix:** names built for discovered Azure, Power BI and Power Platform resources, template imports, the portal's group facets and group retirement now follow the tenant's own group-name pattern instead of assuming `PIM-`.
- **Safer workload binding:** a workload connector no longer falls back to a partial name match that could bind the wrong group.

**The replication preview and what is actually sent now agree for admins.** An admin with no management mode stays on the master tenant. It is shown that way in the preview and listed under *not published*, instead of being previewed as replicated but never sent.

**Defender XDR discovery works.** It now reads Defender roles from the right Graph API version. A read that fails is reported as a failed job, instead of looking like "no roles".


## v2.4.377 — admin account domain per tenant, and the engine now uses your naming

**Admin account domain, per tenant.**
- **The setting:** **Settings → Admin account domain** is a dropdown of this tenant's verified domains. The default is *Tenant default domain*, which is what v1 did.
- **Who uses it:** the engine, the New admin account wizard and managed tenants all use this one value.
- **On a managed tenant:** admins replicated from the MSP master are created at the managed tenant's *own* admin account domain. The master's domain is never carried over.
- **In the wizard:** the New admin account wizard defaults its UPN suffix to this setting and lists the verified domains. On an MSP master it explains that a replicated admin gets each managed tenant's own domain.

**Fixed: the engine ignored your naming conventions.**
- **The bug:** naming set in Settings (group and admin name patterns, the admin domain) reached the Manager but not the engine. Names the engine builds itself, for example for discovered resources and hybrid AD accounts, used the shipped defaults.
- **Now:** the engine reads the same settings the Manager shows.

**Fixed: imported v1 admins showed as "not defined".**
- **The bug:** the validator looked admins up only by their full sign-in name. A v1 admin row has only a user name; the domain is added when the account is created. So every membership of an imported v1 admin was refused as *not defined* and blocked Commit, although the admins were stored.
- **Now:** the validator matches an admin by user name as well as by full sign-in name, the same way the engine does.
- **The import check:** it no longer fills in a stand-in domain, so it sees exactly what the Manager sees.

**Fixed: revoking an Entra role that was not assigned through PIM.**
- **The bug:** revoke always asked PIM to remove the assignment. A permanent assignment made outside PIM (v1, the portal, or the older API) has nothing for PIM to remove, so the revoke failed with *The Role assignment does not exist* and the role stayed.
- **Now:** revoke first reads what is live:
  - **Assigned through PIM:** removed through PIM, at its real scope.
  - **Permanent:** the assignment itself is deleted.
  - **Held through a group:** refused, pointing at that group.
  - **An activation of an eligible assignment:** refused, pointing at the eligibility.
- **The result:** the queue entry says which kind of assignment it was.

**Every wizard says whether a row is replicated.** On an MSP master, the Replication section is unchanged. On a managed tenant, each create wizard now shows a short note: *Local to this tenant — not replicated*.


## v2.4.376 — replication that reaches its tenants, plain words, and pages instead of anchors

**Fixed: a group set to *Replicate to managed tenants* reached no tenant.**
- **When it happened:** the master replicated no admin memberships yet.
- **What went wrong:** the managed tenant's plan skipped all group definitions in that case. Groups, nestings and role bindings set to replicate on their own were never sent, and the preview said "0 of N tenants".
- **Now:** they reach every tenant their ring and tags admit. The preview and the real pull run the same code, so both are fixed.

**Replication, in plain words.**
- **Options:** *Follow (default) — sent only when a replicated row needs it*, *Replicate to managed tenants*, and *No replication to managed tenants — master tenant only*. The duplicate Follow entry and the "MSP-local" wording are gone.
- **Rings say which way they narrow:** Ring 0 reaches every managed tenant, Ring 1 reaches rings 1 and 2, and Ring 2 reaches only ring-2 (pilot) tenants. Each tenant's ring is shown next to its name.

**Every menu item opens its own page.**
- **The change:** *Manager access & roles*, *Emergency access (break-glass)* and *Mail templates* are separate pages instead of links into Settings.
- **Emergency access:** the break-glass accounts and the emergency override share one page.
- **Renamed:** *Review standing access* is now **Review current delegations**.

**Wizards:**
- **Activation policy:** *Delegate a permission — Start here* now asks which activation policy the delegation uses (default, or a template, for example one that needs approval), like the advanced wizards.
- **Role-assignable is locked to Yes** for a permission group that grants an Entra ID role, because Entra refuses the role otherwise. The validator's Fix-all and the define-group dialog follow the same rule.
- **"Show roles that already have a delegation group"** now also counts delegations shown on the Delegation Map and ones you have just staged. It says so when the stored list could not be read.

**Importing v1 CSV files is checked first.**
- **The check:** `setup/Invoke-PimCsvImportCheck.ps1` validates a folder of v1 files before anything is written. It runs the same rules as the Manager's validator, plus file checks: encoding, delimiter, columns and duplicate keys. Engine state files are skipped.
- **The import:** `Migrate-PimToSql.ps1` runs the check first and refuses on any error. `-ValidateOnly` changes nothing. The import adds and updates by key and never deletes. A row that differs from what is already stored is refused unless you choose `-OnKeyConflict`.
- **Keeping rows on the master:** `-ForceLocal` imports everything as master-tenant-only.

**Process is a permission group.** It is no longer offered as a direct group, and the wizard dialogs no longer scroll sideways.

**Permission templates show what they add.** Each template card has a **Show** button. It lists every new permission (the group, what it grants and where), each with a tick box. **Import** stages only the ticked ones.

**Menu badges only count work that needs you.**
- **Pending changes:** the count disappears once you commit. Committed entries wait for the engine and are still listed on the page.
- **Review current delegations:** no longer shows its row count in the menu.

## v2.4.375 — break-glass needs two people, the emergency override works, and a tidier Manager

**Break-glass accounts need a second SuperAdmin.**
- **What it protects:** the break-glass list exempts accounts from being revoked, disabled or offboarded, so one person should never be able to change it alone.
- **How a change works:** saving now raises a *request*, showing the change, your justification and a 72-hour expiry. A different SuperAdmin approves or rejects it; you can cancel your own.
- **Checks on approval:** it applies only if the list has not changed in the meantime, and every step is audited.
- **Always on:** it does not depend on the optional maker/checker setting.
- **Only one SuperAdmin?** An environment with a single SuperAdmin uses the new operator script `Set-PimBreakGlassAccounts.ps1`, which is also audited.

**The emergency override works, and says what it does.**
- **What the card explains:** the passphrase is checked, then approval is switched off on the chosen groups within about a minute and their owners are notified. Nothing is granted: responders still activate through PIM. Approval comes back automatically at expiry.
- **Passphrase status:** the card now shows whether a passphrase is configured, and it is refused clearly when not.
- **Why it could not be used before:** the passphrase could not be read in the hosted Manager. That is fixed.
- **New operator script:** `Set-PimEmergencyPassphrase.ps1` stores only a hash of the passphrase in your key vault and connects the Manager to it.

**A tidier Manager:**
- **All records** now has a compact entity list with a filter, and the table uses the full width.
- **Departments & owners** has its own page under Access, instead of being buried in Settings.
- **Approvers / owners removed:** that separate list was never used. Approvals always come from the department's owners. Anything stored in it is shown once on the new page.
- **Organisational dimension removed:** that Settings choice is gone. Departments, organisations and projects are their own group types, and role groups are always called role groups.

**Upgrade notes:**
- To use the emergency override, choose a passphrase and run `Set-PimEmergencyPassphrase.ps1` once per environment.
- To change break-glass accounts in the Manager, make sure each environment has at least two SuperAdmins.

## v2.4.374 — missing admin sign-in methods are a warning, not a blocker

Since v2.4.370 the Manager has checked each administrator's registered sign-in methods against the tenant.

**The problem:** an administrator with no strong method yet, typically a newly created account that has not used its temporary access pass, was reported as an **error**. Validation errors block every commit, so a normal new-admin situation blocked all changes on the environment.

**The fix:** both checks — "no required method" and "only weak methods" — are now **warnings**. They still appear on Validate, and they no longer block a commit. They describe the live directory, not the data you are saving, and nothing in the grid can fix them.

**Upgrade note:** none.

## v2.4.373 — one rule for disabling an admin, PIM-eligible Azure connector, and a hardened image

**Security:**
- **Disabling an administrator needs a second person on every path.** Saving a grid change that would disable an admin now holds only that change and raises an offboard approval instead of disabling the account on the next run. The trigger is AccountStatus Disabled or Revoked, a retire lifecycle, or a disable date that has already passed. The rest of the commit is saved as normal. The Manager shows what was held and lets you raise the approval. This is the same rule the account editor already follows.
- **The Azure RBAC workload connector now creates PIM-eligible assignments.** It used to make permanent Azure role assignments outside PIM. Every shipped connector on a PIM-capable surface now creates eligibilities.
- **The container image runs as a non-root user,** and its base images are pinned by digest.
- **A master can publish a signed central-kill manifest.** Managed tenants already honour one. The new operator script signs it with the master's own key, and it can also withdraw one.

**Other:**
- **New environments** now use the scheduled (cron) job model by default. An existing environment that already runs always-on workers keeps them.
- **App Service text removed:** the DNS guidance no longer mentions App Service, whose hosting path was retired.
- **Faster test suite:** the whole offline suite now runs in about 7–10 minutes, down from about 30, with every assertion kept.

**Upgrade note:** the image now runs as a non-root user. If you point log or sync folders somewhere other than the defaults, make sure that user can write there.

## v2.4.372 — you control how often managed tenants update, and escalation mail is safe

**Update cadence is now set in the Manager.**
- **Managed tenants:** the Job schedule shows **Managed-tenant pull**, with an on/off switch, an interval from 5 minutes to a day, and **Run pull now**.
- **Masters:** it shows **Publish to managed tenants**, with the same controls and **Publish now**.
- **Where it lives:** each environment keeps its own setting in its own database. Nothing is set centrally.
- **Publish on commit:** when you commit a change on a master that is replicated to managed tenants, a publish is requested automatically. Managed tenants can pick up a change within minutes instead of the next day.
- **Unchanged until you change it:** an environment with no setting stays on the daily cadence.
- **Failures:** a failed run is retried sooner, then backs off.
- **Least privilege:** the publish job reads and writes only its own schedule rows.

**Lifecycle escalation mail is safe to leave on.**
- **Alert setting:** escalations follow your alert setting for expiring access. When it is off, nothing is sent.
- **Mail off or no sender:** a turned-off mail switch or a missing sender is reported as held, not as a failed job. The mail goes out once mail is enabled.
- **No backlog storm:** the first run after upgrading records what is already due without mailing it, so nothing arrives all at once.
- **Reminder cap:** at most one reminder per stage, and none after the date has passed.
- **Recipients:** mail goes to the owners of the sponsor department.

**Other fixes:**
- **Workload delegations:** a delegation with several workload roles is refused with a clear message (one role per delegation). It used to keep only the last role silently.
- **Replication rings:** any whole number is now a valid replication ring. The validator no longer "fixes" a valid ring 3 down to 2.
- **Ring labels:** on a master, the ring shown for a managed tenant is labelled as the master's copy. The managed tenant's own ring decides.
- **Tenant-list refresh:** the Manager's refresh no longer reports a failed step it could not run.
- **Stale secrets:** redeploying a managed tenant's pull job removes secrets it no longer uses.
- **Job status:** a job that does not apply to an environment is shown as skipped, not as a clean run.

**Upgrade note:** after upgrading, each pull and publish job runs once and then follows its schedule. The default is daily from that moment, instead of at a fixed hour. Set the interval you want in the Manager's Job schedule.

## v2.4.371 — no false removal alarms, and the managed-tenant pull works again

A corrective release for two problems that appeared once v2.4.370 was running. Nothing was removed, disabled or
deleted by either one.

- **A plan never raises a removal alert.** v2.4.370 fixed the safety alerts so that they are really sent. The nightly
  read-only convergence check (a plan, which never changes anything) counts the live items that are not in the
  desired state and runs them past the removal budget. It therefore mailed an "engine failure: removal budget
  tripped" alert about a run that could not remove anything. A plan now only logs that finding. The alert is kept for
  real runs, where the budget actually holds changes back.
- **The managed-tenant pull no longer refuses when it cannot read a kill switch nobody configured.** By default the
  pull looks for a central kill manifest next to the bundle. On a bundle store that is not publicly readable, that
  location answers "unauthorized", and v2.4.370 treated that as "a kill might be in force" and refused every pull. It
  now reports the check as not performed and says how to enforce it. A kill location you configure explicitly is
  still checked strictly.
- **The update-ring tools read the ring channel correctly** when it is served as a binary download. Before this, the
  drift check, the sync and the updater installer reported "nothing approved".

**Upgrade note:** none.

## v2.4.370 — a full code review, and every finding closed

This release is the result of a line-by-line review of the whole v2 product. It closes every finding that review
produced. Most changes are about **safety features that must never quietly do nothing** and about **data that must
never be lost by an edit**. It is recommended for every installation. Read the upgrade notes at the end. A few
changes make the product refuse something it used to allow, and they say so when they do.

**Security**
- **The Manager page can no longer be made to run injected script.** Names written into desired state (group,
  account, administrative unit or tenant names) are now escaped before they are placed in the page, so a crafted
  name cannot run script in another administrator's browser.
- **A hosted Manager trusts identity only from a real sign-in layer.** On hosts with no sign-in layer in front, the
  identity headers are refused, and a request with no signed-in user gets *401 sign in required*. It used to get
  read-only access. A new Manager is created closed and opens only after its sign-in is configured and verified.
  Sign-in now also requires an explicit choice of who may use it: named people or groups, or all member users of
  the tenant (never guests).
- **An administrative-unit delegation stays scoped to its administrative unit.** The resource-delegation wizard
  now stages an AU-scoped assignment. It used to stage a tenant-wide one, and the engine now refuses a tenant-wide
  row that claims an AU scope.
- **Delegated (portal-profile) administrators see and change only their own slice.** The data grid returns only
  the rows in their scope. Their commit is merged into the full set, so rows outside their scope are never removed.
- **Two administrators editing the same data at once can no longer overwrite each other.** A commit made against
  data that changed since it was loaded is refused. You are offered a reload that keeps your staged edits.
- **Alerting webhook addresses are no longer shown to read-only users.** Bug reports sent from the Manager or the
  Activator no longer include your sign-in name, tenant id or raw error details unless you choose to include them.
- **Master→managed-tenant bundles:** anti-rollback is enforced on the scheduled pull, with the last applied version
  kept in the managed tenant's own store. A signing key can now be revoked. A central kill switch is honoured. The
  publisher now refuses to publish when it cannot read a projection table; it used to treat that as "project
  everything".
- **PIM Activator:** the extension's site access is narrowed to the Microsoft sign-in, Graph and Azure endpoints it
  uses, and its sign-in tokens are kept only for the browser session (the extension update ships separately).
  Deploying the Activator's browser policy no longer overwrites your organisation's own extension policies.
- **Least privilege in setup:** Exchange administration for the engine is activated through PIM and time-bound. It
  used to be assigned permanently. Root-level User Access Administrator is opt-in. The bundle publisher gets a
  read-only database user instead of database administrator. New installations create the SQL administrators
  group as role-assignable, and an existing group that is not role-assignable is reported as a security finding.

**Safety features that now do what they say**
- **Break-glass (emergency override) is applied by the engine.** While an override is active, approval is switched
  off on the scoped groups. When it expires, the linked policy is restored. Every step is audited.
- **Break-glass accounts are managed in the Manager** (Settings), stored in SQL and read by both the Manager and the
  engine. PIM never revokes, disables or offboards these accounts. If the list cannot be read, PIM protects
  everyone and says so. It never guesses.
- **The three safety alerts are really sent:** the removal budget, the account-disable circuit breaker and the
  policy mass-change hold. A failed send is recorded as failed.
- The offboard safety gate now applies every time, no matter which Manager page was opened first. Setting a
  disable date in the past now raises an offboard approval instead of disabling the account on the next run.
- Lifecycle escalations, the two authentication and activity checks, the ServiceNow intake and "Newly discovered
  resources" are all SQL-backed now, and they act on what they find. Access-review screens show real data or say
  *unavailable*. They never show sample data.
- Revoking sessions shows *queued*, not done. "Mark for manual removal" works. Guest onboarding invites the guest's
  real address, and failed invitations are reported.

**Your data**
- Saving departments in Settings keeps every other column of the department definition, including its ring,
  target and replication settings.
- Validation quick-fixes act on the row they name, including after an earlier fix removed a row. Staged edits
  survive a reload, and the pending-change badge counts real changes.
- Template approvals and ring promotions are stored in SQL. Deploying a template writes desired state for the
  engine to apply.
- Re-running the SQL migration can no longer delete rows added or edited in the Manager since go-live.

**Updates and rings**
- An environment with PIM deployed but no update ring configured is no longer rolled by host-side tools unless the
  operator names an explicit override *and* a version.
- The version drift check compares each environment with its own ring's approved version.
- A skipped smoke test is no longer treated as a pass.
- A deploy that would move an environment backward fails instead of printing a warning.
- The template catalog follows the environment's update ring. Customer-ring environments receive only fully
  promoted template entries.

**Removed** (unused, superseded or unsafe): the proof-of-concept engine container, the SAS-based bundle transport and
its helpers, the pre-v2 MSP and lab scripts, the App Service hosting templates, and the unused local-store tables
(existing tables are left in place; nothing is dropped).

**Upgrade notes**
- A **new** Manager is created closed until its sign-in is configured, and it needs an access choice (named
  principals, or all member users). Existing Managers keep serving behind their current sign-in.
- Environments rolled from the deploy host must carry an update ring. Every environment deployed with the current
  tools already does.
- Break-glass accounts set through the old environment variable still count. Move them into Settings when
  convenient.
- Every managed-tenant pull now checks for a central kill manifest; "not present" is normal.

## v2.4.369 — three screens that did the work and did not say so

This release is about **feedback**, not new capability. In each of the three cases below the product did
exactly what it was designed to do — and the screen did not tell you, so it looked as though nothing had
happened. Nothing was ever lost or wrongly applied. It is recommended for every installation that uses the
PIM Manager; nothing in the product's behaviour towards your directory changes.

- **"Revoke selected" on Review standing access now reports what it staged — and what it could not.** You
  could select rows, type a justification, press **Revoke selected** and get no staged change, no error and
  no message at all. Two things caused that. Some kinds of standing access — in particular Azure resource
  role assignments — were being handed on to the queue without the one detail that identifies the
  assignment to remove, so the queue refused them; and the refusal had nowhere to appear, because the
  button had no message of its own and any failure further in was silently swallowed. Now the full details
  of each selected row are carried through, every row is checked **before** anything is staged, and a row
  that genuinely cannot be addressed is **refused on its own, with the reason**, while the rest are still
  staged. A short status line sits **beside the button** and is written on every outcome — working,
  staged *N*, refused *N*, or the error in plain words. Opening the tab re-arms the button, so it can never
  be present, enabled and inert. The confirmation no longer claims the click removes access: it says the
  rows are **staged as pending changes** and that nothing is revoked until you commit.
  *Why it matters:* a bulk clean-up of standing access is one of the few screens where doing nothing and
  succeeding looked identical.

- **The change queue shows what you just committed, by default.** Commit a configuration or delegation
  change and it is saved immediately — but the list underneath was showing **open directory actions only**,
  under a counter describing those, beside a line reading "no configuration edits waiting". Everything on
  the screen was true and the whole read as *"my change vanished"*; you had to know to switch a filter to
  see your own commit. Now the page opens on **the queue and recent commits together, in one table**, with
  a **state** column that says which is which — a committed configuration change shows as **saved**, with
  *"saved to desired state · the engine applies it on its next run"*. The counter is computed from the rows
  actually shown and names anything it is hiding. The message you get after committing reports the
  server's own per-item numbers (added / removed / changed), says where it went and what happens next, and
  **stays on screen** — including after you press **Refresh**, which now adds to it instead of erasing it.
  The "nothing is waiting" line now separates *nothing is waiting to be committed* from *what you just
  committed is already saved, and listed below*. **Open queue only** is still available as a filter; it is
  simply no longer what you land on.
  *Why it matters:* the one screen you go to after a successful commit was the screen that made a
  successful commit look like a lost one.

- **The Manager shows which update ring the environment is on.** Until now the release ring that decides
  which version an environment may move to was only visible to someone who could read the update job's
  configuration — the Manager itself never said it. The ring now appears **beside the mode badge** in the
  header, marked only when it needs attention (behind, held, or the last update failed), with an
  **Updates & ring** panel under **Jobs** giving the version running now, the version that ring approves,
  the last update run and the last successful one. The nightly update records each of its runs — including
  the runs where it deliberately refused to move — into the environment's own database, and the Manager
  reads that. An environment that has not run an update since upgrading honestly shows **"not recorded
  yet"** rather than a guess, and a record older than two days is flagged as stale instead of shown as
  current. The panel is **read-only by design**: changing a ring stays a deliberate act on the environment's
  update job, and the Manager offers no control that writes one.

**Upgrade note:** none. The two Manager fixes take effect as soon as the new version is running. The ring
display fills in after the environment's update job has run once — until then it correctly reads
"not recorded yet".

**Interested in the licensed (multi-tenant) edition?** Mail **mok@mortenknudsen.net** for information.

## v2.4.368 — an environment never updates itself backward, and the update ring you configure is the ring you get

This release fixes two defects in the automatic update path of a hosted (subscription) environment. It
is recommended for every hosted installation. Nothing in the product's behaviour towards your directory
changes.

- **An automatic update never moves an environment to an older version.** Before it builds or rolls
  anything, the nightly update compares the version its release ring approves with the highest version
  the environment is known to have reached, and **refuses** to go backward — naming both versions, the
  ring that proposed the older one and the two ways out. It also refuses a target that is not a version
  number at all. A deliberate rollback is still possible, but only when it is explicitly switched on for
  that environment; it is off by default, and a run that uses it says so loudly. Forward updates, the
  "already on that version" no-op and the ring approval itself are unchanged — an environment still moves
  only to what its ring approves.
  *Why it matters:* an environment installed at a current version could previously be rolled backward by
  its own nightly update to whatever older version its ring still held. Everything about that update
  looks successful; what breaks is a component the newer version added, hours later, unattended, with
  nothing to alert on it.

- **The release ring you configure is the release ring that gets deployed.** The ring chosen for an
  installation was not being passed on to the update job, so the job was created on the built-in default
  ring instead — and a configuration that named no ring at all was read as the ring that takes every
  build. The chosen ring is now carried through; an installation that does not name one is told which
  default it is getting and why; an unreadable ring value stops the installation instead of being guessed
  at; and the installation **reads the ring back off the deployed update job** and fails if it is not the
  one that was asked for. A ring nobody verified is a version nobody chose.

- **The documentation now says plainly how the product is set up, updated and licensed.** The README
  describes the **six supported setups** by what they actually are — one tenant on its own, a service
  provider's managing tenant, or a tenant that provider looks after, each with where the platform runs
  and where its updates come from — and states that a tenant can start alone, be taken on later, and be
  detached again with its definitions staying in its own database. It also separates the **two ring
  systems** that were easy to confuse: the release ring that decides which *version* an environment
  runs, and the replication ring that decides which *managed tenants a definition reaches*. They are
  independent controls. Finally, the **free and paid editions** are set out in full, with the current
  status stated honestly: licence enforcement is **not switched on**, so nothing is restricted in the
  product today.

**Upgrade note:** none — both changes take effect as soon as a hosted environment runs this version. If
an environment has been running on a ring you did not intend, re-run the deployment naming the ring you
want; it is now applied and verified rather than silently defaulted.

**Interested in the licensed (multi-tenant) edition?** Mail **mok@mortenknudsen.net** for information.

## v2.4.367 — MSP: the provider publishes from the cloud, managed tenants read a signed baseline over the network, and both sides can be deployed by a signed-in administrator

This release changes how a managed-service provider gets its signed baseline to its managed tenants.
Nothing changes for a single-tenant installation.

- **The provider's baseline is published by a job in the provider's own cloud environment, not by a
  management server.** A scheduled container job (daily, and on demand) reads the provider's store, builds
  the baseline and signs it with a **non-exportable key in the provider's key vault**. The job runs as its
  own managed identity and holds no certificate, secret or storage key; it may use only that signing key
  and write only to the baseline container. Before uploading it verifies the signature with the same
  verifier a managed tenant uses, and after uploading it reads the baseline back the way a managed tenant
  does and verifies it again — the run succeeds only if all of that happened. There is no management host,
  scheduled task or machine certificate left in the publish path.

- **Managed tenants pin the provider's signing key.** A baseline signed by the key vault key carries its
  public key, and that is not what makes it trusted: each managed tenant is configured with the key's
  identifier (given by the provider when the key is created) and refuses a baseline signed by any other
  key. More than one key can be pinned at a time, so the provider can change keys without breaking any
  tenant. Baselines signed the previous way (the product certificate) still verify, so an existing
  provider can move over without a gap.

- **No expiring read link any more.** Managed tenants used to read the baseline through a time-limited
  link that had to be renewed on a schedule with credentials from both sides. The baseline is now a
  **signed file reached over the network**, and the path depends on how the two environments are
  connected: where the provider's and the managed tenant's private networks are connected, the tenant
  reads it through a **private endpoint** and the storage has no public access at all; where they are not
  connected, the storage allows anonymous read of the baseline file only (no listing) from the networks it
  explicitly names. Either way trust comes from the signature, never from the network, and nothing in the
  access path expires.

- **A private-only deployment is a supported shape on both sides.** Provider and managed tenant can each
  run with a network-internal application environment and no public entry point, with the baseline store
  reachable only through the private endpoint. The name the store is reached by is published in each
  side's own private DNS, so neither side has to be given rights in the other's network. The database
  keeps no public entry point either: the build opens a time-boxed window for the deploying machine and
  closes it again when it is done.

- **Deploy as a signed-in administrator.** The one-command build can now run on an administrator's own
  sign-in instead of a deployment application with a certificate: leave the deployment identity out of
  the build configuration. Before anything is changed it checks that the sign-in is a person in the right
  tenant and subscription and that no application credential is lying around in the session, and every
  step then runs on that sign-in. The certificate mode is unchanged.

- **The one-command build completes on a new pair.** Several defects found by building a provider and a
  managed tenant from nothing are fixed: the build now requires and forwards a network address plan (it
  used to stop at its second step), passes the right connection details to the database schema step,
  keeps single-value lists as lists, loads its store helpers where later steps can see them, and reports
  cloud errors instead of an internal "command not recognized" message. **Upgrade note:** a brand-new
  provider + managed tenant pair needs two small preparation steps before the two builds (each side needs
  one value the other side creates); the build guide lists them.

- **The provider's Manager says why a baseline is not verified.** The provider view's baseline banner now
  shows which key signed the baseline and, when it is not verified, the reason — for example that the
  Manager itself does not pin that key — instead of a bare "NOT verified". Certificate-signed baselines
  verify as before.

- **A tenant read that has no directory rights is reported as not checked, not as a failure.** The role
  map check used to report a red result when the identity it ran under simply could not read the
  directory; it now says so plainly and skips.

**Upgrade note (MSP only):** move the managed tenants first. Every managed tenant must run this version
and pin the provider's key **before** the provider's first cloud publish replaces the certificate-signed
baseline; a managed tenant on an older version refuses the new baseline and keeps its last applied state
until it is updated. The baseline pull job and the publish job are not rolled by the automatic updater in
this version — redeploy them with this version's image when you update a managed tenant.

## v2.4.366 — The MSP pair test can be pointed at any pair

- **The end-to-end test that proves an MSP master and its managed tenant work together is no longer tied
  to one specific pair.** It had two particular environments written into it, so it could not be used to
  verify a pair you had just built — which is precisely when you most want it. It now accepts a small
  configuration file naming the pair to check; anything the file leaves out keeps the previous default,
  so existing use is unchanged. A configuration file that cannot be found is an error rather than a
  quiet fall-back to the old pair, the run states which pair it checked, and the safety checks that keep
  this test away from production environments are applied to whatever pair is named.

## v2.4.365 — An activation policy for permission delegations, and the delegation table has a name

- **Permission delegations can now be given an activation policy in the wizard.** When you create a
  permission group (Entra ID or Azure), you can pick the activation policy it should use — including
  one that makes activation need **approval** — instead of that only being settable on roles. The list
  is the set of templates **your own tenant has**, including any you added or edited, and each is
  labelled with what it does. **"Use default" is the first choice and changes nothing**: a group
  created without touching the field behaves exactly as it did before. The four permission-group
  record types gained the column that stores it, and resource records gained the replication fields
  the other record types already had.

- **The delegation table has a name in the menu.** Changing an existing delegation — an eligibility
  from 90 to 365 days, or its policy to one that needs approval — was always possible in the records
  table, but that table was called *All records*, which describes the data rather than the job, so the
  one person who needed it could not find it. Access now has **"Delegations — edit in a table"**, which
  opens the same table narrowed to delegation records, with the same edit-then-commit flow. *All
  records* is still there as the raw view, and the narrowed list says it is narrowed and offers one
  click back.

## v2.4.364 — PIM never deletes an account, and the date that disables one is now called what it does

This release removes two ways an administrator account could be switched off or removed that the product
should never have had, and renames the date column that switches one off so it says what it does.

- **🔴 PIM never deletes a user account. Anywhere.** The offboarding sweep used to delete the account once
  a retention period had passed. That capability is **gone from the product** — not switched off, not
  hidden behind a setting, removed: there is no code path that deletes a user, in a single tenant, on an
  MSP master or on a managed tenant, whatever the data says. Offboarding keeps everything else — the
  account is disabled, its sign-in sessions are revoked, its privileged access and group memberships are
  removed, the notice is sent and every step is recorded — and then it **stops**. The account stays in the
  directory, disabled, until a person deletes it by hand. A test in the standard suite fails the build if a
  user-object delete ever reappears in the product.
  - **`DeleteAfterDays` is removed and no longer supported.** It is gone from the admin record, the
    Manager, the baseline sent to managed tenants, the samples and the docs — there is no field, no
    setting and no disabled switch left behind. Existing data needs nothing from you: a record that
    still carries the value is **accepted silently** and the column is removed the next time the
    schema preflight runs. (If the capability is ever wanted again it will be added back deliberately,
    with its own opt-in and approval step.)
  - The guided offboard sequence is now two steps (disable, then revoke access) instead of three; the third
    step used to schedule a deletion.
  - In the Manager, **"Flag for deletion" is now "Mark for manual removal"**, and the confirmation says in
    as many words that PIM never deletes the account.

- **🔴 An account is never disabled just because it is missing from your definitions.** Until now, a live
  admin account that matched your admin naming but was absent from the definitions was treated as something
  to deprovision — throttled by an opt-in, a circuit breaker and a removal budget, but still a disable.
  Every one of those guards limits *how many* accounts are switched off, not *whether the reason is sound*,
  and a half-loaded definition set looks exactly like "they left". The capability is removed, along with its
  setting. The **report stays**: each run still names every live admin account that is not in your
  definitions, so you can see them. Disabling one is your decision, made on its row. Group and membership
  clean-up is a separate mechanism and is unchanged.

- **`OffboardDate` is now `AutoDisableDate`, and the sweep only disables.** The old name promised more than
  the product does. On the date you set, PIM disables the account, revokes its sessions, removes its
  privileged access, sends the notice — and keeps the account. `Lifecycle = Retire` means exactly the same
  disable-only path.
  - **The date is now on the Admin accounts screen**, in its own column and editable per admin, with the
    effect spelled out, a flag when a date has already passed or falls within the next 14 days, and a flag
    when a row still uses the old column name.
  - **Upgrade note — your data migrates itself, and nothing is guessed.** Rows using `OffboardDate` keep
    working: it is still read. The schema preflight copies the value into `AutoDisableDate` and then removes
    the old column, in one idempotent pass. A row that somehow carries **both names with different dates**
    is **refused, not guessed** — the engine skips that admin entirely and the Manager shows an error naming
    both dates, because silently picking one is how an account gets disabled on a date nobody chose. Editing
    the date in the Manager clears the old column for you.
  - **Upgrade note — MSP master and managed tenants must both be on 2.4.364 or newer.** The baseline now
    carries `AutoDisableDate` instead of `OffboardDate`; a managed tenant on an older build would not
    recognise it.

- **Mail about an administrator now goes to their sponsor department's owners.** PIM's mail about an
  administrator account — the new-account notice and the Temporary Access Pass — is addressed to the
  **owners of the department that sponsors that administrator**, all of them. Previously it fell back to a
  manager address recorded on the person, which goes stale the moment somebody changes job; a department
  outlives a reorganisation. Two exceptions are deliberate: an explicit forwarding address on the
  administrator still wins, because it is a decision written on that record; and a manager address on an
  existing record is still honoured so nothing stops working, but it is now reported as **legacy** in the
  Manager, the validator and the readiness check so you can move it to the department. When none of them
  resolves, PIM **refuses to send** and names what to set — the administrator's department, or that
  department's owners — instead of silently mailing nobody.

- **You can see each admin's sponsor department on the Admin accounts screen.** The department that sponsors
  an administrator decides who approves for them and where their mail — including their Temporary Access
  Pass — is delivered, and it was only visible by opening the admin. It now has its own column, with the
  department's owners shown on hover. Two gaps are called out separately, because they are fixed in
  different places: an admin with **no department** (fix the admin), and a department with **no owners**
  (fix the department). If the owner list could not be read at all, the column says *owners not checked*
  rather than claiming there are none.

## v2.4.363 — One command builds an MSP master or a managed tenant, and every admin gets a TAP

- **New: a one-shot build for an MSP master and for a managed tenant.** `tools/setup/Invoke-PimMspBuild.ps1 -Role
  Master|Slave -ConfigPath <file>` runs every step in order, from a machine-local file that holds ids and names only (a
  file that contains anything resembling a credential is refused). It covers:
  - hosting (the existing full deployment, with managed identities only);
  - the SQL admin group, now including the scheduler and Manager identities;
  - the scheduler's and the Manager's directory permissions, and the Manager's right to start the scheduler immediately;
  - the deployment scenario;
  - on the master: the registry, the baseline store, registering each managed tenant, publishing the signed baseline and
    a daily re-publish;
  - on a managed tenant: minting the read link, the pull job, and the weekly certificate-only link rotation.

  It signs in with certificates only and removes its temporary sign-in files when it ends. It shows the plan unless
  `-Apply` is given, can resume from any step with `-From`, and finishes by printing the steps that need a person —
  such as the first approval of policy changes, which is deliberately not automated.
- **New commands the build uses, also usable on their own:**
  - `Register-PimManagedTenant.ps1`: registers a managed tenant on the master with its ring and tags (it replaces a manual
    database step);
  - `Set-PimScenario.ps1`: sets the deployment scenario;
  - `Initialize-PimHostingAccess.ps1`: brings the directory permissions and the start-now right up to date on an
    existing environment;
  - `Register-PimBaselinePublish.ps1`: schedules the signed baseline publish.

  Each one checks the result after writing it and records the change in the audit trail.
- **A Temporary Access Pass is enforced for every Entra admin — on a single tenant, an MSP master and a managed tenant
  alike.** The "create TAP" setting can no longer turn a TAP off anywhere:
  - managed tenants store it as on, and it is no longer carried in the signed baseline;
  - the MSP fan-out and the central-admin registry command ignore a "no";
  - the validator reports a "no" as having no effect and offers a one-click fix;
  - the readiness check now requires every Entra admin to have a delivery address.
- **Fixed: a deployment could give the Manager's read-only identity the engine's full write permissions.** The
  permission grant used the engine's list whatever list was asked for. The Manager now receives only its read-only set.
- **Fixed: the full deployment ignored the SQL admin group name and the troubleshooting identity**, and on a private
  database its access step looked up a setup job with an empty name. Both values are now passed through.
- **The deployment identity can now create and fill the SQL admin group**, so that step runs without manual help.

**Upgrade note:** to build an MSP pair, build the master first, then each managed tenant. The phased onboarding script
used before this release is superseded.

## v2.4.362 — The managed-tenant pull job needs no secret, and every retraction is reported first

- **A policy change held for approval is no longer a failed job.** When the policy mass-change safety check
  holds a set of policy changes, the job that ran into it is now recorded as **needs approval** — shown amber on
  the Jobs page, counted under "needs attention" on the Jobs page and the Home page, and raised as an operator
  alert that names the policy area, the number of changes and the exact approval command. It is never shown as
  passed and never as failed. This applies to the scheduler's engine jobs and to a managed tenant's pull job
  alike (the pull now ends "held" instead of "failed"). A genuine error in the same run still fails the job.
- **Admin lifecycle settings reach managed tenants as the master defines them.** An MSP admin's "create TAP"
  setting, provisioning date, TAP start date and delete-after-offboarding days now travel with the admin to
  each managed tenant. Previously a managed tenant filled these in with its own defaults (for example
  "create TAP" on), whatever the master said. Dates keep their exact value on every host.
- **A managed tenant's pull job can be allowed to remove what no longer reaches it — explicitly, and off by
  default.** `Deploy-PimDownlinkJob.ps1 -AllowRetraction` sets `PIM_DOWNLINK_ALLOW_RETRACTION=true` on the job;
  only an explicit true value turns it on, a mistyped value is reported and treated as off, and removals stay
  within the removal limit. Without it, retraction remains report-only.
- **The weekly baseline read-link rotation signs in with certificates only.** `Update-PimBaselineSas.ps1
  -CertLoginConfig <file>` logs in to the master and the managed tenant with each identity's certificate from
  the machine store (the file may hold only tenant, client, certificate thumbprint and subscription ids; any
  other field is refused) and removes its temporary sign-in profile when the run ends. Registering the weekly
  task now carries every sign-in input into the task; previously they were dropped, so a registered task could
  not sign in.
- **The managed tenant's scheduled pull job now runs without a client secret.** When no engine credential is
  supplied, `tools/setup/Deploy-PimDownlinkJob.ps1` runs the job's work as the job's own system-assigned managed
  identity — the same shape as the scheduler job. The deploy grants that identity the engine's directory
  permissions and adds it to the SQL admin group, so it can read the tenant's own domain, write its own store
  and apply the result. The user-assigned identity stays attached only to pull the container image.
  Previously a job without a secret ran as an identity with no directory permissions and could stage nothing.
- **Admins that stop reaching a managed tenant are reported, not removed.** When the master re-targets an
  administrator away from a tenant, that tenant's pull now reports the admin as "would remove" — exactly like
  groups and memberships already were — and removes it only when the removal is explicitly allowed, inside the
  removal limit. The list is kept in the pull's acceptance record.
- **Joining the SQL admin group waits for the directory.** A member that was just added is no longer reported
  as missing because the directory had not listed it yet; the read-back retries for a short, bounded time.
- Fixed: re-deploying the pull job with the system identity could fail on an internal parameter name.

**Upgrade note:** re-run `Deploy-PimDownlinkJob.ps1` for each managed tenant without `-EngineClientSecret`
to move an existing pull job onto its system identity (the job is recreated once, because an identity change
cannot be applied in place). A job deployed with an engine secret keeps working unchanged. A re-deploy without
`-AllowRetraction` leaves (or returns) the job report-only. To move a registered weekly read-link rotation off
secrets, re-register it with `-CertLoginConfig`.

## v2.4.361 — The nightly updater repairs its own database settings, and the database is administered by a group

- **The nightly updater no longer stops because its own database settings are missing.** If the updater job
  carries no database server, it now takes the server and database the Manager is already using, checks the
  schema with them, and records them on itself for the next night. Previously it refused every release and
  asked for the updater to be redeployed.
- **When the updater cannot sign in to the database, it says exactly who and what to do.** The message names
  the updater's managed identity (its object id) and the SQL admin group to add it to, instead of a generic
  sign-in error. As before, it never rolls a release whose database changes it could not check.
- **New: the database is administered by a security group.** `tools/setup/Initialize-PimSqlAdminGroup.ps1`
  makes a group (default `grp-pim-sql-admins`) the database server's Microsoft Entra administrator, with the
  environment's managed identities, the nightly updater, an optional troubleshooting identity and the previous
  administrator as members. It is safe to run again (a second run changes nothing), reads every change back,
  keeps Entra-only authentication on, keeps existing database users, and offers `-PlanOnly` to preview.
- **New deployments set this up automatically**, for public and private database servers. If the deploy
  identity is not allowed to manage groups, the deployment keeps the previous administrator and prints the
  command to run later.
- **Redeploying the nightly updater adds its identity to the group** when the group is the database
  administrator. It never creates the group or changes the administrator on its own.
- **Fixed: database additions shipped in a release now reach existing installations.** The nightly updater applied
  the shipped database schema only to a new database, so a column added by a release (for example the replication
  setting added in v2.4.360) could be missing on an existing installation while the update reported the schema as up
  to date. It now applies the shipped schema on every run, and refuses the update if a statement would remove data.

**Upgrade note:** nothing is required. To move an existing environment onto the group model, run
`Initialize-PimSqlAdminGroup.ps1 -PlanOnly` with a certificate identity that can manage groups, review the plan,
then run it again without `-PlanOnly`.

## v2.4.360 — MSP master: choose per admin and per group which managed tenants receive it

- **Replication targeting on the MSP master.** Every admin, membership, direct group (role, organisation,
  department, project, cross-org), permission group, nesting and role binding can now say whether it replicates
  to managed tenants — **No**, **Yes** or **Follow** (only when something that replicates needs it) — and to which
  ones, by **ring** and by **target**: tenant tags such as `tag:region:eu`, tags a tenant must carry together such
  as `tag:tier:gold+finance`, or named tenants. Ring and target combine: a tenant must be admitted by both.
- **Set it where you author.** Each Create wizard has a Replication section on its Review step, and the grid has
  the same fields with pickers. Both show **"This will reach: N of M tenants"** (names on hover), computed by the
  same logic the managed tenants run, plus a warning when a group is sent to a tenant only because something that
  replicates there needs it. The section and the columns appear only on the MSP master.
- **MSP sync settings appear only where they mean something.** A single tenant no longer shows "Sync to slaves",
  management mode, ring or slave tags on admin accounts, in the admin wizard or in the grid. A managed tenant shows
  only which admins it received from its MSP master, read-only. The Manager also refuses these settings when the
  tenant is not the MSP master.
- **Nothing changes for existing data.** With the new fields left blank, what is published and what each managed
  tenant receives is exactly as before.
- **Fixed: department, project and cross-org groups were not sent with the memberships that need them**, so a
  managed tenant received a membership into a group it could not create.
- **Fixed: an admin or group marked as local to the MSP could still be included in the signed baseline.** It is
  now left out entirely unless something that replicates depends on it.
- **Fixed: the master's view of which admin reaches which tenant ignored targets and tags**, so it listed more
  tenants than the admin actually reaches.
- **Fixed: admin assignments had no Target column in the grid**, although the baseline reads it.
- **Removing replicated rows is now reported first.** When a row stops reaching a managed tenant, the sync reports
  it as "would remove" and removes it only when you run it with `-AllowRetraction`, within the removal limit.
  **Upgrade note:** a managed tenant's sync that relied on stale replicated rows being pruned automatically must now
  add `-AllowRetraction`.

## v2.4.359 — Install the community edition from GitHub into your own tenant

- **The public GitHub edition now installs end to end.** Clone the repository, create the deploy identity,
  and run the one-shot deploy with `-Scenario S2`: it builds the Manager image from your clone, stands up
  the Manager (scaling to zero), the scheduled engine job and the database in your own subscription, puts
  Microsoft Entra sign-in in front of the Manager, and makes you its administrator. See **Getting started**
  in the README.
- **The image builds from the public repository layout.** The build recognises a clone of the public
  repository and prepares its build context itself, using committed files only and never your local
  customer files, licences or keys.
- **The deploy identity gets the directory permissions the install needs.** `-GrantGraph` adds the three
  Microsoft Graph permissions the deploy uses to grant the Manager and engine their own permissions, and
  proves the identity can read the directory before the install starts.
- **A community install no longer fails on the in-cloud updater.** Without a published release feed the
  deploy skips that step and tells you how to update: `git pull` and run the same command again.
- **A deploy whose automated smoke test is not present is recorded as unverified — it is no longer rolled
  back.** Previously a missing smoke test counted as a failed health check.
- **Sign-in consent is granted even when the deploy runs as an application.** If the Azure CLI cannot
  grant admin consent for the Manager's sign-in registration, the deploy grants it through Microsoft Graph.
- **Fixed: creating the deploy identity could fail on a busy directory** (a new registration not yet
  visible), and an Azure CLI warning could be mistaken for the identity's id.
- **Documentation refreshed** for everything shipped since the previous public release, with new
  screenshots, a licensing section, code statistics and customer-facing release notes.

## v2.4.358 — Engine jobs run again in hosted environments

- **Fixed: engine jobs failed on 2.4.357 in container-hosted environments.** Keeping a copy of each job's
  output tried to reuse a console colour that a container console does not have, and the error stopped
  the job before it applied anything. Output is still kept for the Logs view, and showing it on the
  console can no longer fail a run.
- **Upgrade note:** if you run 2.4.357 in a container, update to this release.

## v2.4.357 — Job logs show what the run did, and recovered jobs stop showing as failing

- **Logs show the real run output.** The Logs button on the Jobs page shows everything a run printed —
  each area the engine checked, what it created or changed, warnings and errors — under the short
  summary. While an engine job is running, live tail shows its progress. The last three runs of each job
  keep their output.
- **Run now works for every scheduled check.** Run now on the convergence check and on the discovery jobs
  queues them for the scheduler, the same way engine jobs already worked, instead of recording
  "not implemented".
- **A job that failed and then recovered is no longer "failing".** Such failures show as "failed earlier,
  recovered" under History; only failures that are still standing need attention. Ack clears every
  standing failure of a job in one click.

## v2.4.356 — Drift items show names

- **Drift items name who and where.** An item that exists in the tenant but not in PIM now reads, for
  example, "admin-x@contoso.com -> member of group PIM-ROLE-... (Eligible)" instead of object ids. A
  principal the directory no longer knows is shown as "unresolved principal", still with its group. Names
  appear after the next drift check (Check now, or the 4-hourly run).
- **No more double listings.** The technical key is only shown when it adds something.
- **Access page:** a stray block of design text above the wizards is gone.

## v2.4.355 — Drift gets its own page, a tidier menu, and queued actions no longer wait for a long run

- **Drift: live vs desired is its own page** under Reviews & controls. It opens instantly from a check the
  scheduler runs every 4 hours, shows desired, live and in-sync counts per area, and each row expands to
  the differences. Check now queues a fresh check.
- **Menus make more sense.** Daily operations is folded into Reviews & controls; newly discovered
  resources and the job schedule have their own pages; Manager access & roles, the emergency override,
  permission template packs and mail templates are sections in Settings.
- **Queued actions apply during long engine runs.** A committed Temporary Access Pass re-issue or session
  revoke is applied between engine steps instead of after the whole run.
- **Change queue and badge.** Pending entries are listed first; the red badge counts only what needs you
  (pending or failed), and committed entries waiting for the engine show in blue.
- **Review standing access hides deleted principals** by default; tick "show deleted principals" to list
  and revoke them.
- **Access map and wizards.** Departments, organization, project and cross-org groups sit with the direct
  groups; suggestion lists show every value in use; audit entries name the real group, not its tag.
- **A group created in a run is used in the same run.**

## v2.4.354 — Faster membership checks see every existing membership

- **Nothing is missed by the faster check.** Microsoft Graph's per-person membership list can leave out
  some older group nestings, so 2.4.353 treated them as missing and re-checked them one by one (no changes
  were made). The engine now confirms anything that list did not return — and every removal — with a read
  of that group, and uses the full read if any part of the faster read fails.

## v2.4.353 — Changes apply in minutes, not a full engine pass

- **Only what changed runs.** A committed change starts only the engine steps for the kind of data you
  changed (for example, an Azure role delegation runs the Azure policy and assignment steps), instead of
  every step for the whole tenant.
- **The engine starts right away.** Commit and Run start the engine immediately instead of waiting for its
  next scheduled start, when the Manager is allowed to start the scheduler job. A run already in progress
  picks up new commits and queued actions as soon as its current step finishes.
- **Faster admin and nesting checks.** Routine runs read only the memberships of the admins and groups your
  rows name.
- **Every admin shows a type** in the admin accounts list, including admins created before the type was
  stored.

## v2.4.352 — Reviewing standing access no longer freezes the Manager

- **Active assignments come from a snapshot.** The scheduler reads active Entra role, Azure and PIM for
  Groups assignments every 2 hours (editable on the Jobs page). Review standing access, the Revoke tab and
  the Home expiring-access tile open instantly and show the snapshot time. Previously each open read the
  tenant live for minutes and blocked other Manager users.
- **Refresh queues a new read** instead of reading while you wait, and a completed revoke queues one
  automatically. A revoked row is marked "revoke queued" until the next snapshot no longer contains it.

## v2.4.351 — Manager fixes: Commit all, dialogs, recent commits, role lookup, New admin

- **Commit all includes queued actions** such as a pending Temporary Access Pass re-issue or revoke.
- **Dialogs open on top** instead of under the menu bar.
- **See what was committed recently** with the change queue's Show filter.
- **Less noise before committing.** Informational validation notes no longer raise the yellow banner.
- **Delegation wizards help avoid duplicates.** The Entra role picker hides roles that already have a
  delegation group, and the Workload field suggests workloads already in use.
- **"+ New admin" and "Give access" work again**, and Role lookup finds roles such as Exchange
  Administrator on the hosted Manager.

## v2.4.350 — Policy errors name the role and scope they concern

- **Failing policy items read as policies.** An Azure resource or PIM for Groups policy item under Engine
  logs & errors now reads, for example, "PIM policy for Azure role 'Reader' at management group X
  (template Y)" instead of showing an empty group and role.

## v2.4.349 — Complete audit of policy changes and revokes, no passwords in logs

- **Policy changes are audited rule by rule**, with the value before and after, the template, and whether
  an approved mass-change plan applied it.
- **Revokes, Temporary Access Pass resets and session revokes are audited when they happen**: who asked,
  what was done to whom, how it was verified, and the outcome.
- **Initial passwords are never shown or saved** when creating an admin account from the setup tools;
  onboard the admin with a Temporary Access Pass.
- **A refused commit stays on Pending changes** and lists the blocking errors, with the rows they concern
  and a link to the fixes.
- **Template rows that still carry the placeholder subscription are no longer offered for import.**

## v2.4.348 — Delegations deploy as chosen, errors name real groups and roles

- **A delegation made Eligible in the wizard is written Eligible.** The role, project and permission-group
  wizards wrote every group-into-group nesting as Active. Entra ID refuses an Active membership of a group
  in a role-assignable group, so those delegations never reached the tenant. Nesting into a role-assignable
  group is now always Eligible.
- **Upgrade note:** validation reports any existing Active nesting of that kind as an error with a
  one-click "Set to Eligible", and the engine lists it under Engine logs & errors instead of skipping it.
- **New delegations get their PIM for Groups policy straight away.** Applying the template to a new group's
  untouched default policy no longer trips the mass-change safety brake. Changes to policies someone has
  already set are still guarded.
- **Engine errors say which group, role and scope they are about**, with a link to that scope's PIM
  policies in the Azure portal.
- **"Run now" on an engine job queues it for the scheduler** and says so; running jobs show as running.
- **Missing engine permissions are shown loudly.** The permission banner on Home turns red and names what
  the scheduled engine was refused.
- **The audit trail records what the engine changed** — every membership, role assignment and account
  change, with the real person, group, role and scope, and the job run that made it.
- **Commit re-checks your staged changes before refusing**, so a fix you just staged counts.

## v2.4.347 — Staged changes survive a reload or restart

- **Changes in Pending changes are no longer lost when the page reloads.** They are kept in your browser
  and put back after a reload (for example after a Manager update), applied on top of the current data so
  a colleague's commit in the meantime is kept. Nothing is committed for you. The page also asks before you
  leave with uncommitted changes.
- **Discarded queue entries are hidden by default**; tick **Show discarded** to see who discarded them and
  why.
- **Upgrade note:** on versions before this one, staged edits live only in the open page. Commit or note
  pending changes before updating an environment that runs an older version.

## v2.4.346 — Faster engine runs

- **Scheduled runs spend far less time saving state.** Settings are only written when they change, and job
  history keeps the 10 most recent runs per job in a compact form.
- **Microsoft Graph throttling is handled in one go**: the engine waits the time Graph asks for once and
  resends the throttled reads together.
- **Lookups are reused within and across runs**, such as each group's PIM policy id. Revokes and the drift
  check always use fresh data.

## v2.4.345 — Group policy safety brake always on, faster group policy updates

- **The mass-change safety brake covers PIM for Groups policies in every case.** With batched reads (the
  default), a large or weakening set of group policy changes could be applied without being held for
  approval. It is now held exactly like Entra role and Azure resource policies.
- **Group policy updates send only what changed**, which makes large policy alignments many times faster.
- **Opening Governance no longer slows down the Manager.** The drift check runs only when an admin clicks
  **Check for drift (slow)**.

## v2.4.344 — Home loads instantly

- **Opening Home no longer slows down everyone else.** The *Expiring access* and *Pending access reviews*
  tiles load only when an admin clicks **Load live data (slow)**.

## v2.4.343 — Fast, stable database access under load

- **The Manager no longer runs out of database connections.** All database calls share one connection
  pool, so a page load uses a handful of sessions instead of hundreds.
- **Database sign-in tokens refresh on time** under frequent use.
- **Home no longer freezes the Manager for other users**; the expiring-assignments tile reuses a recent
  result.

## v2.4.342 — PIM policies identical to v1

- **Moving from v1 changes no PIM policy.** The standard policy templates for Entra roles, Azure resource
  roles and PIM for Groups (member and owner) carry exactly v1's values. A standing check compares every
  rule with v1's definitions.
- **Upgrade note:** the PIM for Groups member activation maximum is back to 8 hours; earlier v2 builds
  used 1 day.

## v2.4.341 — Controlled updates, enforced group policies, MSP admin sync and on-premises AD admins

- **Updates are release-stage controlled end to end.** Each environment moves only to the version its
  release stage approves (customer environments default to the most conservative stage). The nightly
  updater checks the database schema before rolling and refuses to update when it cannot.
- **A Temporary Access Pass is issued to every cloud admin.** On-premises AD admins cannot hold one and use
  a password.
- **On-premises AD admins work as in v1.** They are created and kept up to date in Active Directory, in the
  organizational unit and with the names your naming settings produce. The initial password is emailed to
  the admin's office address (or manager) and never stored.
- **Remove rows revoke.** Marking a delegation for removal revokes it (eligible and active) and then
  removes the row. A removal that is held or fails keeps its row.
- **Group and Entra role policy changes have the same safety brake as Azure policies.**
- **Clearer permission errors** when a group policy cannot be read.
- **MSP: each admin says whether it is synced to managed tenants, and to which.** Only admins marked as
  MSP-managed are synced, optionally narrowed to tagged tenants. The Manager shows which mode the tenant
  runs in.
- **Faster runs** through batched group membership and policy reads and a single Azure role assignment
  query.
- **Everything is stored in the database**, including remaining settings, audit, scheduler state, tenant
  caches and mail templates.
- **Mail is sent as the environment's managed identity**, with the send right scoped to the sender mailbox.
- **Stored policy templates receive new settings automatically** without overwriting your changes.
- **Settings shows what each naming pattern produces.**

## v2.4.340 — A long run keeps its turn

- **Scheduled runs no longer overlap.** A run that took longer than its 15-minute turn (for example the
  first alignment of hundreds of group policies) could have the next run start alongside it. A run now
  renews its turn while it works, and stops making changes if another run has taken over.

## v2.4.339 — Both assignment types are kept unless you say otherwise

- **An assignment that exists as both eligible and active is no longer trimmed automatically.** 2.4.338
  removed the type your data did not name, which is common after years on v1. This is now off by default,
  as in v1. Changing a row from eligible to active (or back) still replaces the old type.
- **Upgrade note:** turn on the **Remove type leftovers** setting once you have reviewed what it would
  remove.

## v2.4.338 — Ready to replace v1: Azure resource PIM policies, full admin lifecycle, nothing stored in files

- **Azure resource PIM policies are managed** from your policy templates (activation and assignment
  durations, MFA and justification, notifications, approval). Partly configured policies are repaired rule
  by rule; approval that is already on is never removed.
- **A safety brake on policy changes.** A run that would change many policies at once, or weaken
  protection, changes nothing and shows the plan for an administrator to approve.
- **Group owner policies and complete notification settings** are managed for every directory role and
  managed group.
- **Disabled and revoked admins stay disabled**, with sign-in sessions revoked when revoked.
- **Offboarding runs on its own schedule**: disable, revoke sessions, remove access, notify, and delete
  after the retention period, resuming where an interrupted run stopped.
- **Removals and changes in your data are carried out**, including switching between eligible and active,
  duration changes and auto-extend. Bulk removals are held for review.
- **Admin accounts are created when due**, with name, job title, company and usage location kept in step.
- **Temporary Access Passes** respect a start date, are issued once, and follow your tenant's TAP policy.
- **Workload roles** (Defender, Intune, enterprise applications, Power BI, Power Platform, Dataverse,
  Business Central, Azure DevOps, Azure RBAC) listed in your data are applied, with exemptions.
- **Reminders, the daily summary and the tier report** contain real content.
- **Pending changes shows real names** for queued revokes and passes; entries can be discarded.
- **Jobs › Engine logs & errors** can approve a held policy change.
- **Audit times are correct on any server time zone.**
- **Upgrade note:** the Manager no longer reads or writes settings, access or template files and requires
  its database to start. Policy templates are kept in the database and upgraded automatically when
  unchanged.

## v2.4.337 — Saving an admin works, and Entra role policies are enforced again

- **Entra role PIM policies are enforced again** after a 2.4.336 change made the policy job fail on every
  run.
- **Saving an admin no longer reports a failure for a save that worked**; two other save screens had the
  same fault.
- **The Manager column shows the manager**, not the office email.
- **The admin list no longer stalls**; the full mail check runs when you press **Check** on one admin.
- **Department list** explains when it is empty and loads properly.
- **Group tags no longer warn as badly named**, and placeholder Azure scopes can be removed from the check
  itself.

## v2.4.336 — Failed jobs say what to fix, and offer the fix

- **A failed engine job explains itself**, grouped by cause — for example assignments rejected because the
  Azure PIM policy allows a shorter duration, or rows still pointing at a template placeholder subscription.
- **Jobs › Engine logs & errors is its own page**, with every recent run, a failures filter, full logs,
  and a **Failing now** section showing each item the engine could not apply, why, what to do, and for how
  long.
- **One-click fixes, still reviewed.** Items offer *Remove this row* or *Make it Eligible*; the fix goes to
  **Pending changes** and nothing changes until an administrator commits it.
- **Entra role assignments made by the scheduled engine work again.**
- **Re-issuing a Temporary Access Pass from the queue delivers it** to the account owner's office email,
  and refuses before touching the existing pass if mail cannot be delivered.
- **Pending changes always lists the queue.**
- **Scheduled jobs run on their configured cadence**, and *Next run* matches it.
- **Checks you can trust.** Validation states a definite result or says it could not check; findings that
  can never be applied are errors.
- **Admin accounts:** office email is a clearly labelled field; *Forward mail* and *Department* are
  dropdowns; mailbox forwarding can be set (off by default).
- **Direct groups:** new **Project** and **Cross-org** types; Department and Process groups are created by
  the engine.
- **Admin names:** a configurable admin word ("Admin", "adm") no longer loosens name validation.

## v2.4.335 — Queued changes are visible, and the admin screen no longer waits for everything

Includes the changes from 2.4.332 – 2.4.334.

- **Queued changes show a counter on Pending changes**, updated as soon as something is queued and within a
  minute for changes queued by other administrators.
- **One queue, one menu entry.** Three entries that led to the same list are now one.
- **Temporary Access Pass status is checked per admin** with **Check**, so the account list appears at once.
- **Edit sits on the admin's own row.**
- **A pass is mailed to the admin's forwarding address**, not to their manager; values that are not email
  addresses are refused.
- **The word "admin" in account names is configurable** (for example "adm").
- **A new direct group asks what type it is** — role, organisation, department, process or resource.

## v2.4.324 — Administrators can no longer be locked out; updates bring the database with them

- **Fixed: administrators could be refused as read-only users.** In environments set up the supported way,
  a valid permission list was processed twice and looked corrupt, so no one could be recognised at any
  level. The same fault denied delegated access profiles and confused the scheduler about its jobs. All are
  fixed; a genuinely damaged list is still refused.
- **When permissions cannot be read, the product says so** instead of moving on silently.
- **A job that had just run is no longer reported as overdue**; genuinely missed slots are still reported.
- **The delegation wizard no longer repeats its first panel down the page.**
- **Every check either has a working fix or explains what to do instead.** Five checks gained one-click
  repairs.
- **A successful update no longer reports itself as failed** over a final bookkeeping step.
- **Stored web links are checked after saving**, so one cut short on save is caught immediately.
- **Protection against data loss when a source fails.** Replacing all records of one kind with nothing is
  refused, with a count of what would have been removed. Deliberate clearing still works.
- **Messages no longer point at files that do not exist.**
- **Wizard fields help you fill them in**: domains in use, country lists, and short codes suggested from the
  scope or role you selected. New values can still be typed.
- **Updates bring the database with them.** The database is brought up to date first, never removes a
  column or its data on an unattended update, and the update stops if the database cannot be updated.
- **Update reporting.** Each environment reports one short record per nightly run (from/to version, what it
  did, duration, errors), without personal data or credentials, and reporting can never delay an update.
- **Approving a release is one change per group of environments**, and an environment that is too far
  behind is held back instead of jumping the gap.
- **Installing into an environment whose container registry is elsewhere** now grants and confirms the
  needed permission.
- **Access reviews with nothing to decide no longer count one outstanding decision**, so reviewers are no
  longer reminded about items that do not exist.

## v2.4.323 — An update that has to be undone can always be undone

- **Rollback no longer depends on records the platform may delete.** The update also records the version's
  contents, and rollback is confirmed against what is actually running.
- **A healthy update is no longer failed over a version-number mismatch**; the check asks whether the site
  runs exactly what was just deployed.
- **"Fix all auto-fixable errors" fixes all of them**, including assignments that point at an undefined
  administrative unit (remove the assignment, or define the unit). Anything that cannot be repaired is
  named.
- **Reliability:** two routines that shared a name were separated, so behaviour no longer depends
  on load order.

## v2.4.308 — Environments can build their own updates

- **An environment now produces its own new version.** It fetches the approved version's source and has its
  own container registry build it, then updates itself — no build machine or administrator needed.
- **No shared credential is needed.** Each environment is given a read-only link to one file.
- **Off until configured.** An environment without a source behaves exactly as before.
- **An environment that cannot fetch or build its approved version says so and stops** instead of reporting
  success.
- **The approved version is a single value**, the same in every environment of a group.

## v2.4.307 — Admins whose names differ only in capitalisation show their access

- **The Access board matches sign-in names and group names ignoring case**, for every kind of connection,
  as validation always did. A person could previously look as if they had no access.
- **A name that matches nothing is reported** instead of silently dropped.

## v2.4.306 — Importing your data no longer runs out of database connections

- **Imports write each file over one connection, in one transaction.** A file that fails is rolled back
  whole, so re-running is safe.
- **A failed file means a failed import**, naming every file that failed and how many imported.

## v2.4.305 — The nightly update updates every part of the environment

- **The updater discovers what is deployed** and updates every component running the same software, not
  only the management interface, scheduler and updater.
- **It leaves everything else alone**, including your own scheduled work in the same resource group, and
  reports skipped items with the reason.
- **A component left behind is a failed update**, named in the result.

## v2.4.304 — Reliability and test improvements

- Automated checks now cover every deployment script. No customer environment was affected.

## v2.4.303 — Automatic updates no longer undo each other overnight

- **Whatever builds a new version also marks it as the approved one**, after a clean run only, so the
  nightly update and the build step can no longer pull in opposite directions.
- **The approved-version marker is read back after it is written**; a failed save is reported immediately.
- **Installing the updater refuses a version too old to run it.**

## v2.4.302 — The nightly updater finds its own program files

- **Fixed: the updater looked for its shared code in the wrong folder** and stopped immediately. If the
  layout is ever unexpected, the message now names the missing folder.

## v2.4.301 — The update installer checks that the version exists

- **The installer checks the registry before creating anything**, for both the version it installs and the
  version it would upgrade to, and stops with a clear message if either is missing.

## v2.4.200 – v2.4.299 (summary)

### Installing into a new organisation (2.4.272 – 2.4.285)

- **A first installation can complete end to end.** The deployment creates the database and all of its
  tables before anything needs them, signs in to the database correctly, and restarts the web interface
  once its database exists.
- **Per-organisation settings.** Resource names, network range, subnet and region can be supplied instead
  of being derived from a fixed naming scheme.
- **Sign-in is required.** The installation puts Entra sign-in in front of the PIM Manager and verifies it.
  You can also name the people or groups who may sign in; assignment is only required after those
  assignments are confirmed, so no one is locked out.
- **The installation grants the Manager access to its own database and verifies it**, with an option for
  private database connections.
- **No unattended stalls.** Steps no longer wait for console input; missing inputs are reported by name up
  front.
- **Clear results.** Policy-blocked actions are summarised once; a missing permission is reported as
  missing instead of retried as a delay; the summary distinguishes checks that did not run from checks
  that passed.
- **Commands sent to Azure on Windows are no longer altered** by the Windows command processor.
- **Rollback keeps the scheduled engine on the same build as the interface**, and the update reports the
  version actually serving.
- **The Manager refuses to start on anything but its supported database.**

### Safer by default (2.4.253 – 2.4.271)

- **Access decisions fail closed.** If authorisation data cannot be read, access is refused; a file on the
  host can no longer decide who holds the highest role; the emergency override is stored where the engine
  reads it.
- **The audit trail is kept in your database and names the person who acted.** Suppressions and exceptions
  are stored in the database too.
- **Failed scheduled jobs raise an alert.**
- **A configured identity that cannot be used is refused** instead of silently replaced by another
  credential, for both directory and database connections. There is no hidden default local database.
- **Onboarding setup accepts certificates**; no client secret is required.
- **Managed tenants:** role reach can be reviewed and edited by role, and accounts a managed tenant's naming
  convention would not recognise are withheld and reported.

### A Manager that speaks your language (2.4.254 – 2.4.261)

- Plain menu names, roles picked from a list, display names with a user/group/application chip, and
  findings that offer the action that resolves them.
- Viewing and changing are separate: the delegation map is a map, and linking and revoking have their own
  place. Configuration lives in Settings.
- Job status is honest: a disabled job reports "disabled", not "failed", and a job a worker does not run is
  reported once, separately.
- A read-only sweep finds leftover test-style objects outside your naming filters, including their owners.
- Several causes of changes that could never be committed are fixed.

### Managed tenants and updates (2.4.245 – 2.4.252)

- **A managed tenant receives signed updates end to end**: it fetches and verifies the update, checks it is
  approved for its release stage, stores it and creates the accounts. Re-running changes nothing.
- **Control what is sent**: keep an admin local to one organisation, target specific tenants or tenant
  labels, and deny roles per relationship. Every exclusion is reported.
- **Upgrade note:** narrowing controls what is sent from now on; it does not withdraw access that was
  already delivered.
- **A fallback delivery address for Temporary Access Passes** can be configured.
- **Deployments verify that the scheduled update job can really run**, repair a broken one, and use the
  right credential type in containers.
- **Updates refuse to change your policy baseline by accident.** If the shipped policy templates changed,
  the update names them and proceeds only when you confirm.
- **The scheduled engine is updated together with the interface**, from the same image.
- **Multi-tenant fixes:** access tokens are cached per tenant (previously a second tenant could reuse the
  first tenant's token); the active identity is restored after a multi-tenant pass; the directory snapshot
  is refreshed every run; a central admin can be resolved into a managed tenant.
- **Upgrade note:** if you run PIM4EntraPS across more than one tenant from one host, or run the scheduler
  as a container (where overlapping runs were not detected), update to at least 2.4.246.
- **First deployments** retry briefly when an administrative unit created in the same run is not yet
  available.

### PIM policies (2.4.247 – 2.4.248)

- **Approval can be switched off again**, on directory roles and group policies.
- **Fixed: policies that stopped accepting changes.** The approval-required template named approver
  notification recipients, which made the directory reject every later change to that policy. The setting
  is removed and affected roles are unlocked automatically on the next run; the recipients that could not
  be preserved are named in the run output.
- **Activation notice recipients on approval roles** can be set again.
- **Standard templates leave the admin-eligibility rule empty**; activation still requires MFA and a
  justification.
- **Upgrade note:** if you use approval-required roles, update to at least 2.4.248.

### PIM Activator (2.4.230 – 2.4.240)

- **Activation progress reflects reality**: it finishes as soon as the activated role is active, and waits
  for nested roles to arrive or be removed.
- **"Show Roles" lists what a group really grants** across Entra ID and Azure, eligible and active.
- **Much faster load on high-latency hosts**, with fewer throttling errors.
- **Diagnostics no longer report expected permission limits as errors.**
- **Updating the extension can no longer de-list your Chrome or Edge profiles.**
- **Backend deployment** signs in interactively without Azure CLI or a certificate, and registers sign-in
  for both the released and test extension by default. It needs Cloud Application Administrator, plus
  Privileged Role Administrator to grant admin consent.
- Released extension builds 1.6.100 – 1.6.122.

### Manager, governance and engine foundations (2.4.200 – 2.4.230)

- **Six clear menus and a Home dashboard**; every Manager feature can be switched on or off in Settings.
- **Safer changes**: a backup before every commit, all-or-nothing commits with undo, second-person approval
  for sensitive changes, and an inline preview before each commit.
- **Delegation Map** gains search, a risk overlay (orphaned, stale, over-privileged), revoke from the map,
  and drill-down from an admin to their direct role groups.
- **Role Lookup** finds which roles grant an action, least privilege first, with compare and export.
- **Governance**: actionable access reviews, approval-gated offboarding and bulk revoke, full audit history
  with before/after and CSV export, an exemptions register, alerts, a fleet conformance matrix, a tier-impact
  report and a stale-admin sweep.
- **Operations**: job failure history and overdue detection; a Support page with a connectivity and
  permission self-check and a sanitised diagnostics bundle.
- **Mail templates are editable in the portal**, survive updates, and can be reset to default.
- **Admin account naming** uses a prefix by admin type (internal, external, guest) and a suffix by
  environment (cloud or on-premises AD).
- **PIM Activator** folds out the nested permission groups of an activated role group so each can be
  activated on its own.
- **New engine core**: REST-only (no Graph or Azure PowerShell modules), runs on Windows PowerShell 5.1,
  PowerShell 7, a VM or a Linux container, with delta and full modes. Removing live items not in the desired
  state requires an explicit prune, and an empty desired set is never pruned.
- **Scheduler and job runner** for containers or VMs, with per-area jobs and immediate processing of
  commits.
- **Azure SQL data store** with private endpoint and managed identity (no secrets), and a non-destructive
  migration from configuration files.
- **Hosted PIM Manager** available around the clock with Entra sign-in, plus a local break-glass console
  that signs the administrator in interactively against the same database.
- **Approver Matrix**: approval routing by workload, tier, level, plane and scope, with escalation through
  broader approvers and reusable roles such as CISO or IT manager.
- **Community (free) and Pro editions.**

## v2.4.100 – v2.4.199 (summary)

### Admin lifecycle and governance (2.4.152 – 2.4.159)

- **Date expressions** such as "first workday next month, 3 days earlier, at 08:00", with a live preview.
- **Scheduled admin creation** and **Temporary Access Pass windows** with a configurable lifetime; passes
  are created close to their start time.
- **Admin templates** (for example consultant, new employee next month) and **customizable mail
  templates**.
- **Policy templates** (default and approval-required) with automatic re-apply, and **approvals by group
  owners**, in parallel or serial with escalation.
- **Date-driven offboarding** (disable, revoke sessions, remove access, notify, delete after retention),
  **group retirement**, and **membership drift cleanup** in report or enforce mode.
- **Unified append-only audit**, and automatic addition of new columns to existing configuration.
- **Manager roles** Reader, Admin and SuperAdmin with server-side enforcement, a Governance tab, and an
  **emergency break-glass override** with automatic restore and owner notification.
- **Resource discovery** reports new Azure subscriptions and Entra roles.

### Delegated administration, data store and connectors (2.4.160 – 2.4.199)

- **Delegated portal administrators**, scoped by tier, level, service, Azure scope and capabilities.
- **Target-first permission wizard** that derives group name, tier, level and plane.
- **Azure auto-discovery** reconciles management groups, subscriptions and resource groups; a moved
  subscription is treated as a rename, not an orphan.
- **Change queue** with fast delta commits, alongside full reconciliation.
- **Guest invitations** for external admins, and owners can enable or disable their own consultants.
- **Automatic import of new role definitions** by policy.
- **SQL data store** (Azure SQL or SQL Server) with settings stored in the database, and optional
  **network-tiered access** (tier 0 managed only from a privileged access workstation).
- **Lifecycle calendar**: upcoming expirations, auto-renewal and escalating reminders.
- **Resource owners** can approve assignment requests and review existing assignments.
- **Workload connectors** for Entra roles, Defender XDR, Intune, Power BI and Fabric workspaces, Azure RBAC,
  enterprise application roles and Dataverse security roles.
- **Template versioning and conformance** (up to date, gap, exempt, drift), with exemptions that must expire.
- **Migrated data is brought to the current structure automatically**; the old tier column is replaced by
  an explicit **Purpose** (day-to-day or high-privilege admin), each with its own naming convention.
- **Licensing:** Core stays free and fully functional (including the SQL data store); Pro features unlock
  with an offline signed license file, and an expired license never breaks a tenant.
- **MSP**: multi-tenant rollout from a central registry with deployment rings; managed tenants pull and
  verify a signed baseline over a private endpoint, and local IT keeps full autonomy.
- **Mail redirect override** to watch all engine mail from one mailbox while testing.
- **PIM Activator 1.6.27**: an expired session (for example from Conditional Access session lifetime) signs
  you in again instead of showing an error.
- **Engine app registration setup** reuses a valid certificate, uses the machine certificate store by
  default, and can be re-run safely.

### PIM Manager (2.4.129 – 2.4.144)

- **One Manager for many tenants**, with fully separated data per tenant, a tenant switcher built for many
  instances, and per-tenant connections.
- **Much faster**: page load down from about 12 seconds to under one, and no more server freezes.
- **Delegation Map**: people, roles and org groups, capability bundles and permissions on one board. Click
  anything to see its full path in both directions, assign admins to groups and link bundles by clicking.
- **Role pickers load Entra roles and Azure RBAC role definitions from the tenant.**
- **Permission templates**: centrally maintained delegation packs with one-click import.
- **Deployment rings** for staged admin rollout across tenants; new admins default to test tenants only.
- **Workload delegation** to Defender XDR and Intune roles, applied by the engine (opt-in), with validation
  of workload rows.
- **Revoke tab** now lists PIM for Groups activations and handles large tenants.
- **The Manager runs fully offline**, with no external network requests.

### Engine fixes (2.4.114 – 2.4.128)

- **On-premises AD admin rows are provisioned** (they were silently skipped), routed to the right
  organizational unit by account naming convention, with group managed service account support. Passwords
  are no longer saved for accounts that failed to be created.
- **Administrative unit membership**: a single bad row no longer crashes the engine, and lookups that match
  nothing or several objects are skipped with a clear message.

### PIM Activator deployment (2.4.100 – 2.4.113, 2.4.145 – 2.4.151)

- **Intune deployment in one profile.** Conflicts with existing force-install policies are detected and
  skipped per browser, with the exact setting names printed; upload problems are retried and explained,
  including when Intune Administrator has not been activated.
- **Backend deployment** signs in through Microsoft Edge by default, checks your active roles, detects Graph
  SDK version conflicts, creates missing Microsoft service principals, and prints a troubleshooting banner.
- **Client deployment** discovers the tenant from Entra instead of reusing another tenant's catalog, and a
  manually entered single tenant wins over a managed catalog.
- **Extension updates** clear stale browser registrations safely.

## v2.4.0 – v2.4.99 (summary)

### PIM Activator browser extension

- **Turnkey setup** with a fixed extension identity, hosting on GitHub Pages (no Azure cost), Edge and
  Chrome support, and unattended deployment with an app-only identity (2.4.5 – 2.4.9).
- **My Access tab** with deactivate (single and bulk), role previews including nested groups, Azure RBAC
  roles, automatic token repair, a light theme, grouping into Entra, Azure and PIM for Groups, recently
  used groups first, and large performance improvements (2.4.10 – 2.4.37).
- **Extension 1.0.0** released for production use (2.4.43), followed by a multi-tenant picker and Intune
  rollout (2.4.44 – 2.4.50).
- **Default activation duration is 8 hours** (2.4.51); values pushed by managed configuration still win.
- **Upgrade note (2.4.52):** if you installed during 2.4.43 – 2.4.51 and the popup says "Not configured",
  re-run the Activator client deployment with the corrected extension id and restart Edge and Chrome.
- **Simpler deployment**: sensible defaults and admin consent granted by default (2.4.57 – 2.4.58).
- **Tenant catalog and header switcher** for admins who manage many tenants (1.6.0), with prefix shortcuts
  and Intune catalog push (2.4.88 – 2.4.94).
- **Fixed: devices stuck on old extension versions** because an extension settings policy was written in
  the wrong shape; unified Intune profile (2.4.98). The update helper no longer damages browser profiles
  (2.4.97).

### PIM Manager

- **Revoke tab** (2.4.2): bulk revoke active Entra role, Azure RBAC and PIM for Groups activations with a
  mandatory justification, confirmation and per-row results.
- **New look** (2.4.53).

### Engine

- **Performance** (2.4.0 – 2.4.1): cached group lookups, tenant-wide schedule preloads and Azure Resource
  Graph queries — an estimated 10 – 15 minutes saved per run at scale.
- **Four authentication methods** for launchers, one solution-wide configuration, and an admin consent
  helper (2.4.4, 2.4.7).
- **First run** copies missing configuration from the samples, and v1 configuration files are picked up
  automatically (2.4.56, 2.4.60).
- **Exchange Online** uses the high-privileged automation identity with its own certificate; certificates
  are preferred over secrets; propagation delays after creating a group are retried (2.4.62 – 2.4.68).
- **Upgrade note (2.4.68):** Exchange Online app-only access needs the **Exchange.ManageAsApp** application
  permission (not the V2 variant) and the Exchange Recipient Administrator role.
- **Critical fix (2.4.69):** the engine could create duplicate groups on every run when the group naming
  prefix did not match the tenant; the default prefix is now `PIM-`.
- **Upgrade note (2.4.69):** delete the empty duplicate groups created by earlier runs — of each pair with
  the same name, the newer one with no members.
- **Admin account patterns** accept a list, with Admin- and X-Admin defaults (2.4.70).
- **Engine fixes** (2.4.75): PIM policy rule updates that failed on every role, schedule preloads, date
  parsing, and a wrong "expires in 36159 days".
- Shorter, tagged log lines (2.4.72 – 2.4.73).

## v2.3.0 – v2.3.2 (summary)

- **Your configuration is your own from day one** (2.3.0): shipped baseline data files were removed and the
  samples carry generic examples.
- **Upgrade note (2.3.0):** if you still have the old shipped baseline files, rename them to your custom
  configuration files.
- **Faster runs** and clear warnings when Microsoft Graph reads fail silently (2.3.2).
- Updated README with the full feature catalog and a PIM Manager section (2.3.1).

## v2.2.0 – v2.2.1 (summary)

- **Optional admin metadata** such as company and notes, and a **role sponsor** column (2.2.0).
- **Per-role permission drill-down** in the PIM Manager (2.2.0).
- **Temporary Access Pass delivery** by email, Teams or Slack, with a scheduled start time using relative
  expressions such as "+2d 8:00" (2.2.0).
- Environment-specific data removed from shipped baseline files (2.2.1).

## v2.1.0 – v2.1.7 (summary)

- **MSP variant** (2.1.0): MSP-owned admins come from a central source, and the MSP can centrally disable or
  revoke an admin — only for admins the customer's security officer has opted in with a code in their own
  Key Vault.
- **Mapper renamed to PIM Manager** (2.1.1). **Upgrade note:** update any shortcuts or scheduled tasks that
  started the old Mapper.
- **PIM Manager**: pre-flight validation with bulk Fix all, multi-step wizards, a tenant cache and dropdown
  pickers (2.1.2). **Upgrade note:** refresh the tenant lists once after updating.
- **Server-side filtering** of admins and groups by naming convention, and naming-aware wizards (2.1.3).
  **Upgrade note:** set your admin account and group patterns in the naming convention configuration;
  without them the engine warns and reads unfiltered.
- Hotfixes for naming convention loading, row removal feedback and an engine crash on empty dates
  (2.1.4 – 2.1.6).

## v2.0.0 — The PIM v2 toolkit

- **PIM Manager (then called Mapper)**: see and edit the delegation model as a graph or grid, with a diff
  before every commit.
- **PIM Activator**: an Edge extension for bulk activation of PIM for Groups memberships.
- **One-step engine app registration setup**.
- **Engine**: a unique random password per new account instead of one shared initial password, optional
  Temporary Access Pass for new accounts, and reliable WhatIf mode.
- **Upgrade notes:** the engine identity needs the **UserAuthenticationMethod.ReadWrite.All** application
  permission to issue Temporary Access Passes; re-save your admin definitions to pick up the new pass
  columns; customer configuration files moved to the custom naming; the shared initial password secret is
  no longer used.

## v1.0.0 – v1.0.2 (summary)

- **Solution restructure** (1.0.0): one folder per engine, launchers per task, a shared module, logging,
  separation of shipped and customer configuration, and naming and filter extension points.
- **Missing baseline data files now ship** (1.0.1).
- **Launcher path fixes** (1.0.2). **Upgrade note:** rename an existing launcher configuration file to its
  custom name.
