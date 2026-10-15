# Upgrade notes

Updates are automatic through the updater job (see [Releases, rings and updates](release-and-updates)). This page lists
what changes for an installation that already runs.

## Mail subjects

Every mail subject now starts with the environment's name and, when it matters, a severity word: `Failed`,
`Warning` or `Action needed:`. Update mail rules that match on the old subjects.

## Strict mode

The first version with Strict mode only records the engine's fingerprint. Strict starts at the **next** update that
changes the engine, for 24 hours (see [Guards and Strict mode](guards)).

## Install names

Each installation records the names of its own resources (portal, engine, updater, jobs, the SQL admin group). Every
script and job reads them from that record, so an installation with its own names keeps working through updates.
Existing installations record the names they already use; nothing changes for them.

## The security cut-over

Some security improvements change an installation that already runs, so they are **never made by the updater**. They
are made once, per environment, through a scripted cut-over: it shows a plan first, reads every change back and writes
a rollback record.

| Change | What it does |
|---|---|
| Image-pull identity out of the SQL admin group | The identity that pulls images has no database access |
| No schema right for the portal | The portal can no longer change the database schema |
| 8-hour fixed sign-in session | Sessions end after 8 hours, whatever the activity |
| Updates fetched from invardia.com | No storage token is kept in the updater |
| SQL auditing | Security events go to your Log Analytics workspace for 90 days |
| Least-privilege database roles | Run 1 installs the roles and the signed grant procedure; run 2 removes the broad built-in roles (see [Database access](sql-access)) |

A new installation gets all of this from the install itself.

## Documentation inside the portal

The portal's **Documentation** menu shows these pages for the installed version, also on private-network installations.
