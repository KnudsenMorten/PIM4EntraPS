# Database access (least privilege)

PIM Manager's database is designed to run for years without anyone administering it, with every component holding
only the rights its own job needs.

## The principles

1. **Entra sign-in only.** The SQL server accepts Microsoft Entra tokens only. There are no SQL logins and no passwords
   anywhere.
2. **One database user per component.** Each component signs in with its own managed identity, and its database user
   is created from that identity's client id. An identity that only pulls images has no database user at all.
3. **One role per component.** Each user is a member of its own custom role, never of a broad built-in role.
4. **No standing security right.** No component can grant itself or anyone else more rights. The updater may change the
   schema, and it can grant only through one signed procedure under fixed rules.
5. **An admin group that may stay empty.** The SQL server's Entra administrator is a group. After the install nobody
   needs to be in it, for years.
6. **Everything is audited.** SQL auditing sends every security event to your own Log Analytics workspace for 90 days.

## Who reaches the database, with which rights

| Identity | Database role | What it may do |
|---|---|---|
| Portal | pim_web | Read the store; write staged changes, settings and audit rows; no schema changes |
| Engine | pim_engine | Read and write the store it applies; read-only on the tenant registry |
| Updater | pim_updater + schema changes | Apply the schema; run the signed grant procedure; nothing else in security |
| As-built job | pim_asbuilt | Read one view (the installation's configuration, without people or secrets) |
| Publish job (managing tenant) | pim_publish | Read named objects; write its own last-run row |
| Downlink job (managed tenant) | pim_downlink | Read and write the settings it applies |
| Hybrid worker | pim_hybrid | Read settings and definitions; write its own results |
| Image pull identity | none | No database access |
| SQL admin group | server administrator | Empty after the install, or the Invardia Support app when you name one |

## The signed grant procedure

A new version sometimes needs a new grant, for example "the engine may read a new table". Instead of giving the
updater the right to grant anything, PIM Manager uses **one procedure** that applies a release's grants, and only
those, under fixed rules:

- the grantee must be one of PIM Manager's own roles (a `pim_` role), never a built-in role such as db_owner;
- the permission must be SELECT, INSERT, UPDATE, DELETE or EXECUTE;
- the object must be in PIM Manager's own schemas, never dbo, never another database;
- the procedure can also create the database user for a component, and only into that component's role.

The procedure is **signed with a certificate that lives inside the database**. The signature gives the procedure, and
only the procedure, the right to grant. The certificate:

- is created once, by the install or the security cut-over;
- expires on 31 December 2099, so it never needs renewing;
- has its **private key removed** right after signing, so nobody can sign anything else with it;
- has no password that anyone ever sees or stores.

If anyone changes the procedure, SQL Server drops the signature and the procedure loses its rights. The updater may
only **run** the procedure; on its own it is refused when it tries to grant anything. The procedure's rules are general
enough for every future release, so it never needs to be changed or re-signed.

These properties are checked on a live installation: the updater can grant through the procedure and is refused
without it; the engine cannot run the procedure; a built-in role and the dbo schema are refused.

## Five years without contact

Most installations are never in contact with Invardia. The design holds for that:

- Every update applies its own schema and grants, using only the updater's own database user and the signed procedure.
  No update ever needs the admin group, a person or the Support app.
- Nothing expires: no password, no secret, no certificate that needs renewing.
- If you ever want help, a Global Administrator adds the Invardia Support app to the SQL admin group. That is an
  Entra change, so it needs nobody inside the database. If the group itself is gone, an Owner of the SQL server points
  the server's Entra administrator at a new group. The database can never be locked out for good.

## How an existing installation moves to this model

Installations made before this version move in two runs, one environment at a time, Invardia's own environment first:

1. **Run 1 (additive):** the roles, the signed procedure and its certificate are installed and every component user is
   added to its role. Nothing is taken away.
2. **Run 2:** after a clean update with run 1 in place, the broad built-in roles are removed and the updater leaves the
   admin group.

Each run shows its plan first, records what existed before (a rollback record) and reads every change back. Every
statement is recorded with its reason before it runs.
