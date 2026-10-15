# Day-to-day operations

## Stage, then commit

Every change made in the portal is **staged** first and reaches the tenant only when it is **committed**. Staged
changes are kept in the database, not in the browser, so a closed tab loses nothing. A commit records every row's
before and after, who initiated it and who approved it, in the same transaction as the change.

## Approvals

- **Second approver (Pro, on by default):** changes classified as sensitive (privileged roles, tier 0 and 1, guests,
  offboarding) need a second person. Self-approval is always refused.
- **Always on:** changing the break-glass list needs a second SuperAdmin.
- **Guard approvals:** see [Guards and Strict mode](guards).

## Undo, backups and restore

- **Undo:** a commit can be undone by planning its inverse and committing it through the same guards. A SuperAdmin can
  undo any commit; an Admin their own.
- **Snapshots:** a snapshot is taken before every apply.
- **Configuration backups:** on a schedule, kept 90 days by default (1 to 3650). A restore shows a plan first and lets you
  pick what to restore.

## Scheduled jobs

The engine and its helpers run on schedules you can see and change on the **Jobs** page. Each job can be paused on its
own, or all at once. **Run now** starts the engine immediately. The status of a job is its latest run; it heals itself
when the next run succeeds, so there is nothing to acknowledge.

## Mail

PIM Manager mails Temporary Access Pass codes to new admins, approval requests, guard trips and failures. Every subject
follows one format:

```text
[<Environment>] <Failed | Warning | Action needed:> <what happened> [<ticket>] [PIM Manager]
```

at most 120 characters, so a mail rule can sort on the environment and the severity word.

## What to watch

- The portal's home page: failed jobs, held changes and items that need an action.
- The **Guards** page while Strict mode is on after an update.
- Your Log Analytics workspace: the SQL security audit and the container logs.
