# Guards and Strict mode

PIM Manager can change privileged access across your tenant, so every change passes guards first. Guards are always on:
no guard can be switched off. Their limits are **counts**, never a share of a list.

## The guards with a limit

A SuperAdmin sets these limits on the **Guards** page, inside a fixed range. A stored value outside its range, or one
that cannot be read, is ignored and the default applies. An environment setting can lower a limit, never raise it.

| Guard | Protects against | Default | Range | Strict limit (default) |
|---|---|---|---|---|
| Commit removal check | A commit that takes many rows out of one list | 25 rows of one list in one commit | 5 to 200 | 12 |
| Removal budget | One engine run removing a lot in one scope (removals, prune, reconcile, offboarding, group deletes, queued deletes, a managed tenant's retraction) | 5 removals per scope per run | 1 to 25 | 2 |
| Mass-disable breaker | One run disabling many admin accounts | 3 accounts per run | 1 to 25 | 1 |
| Bulk revoke | A large revoke from the portal | 5 assignments in one batch | 1 to 25 | 2 |
| Account delete | Many account deletes in one run | 5 deletes per run | 1 to 25 | 2 |

Other guards hold changes whatever the numbers: the policy brake holds mass or weakening policy changes for **the
tenant's own SuperAdmin**, and the hybrid server batch limits how many servers are changed at once.

## What happens when a guard trips

| Outcome | What it means |
|---|---|
| Held | Nothing in that scope is applied; the exact list waits for a SuperAdmin's approval |
| Halted | The run stops before the change; the next run tries again |
| Refused | The request is not accepted, with the reason |
| Skipped | That one item is left alone and reported |
| Warning | Reported only; nothing is blocked |

Every trip is mailed, audited and reported. The mail subject names the environment and what needs doing, for example
`[Production] Action needed: removal budget held 7 removals [PIM Manager]`.

## How a held change is approved

- Only a **SuperAdmin of the tenant**, signed in to the portal, can approve or release. Developers and Invardia never
  approve on your behalf.
- An approval is bound to the **exact list**: a changed list is held again. It needs a reason, it is audited (who, when,
  why and every item), and it ends by itself (one run, at most 24 hours; a commit approval after 48 hours).
- Approvals and held lists are never restored from a backup or copied by an import, so a used approval cannot come back.

## Things no approval can unlock

The break-glass accounts, account deletion by a prune or a reconcile, shared workload assignments, objects the product
does not own and the last SuperAdmin of the portal are locked. They have no limit and can never be approved or released.

## The one delete path

The engine never deletes an account by itself, and a prune or reconcile never deletes anything: an undefined account is
only reported. The only delete is an operator's **Delete account** on an account PIM Manager manages (typing DELETE is
the approval). Sessions are revoked first; never a break-glass account; at most the account-delete limit per run. Entra
keeps a deleted user restorable for 30 days.

## Strict mode after an engine change

For **24 hours** after an update that changed the engine's code, every numbered limit is halved:

```text
effective limit = max(1, floor(configured limit / 2))
```

So a limit of 1 stays 1, and 25 becomes 12. Strict covers every guard in the table above, the policy brake counts and
the hybrid server batch.

- The **Guards** page shows the configured and the effective limit and when Strict ends. The portal header shows
  "Guard mode: Strict" to SuperAdmins.
- A SuperAdmin can end Strict early, with a reason (at least ten characters). Ending it is audited.
- A Strict trip is held and approved like any other trip.
- The first version that brings Strict to an installation only records the engine's fingerprint, so the switch itself
  never starts it.
- Whether a release changed the engine is decided when it is published, from a fingerprint of the engine code.

## How a trip reaches support

When telemetry is on, a guard trip is reported to Invardia (the guard, the outcome and the counts; no names). Invardia's
support turns a pattern of trips into a ticket. You see the trip at once in the portal and in the mail.
