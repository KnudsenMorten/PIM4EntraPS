# Releases, rings and updates

## From code to your installation

```text
build -> offline tests -> signed release -> ring 0 -> ring 1 -> APPROVED -> ring 2 (waves) -> ring 3
                                              |          |                      |
                                       per-environment checks after each ring: runs, failures, version, deletions
```

1. **Build and test.** Every release is built from a tagged source version and passes the offline test gate before it
   is published.
2. **Publish.** A dedicated publisher identity publishes the release with a fingerprint of the engine code and says
   whether the engine changed since the previous release. A publish whose answer is lost (a server error) is read back
   before anything is retried, so a release is never published twice.
3. **Rings.**

| Ring | Who | How a version gets there |
|---|---|---|
| 0 | The vendor's own installation | Every release, first |
| 1 | Test installations | Every release, after ring 0 |
| 2 | Design partners | Only a version the release owner marked **APPROVED** (with a reason, audited), and only after it ran in a lower ring |
| 3 | Everyone | The same approval |

4. **Waves.** Inside ring 2 or 3, a version can be served first to a named group of installations (a wave), for
   example "Ring 2 - first group". Stopping a wave never moves an installation back.
5. **Evidence.** After a release that changed engine code, installations report more often for the first hours, and
   the release collects evidence (guard trips, the engine's own changes, run results) for the owner's decision on the
   next ring.
6. **Checks after each ring.** Per installation: the engine runs since the update, failures, the installed version and
   an audit of every removal in the directory.

## How your installation updates

- The **updater job** runs daily (03:00 UTC by default). It asks for the version approved for your ring, verifies the
  signed manifest (RS256, RSA 4096, public key embedded in the product), checks the archive's hash and size, builds
  the product from source **inside your own registry**, applies the database schema and grants (see
  [Database access](sql-access)) and rolls the portal and jobs. No pre-built vendor image is pulled.
- Replays are refused (each manifest carries a sequence number), and so are downgrades unless you allow them.
- After an update that changed the engine, **Strict mode** halves the guard limits for 24 hours (see
  [Guards and Strict mode](guards)).

## Your controls

| Control | Effect |
|---|---|
| Hold | `PIM_UPDATE_HOLD=1` freezes the installation at its version |
| Schedule | Change the updater's schedule |
| Manual only | Remove the update job; you update by hand |
| Minimum-from version | Prevents skipping a required step |
| Downgrades | Refused unless you allow them |

## Rollback

A release that misbehaves is fixed forward with a new release through the same rings. An installation can also be
re-pointed to an earlier approved version, which the updater rolls like any other.
