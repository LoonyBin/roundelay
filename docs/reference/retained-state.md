# Reference — Retained state

The server is storage-agnostic, but the behaviour specified across the five layers implies
facts it must remember. **[S]** This is the complete set; anything else an
implementation keeps is its own business.

| Facts | Required by |
|---|---|
| **Per op** — envelope bytes; transport position; Workspace; class; key epoch; op id; author; author key id; author position; reprised-by position | idempotency, chain check, epoch floor, prune cross-checks, `include_reprised` |
| **Uniqueness** — `(workspace, author, op_id)` and `(workspace, author, author_seq)` | idempotency and the author chain; **enforced by storage, not application code** |
| **Per device** — id; control signing key; content signing key; sealing key; the three derived key ids | `kex_key_id_not_registered`, `author_member_mismatch`, `author_key_class_mismatch` |
| **Per registration** — `(Workspace, device)`; member kind; **holder Root public key** | the access gate, member listing, `unknown_grantee`, `no_registration` |
| **Per Workspace** — existence and genesis position; **current Root public key** | `workspace_not_created`, certificate verification, `cert_root_pk_mismatch` |
| **Per delegation** — `(workspace, delegation_id)`; delegate public key; start position; end position (**write-once**) | root-authority signature checks, `delegation_id_already_used`, `already_revoked` |
| **Per grant** — `(workspace, grant_id)`; device; role; granter; start position; end position (**write-once**) | the positional verdict, `grant_id_already_used`, `already_revoked` |
| **Per (Workspace, epoch)** — committed digest; escrow wrap; rotate position (absent at epoch 0) | the digest gate, `rotate_not_materialised`, the epoch-keys omission rule |
| **Per (Workspace, device, epoch)** — sealing key id; wrap | `keywraps/me`, write-once |
| **Per vault slot** — locator; version; blob; signature; pinned Root public key | trust on first use, `vault_version_regression`, `bad_vault_signature` |
| **Vault fetch audit** — append-only, one row per read served | the audit rule |
| **Refresh tokens** — irreversible hash; device; expiry; revocation | the revocation cascade |
| **Challenge nonces and rate counters** — with expiry | device login, rate limits |
| **Per extension binding** — `(Workspace, member, extension class)`; bound NAME; start position; end position (**write-once**); several intervals per key | judging `0xC0–0xFF` ops against their author's own binding at that position; **only where extensions are implemented** |

**[S]** The vault slot's pinned Root is **not** write-once. It moves when a write
carries a different `root_pk` and is signed by the key currently pinned — the vault's
half of a root handover ([Keys](../04-keys.md)).

**[S]** A vault slot is **keyed** by locator alone: it has no owner and no Workspace.
It is not thereby unlinkable. Two slots holding the same Root under different secrets
carry the **same pinned Root public key**, so grouping on that column returns every
wrapping of one identity.

> Worth stating because the key and the contents point in opposite directions. There
> is nothing to key a slot by except its locator — the server holds no account record
> — but the pin is in the row regardless, because every later write is verified
> against it. The linkability is a consequence of the pin, not of the key, and it
> cannot be removed without removing the pin.

**[S]** A deployment MAY use that grouping to **bound slots per Root**, and SHOULD.
Founding is admitted once ([Identity](../02-identity.md)) and locators are the
caller's to choose, so nothing else limits how many slots one admitted identity
writes.

## Derived, never stored

**[S]** A Workspace's **current epoch is the maximum materialised epoch**, computed on
demand.

> A stored "current epoch" would be a cache of that maximum, free to disagree with the
> records that produced it — and `rotate_epoch_conflict`'s `expected_from_epoch`
> depends on it being right.

## What a log replay can and cannot rebuild

**[S]** These are **derivable from the log alone**, and a replacement MAY rebuild them
by replaying it:

- Workspace existence and genesis position
- **the Workspace's current Root**, from its genesis and every handover since
- every grant, with role, granter, and start and end positions
- every delegation, with its key and its start and end positions
- every epoch's committed digest and rotate position, for epochs ≥ 1
- each device's registration facts, and which Workspaces it is registered in
- every extension binding — which member agreed to which NAME for which class, over
  which span of positions — because `ext_binding` ops are in the log, which is why
  the binding was put there rather than in configuration

**[S]** These are **not in the log** and MUST be backed up independently:

| Not in the log | Consequence of losing it |
|---|---|
| every member wrap | every device locked out of every epoch |
| every escrow wrap | recovery of epoch keys from the vault becomes impossible |
| the epoch-0 record | no rotate op creates it; its digest arrived in a request body |
| every vault slot | no recovery path for any identity — but see below |
| shells | devices whose registration has not yet landed must re-present it |
| refresh tokens and the vault fetch audit | sessions and the audit trail |

**[S]** **Losing every vault slot does not stop the server verifying anything.** A
Workspace's Root comes from its genesis and its handovers, both of which are ops. The
log still replays, every control op still verifies, and every device that already
holds its own keys keeps working.

> Worth stating because the opposite is the intuitive guess, and it drives the wrong
> backup priority. The vault is the *users'* recovery path, not the server's trust
> anchor. An operator who loses it has locked out everyone who needed to enrol a fresh
> device from a credential; they have not broken the log.
>
> The real gap in a replay-only restore is the **key plane** — the wraps. Those arrive
> in request bodies rather than as ops, and without them the log is a pile of
> ciphertext that every device is locked out of.
