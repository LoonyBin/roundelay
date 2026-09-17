# Reference — Retained state

The server is storage-agnostic, but the behaviour specified across the five layers implies
facts it must remember. **[S]** This is the complete set; anything else an
implementation keeps is its own business.

| Facts | Required by |
|---|---|
| **Per op** — envelope bytes; transport position; Workspace; class; key epoch; op id; author; author key id; author position; reprised-by position; **envelope hash, from the moment the bytes are dropped** | idempotency, chain check, epoch floor, prune cross-checks, `include_reprised`, `prune_target_attestation_mismatch` once the bytes are gone |
| **Uniqueness** — `(workspace, author, op_id)` and `(workspace, author, author_seq)` | idempotency and the author chain; **enforced by storage, not application code** |
| **Per device** — id; the **registered** control signing key, content signing key and sealing key; the three derived key ids | `author_member_mismatch`, the shell record, and the interval-zero value of every row below |
| **Per (Workspace, device, key name)** — the key and its derived id; the `amend_id` that opened the interval; start position; end position (**write-once**); several intervals per name | `member_amend` interval closure at the amend's commit, the in-force lookups (`kex_key_id_not_registered`, the auth challenge), `author_key_class_mismatch` against **every** id held for a class, `amend_id_already_used` |
| **Per registration** — `(Workspace, device)`; member kind; **`holder_ref`, 32 opaque bytes** | the access gate, member listing, `unknown_grantee`, `no_registration` |
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

**[S]** The **envelope bytes** are the one entry an accepted `hard_prune` may drop
([The Log](../01-the-log.md)). Everything else on that row is the **tombstone** and
survives for ever — **ten facts, no fewer**: transport position, Workspace, class,
key epoch, op id, author, author key id, author position, reprised-by position, and
the envelope hash. That enumeration and the tombstone in
[The Log](../01-the-log.md) §7 are **one list**; a field added to either belongs in
both.

> Each is load-bearing once the bytes are gone. Without op id and author,
> `(workspace, author, op_id)` stops refusing a re-append and a destroyed op can be
> resurrected as a new one. Without class and reprised-by position, a repeat
> `hard_prune` cannot be judged against `hard_prune_target_is_prune` and
> `hard_prune_target_not_reprised`. Without the envelope hash, its attestation cannot
> be judged at all, and a false one lands silently.

**[S]** The envelope hash is materialised **at `hard_prune` time** — computed from
the bytes about to be dropped, or carried over from the attestation check just
performed on those same bytes, which computes the identical value. It is **never**
taken from the payload that asked for the destruction. While the bytes are still
held it need not be stored at all: it is a function of them, and a server may
compute it on demand.

> Taking it from the payload would make every later check circular — the first
> `hard_prune` would get to choose what every one after it must match, which is
> precisely the forgery the attestation exists to catch.

**[S]** A device's **registered** keys are its keys in every Workspace until a
`member_amend` lands there, and an amend is **per Workspace**
([Authority](../03-authority.md#member_amend)). The two rows are therefore not
alternatives: the per-device row is what a shell has and where every interval starts,
and the per-Workspace rows are what an envelope at a position is resolved against.

**[S]** The **auth challenge** is the one check that reads across them. It has no
Workspace in its route, so it accepts the control key in force in **any** Workspace
the device is registered in — which is a union over the rows above, materialised as
the route evaluates, and authoritative for nobody
([Authority §1](../03-authority.md#1-the-central-idea-permission-lives-in-the-log)).

**[S]** Quota, allowance and billing state are **not on this list**. Nothing derives
from them, no op records them, and a replacement rebuilt from the log is complete
without them — like rate-limit counters, which they resemble in every way that
matters here.

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

**[S]** A Workspace's **control tip** — the hash of the latest accepted control op's
payload ([Authority](../03-authority.md#the-control-chain)) — is likewise computed on
demand. The bytes it is computed from are always there: a control op is never a prune
target (`prune_target_is_control`), so no `hard_prune` can reach its envelope.

> Same reasoning, one step further along. A stored tip is a cache of a function of the
> log, free to drift from it, and the drift is spelled `control_chain_break` on a
> request that was correct — or, worse the other way, a chain the server stopped
> enforcing.

**[S]** A Workspace's **role table in force at a position** — the table carried by the
latest `role_table` op below it, or the profile's initial table where there is none
([Authority §7](../03-authority.md#the-table-in-force-and-how-it-changes)) — is
likewise computed on demand. The bytes are always there, for the reason the tip's are:
a control op is never a prune target, so no `hard_prune` reaches the certificate.

> A stored "current table" is a cache of a function of the log and the profile, free
> to drift from both, and the drift is a permission the server grants or refuses on
> its own authority — which is the one thing this layer says it cannot do. An
> implementation that indexes it is doing what it already does for grants, and that
> index is authoritative for nobody
> ([Authority §1](../03-authority.md#1-the-central-idea-permission-lives-in-the-log)).
>
> Note what is **not** derived: the profile's *initial* table is configuration, and a
> server refuses to start without it ([profile
> obligations](profile-obligations.md)). Derivation begins from that row, not from
> nothing.

## What a log replay can and cannot rebuild

**[S]** These are **derivable from the log alone**, and a replacement MAY rebuild them
by replaying it:

- Workspace existence and genesis position
- **the Workspace's current Root**, from its genesis and every handover since
- every grant, with role, granter, and start and end positions
- every delegation, with its key and its start and end positions
- every epoch's committed digest and rotate position, for epochs ≥ 1
- each device's registration facts, and which Workspaces it is registered in
- **each device's key intervals in that Workspace**, from its registration and every
  `member_amend` since — which is why an amend is an op rather than a route
- **the role table in force at every position**, from the profile's initial table and
  every `role_table` op since
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
