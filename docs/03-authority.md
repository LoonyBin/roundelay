# Authority

*What a device is allowed to write, and how that decision is recorded.*

[Identity](02-identity.md) established which key is speaking. This layer decides
what it may say — and, crucially, records that decision **inside the log itself**, so
that every device can work it out independently and nobody has to trust the
server's opinion.

---

## 1. The central idea: permission lives in the log

The obvious design is a permissions table on the server. This is not that.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  THE LOG                                                    │
   │                                                             │
   │   1: genesis      "this Workspace exists; here is Root"     │
   │   2: register     "laptop's key is THIS key"                │
   │   3: grant        "laptop may write content"                │
   │   4: content      ← legitimate, because of op 3             │
   │   5: register     "phone's key is THIS key"                 │
   │   6: grant        "phone may write content"                 │
   │   7: content      ← from phone, legitimate                  │
   │   8: revoke       "op 3's grant is over"                    │
   │   9: content      ← from laptop, REFUSED                    │
   └─────────────────────────────────────────────────────────────┘
              │                              │
              ▼                              ▼
     the server replays this        every device replays this
     to refuse writes cheaply       to decide what to trust
              │                              │
              └────────── same answer ───────┘
                     but the log is the truth
```

**[S]** The server keeps an index of all this so it can refuse writes without
replaying the log every time. **That index is authoritative for nobody.** Tampering
with it cannot elevate anyone's authority, because every device derives the same
answer from the signed ops.

> This is what makes a hostile or compromised server survivable. It can withhold
> ops, and it can refuse writes it should have accepted. It cannot *grant* anyone
> permission, because it cannot forge a signature.

---

## 2. Root: the trust anchor

**Root is an Ed25519 keypair that never authenticates to the server** and never
appears in an `Authorization` header. It is not a credential.

```
   ┌────────────────────────────────────────────────────────────┐
   │  ROOT KEYPAIR                                              │
   │                                                            │
   │  · random, never derived from a credential                 │
   │  · at rest, exists ONLY wrapped, inside a vault record     │
   │  · held by a device only during a ceremony, then dropped   │
   │  · the server never has it, in any form                    │
   └────────────────────────────────────────────────────────────┘
```

Root authorises by **signing documents that travel inside ops and requests**:

| Root signs | Which means |
|---|---|
| a **genesis** certificate | this Workspace exists, and this key is its Root |
| a **registration** certificate | this device's keys really are that device's |
| a **grant** for the authority role | the only way to create one |
| a **revoke** of the authority role | the only way to remove one |
| a **handover** certificate | the only way to move a Workspace to a new Root |
| a **vault** record | the only way to write a vault slot → [Keys](04-keys.md) |

**[S]** A Root-signed control payload is accepted **regardless of the author's
permissions**.

> That is how a device with no permissions at all posts the batch that registers and
> grants it. It is safe because Root's signature is the strongest authority in the
> system — stronger than any permission the batch could have carried.

So authorisation here is not two-valued. A request carries a credential **and** may
carry Root-signed documents, and the second can authorise what the first cannot.
[Keys](04-keys.md) states it most compactly in the vault: the locator gets the
request *to* the slot; the Root signature gets it *into* the slot.

### Root is also the identity

**[W]** A Workspace's id is derived from the public key of the Root that **founded**
it (§3). The trust anchor and the thing it anchors are bound by arithmetic, not by a
record somebody keeps.

```
       founding root_pk ──────►  the Workspace id, for ever
                          │
   current root_pk ───────┴───►  the key every certificate is checked against
        (materialised from the log — the same one, until a handover)
```

**[W]** The two are the same key until a `root_handover` moves the second one (§9).
The first never moves: a Workspace's id is fixed at genesis.

> Which is why there is normally no pinning step in this layer and no window during
> which a Workspace's Root is provisional. A key either derives the Workspace it
> claims or it does not, and every server computes that answer identically from
> nothing it had to be told.
>
> A handover is the one exception, and it is deliberate. Without it a Workspace's
> Root could never be replaced, so a compromised Root would be permanent — no
> revocation, no rotation, no remedy anywhere in the system. The price is that a
> Workspace which has used the escape hatch answers reachability from materialised
> state rather than from arithmetic alone.

---

## 3. Which Workspaces a Root can address

Before any permission question, a coarser one: is this Workspace id something this
identity may name at all?

**[S]** Every Workspace-scoped route evaluates a **reachability predicate** first,
before anything else, and refuses `403 workspace_not_reachable` when it is false.

```
   reachable(root_pk, workspace_id) → true / false
```

**[S]** The `root_pk` is whatever the request establishes: the **certifying Root**
recorded beside the device ([Identity](02-identity.md)) when the credential is a
device token, or the `root_pk` in the body when a registration certificate is being
presented.

**[P]** The predicate is a **profile decision**, and there is **no permissive
default**.

> Be clear about what it does and does not bound. It decides which ids *one*
> identity may address; it does not bound how many identities exist, because anyone
> can mint an Ed25519 keypair without asking. Limiting that is admission's
> job ([Identity](02-identity.md)), and a profile that leaves reachability strict
> while leaving admission `open` has bounded nothing.

The core names two policies; a profile may define others.

### Policy `derived`

**[P]** The profile freezes an ordered list of UUID namespaces. A Root's Workspace
ids are computed from them — the same answer on every device, offline, with no round
trip.

```
   root_pk ──┬── uuid5(NS₀, root_pk) ── Workspace 0
             ├── uuid5(NS₁, root_pk) ── Workspace 1
             └── …

   reachable(r, w)  ⟺  w is one of those            ← the founding Root
                       OR  r is w's current Root    ← after a handover, §9
```

**[S]** The second disjunct is the only part of this predicate that consults stored
state, and it is false-by-absence: a Workspace that has never handed over has a
current Root equal to its founding one, so the first disjunct already answers.

**[W]** UUID version 5 as in RFC 9562: SHA-1 over the 16 namespace bytes followed by
the name bytes, truncated to 16, with version and variant bits set. The name is the
**32 raw bytes of Root's Ed25519 public key** — not a base64, hex or any other
spelling of them.

> Raw bytes are the point. A textual identifier has spellings — case, padding,
> whitespace, normalisation form — and two peers that spell it differently derive
> different Workspaces and never converge, with nothing reporting the divergence
> because each side is internally consistent. A public key has no spelling. The
> hazard is not mitigated here; it does not exist.

**[P]** Namespaces are **frozen literals in the profile**, never recomputed at
startup.

> Recomputing them would make Workspace identity depend on two languages' UUID
> implementations staying byte-stable for ever. If client and server disagree, every
> request fails `workspace_not_reachable` with nothing to debug.

### Policy `explicit`

**[P]** Reachable iff the server holds an accepted genesis for that Workspace *and*
the Root named in it is the caller's.

**[P]** Admission at device registration ([Identity](02-identity.md)) is what
gates founding, because the first op into a fresh Workspace cannot satisfy the
predicate.

> That bootstrap gap is the cost `derived` avoids, and the reason most profiles start
> there. `explicit` earns its keep only when Workspace ids must be assigned rather
> than computed.

---

## 4. Control ops

Permission changes are ops like any other — class `0x80`, in the same log, in the
same order. Server-read, like every class with bit 7 set.

**[W]** `0x80` bodies are **unencrypted JSON**, for ever. Six types:

```
   workspace_genesis   the Workspace exists; here is its Root
   member_register     this device's keys are these keys
   grant               this device holds this role
   revoke              that grant is over
   root_handover       the Workspace's Root is now this other key
   rotate              the Workspace moved to a new content key → Keys
```

**[W]** Every one carries the same two mandatory fields:

```json
{"type": "grant",
 "prev_control_hash": "<hex64>",
 …type-specific fields…}
```

### The control chain

**[W]** `prev_control_hash` is SHA-256 over the **previous control op's payload
bytes** — the unpacked payload, not the envelope, not a re-serialisation.

```
   control ops form their own chain, across all authors:

     genesis ──► register ──► grant ──► register ──► grant ──► revoke
        │           │           │          │           │         │
      zero        hash of     hash of    hash of     hash of   hash of
      link        genesis     register   grant       register  grant
```

**[W]** Because a chain link points at bare bytes with no surrounding context,
**every control payload must be self-identifying: `type` is mandatory in every type,
for ever.**

**[W]** **An all-zero link is genesis-only, in both directions.** A non-genesis type
carrying one is refused; a genesis carrying anything else is refused.

**[C]** A device served a truncated history MUST detect it by this rule, and MUST NOT
accept a non-genesis control op with a zero link even when its own view is empty.

> That is the whole point of the rule. Without it, a hostile server could serve a new
> device a history that starts in the middle — omitting a revocation, say — and the
> device would have no way to notice. With it, the only op that may claim "I am the
> beginning" is the one that genuinely is.

---

## 5. The certificates

Five of the six control types carry a **certificate**: a frozen, separately signed
document. The sixth (`rotate`) does not, and §9 explains why.

```
   ┌─────────────────────────────────────────────────────┐
   │  CONTROL OP (class 0x80)                            │
   │                                                     │
   │   type, prev_control_hash                           │
   │                                                     │
   │   ┌───────────────────────────────────────────┐     │
   │   │  CERTIFICATE  (opaque bytes)              │     │
   │   │  signed by Root, or by a granting device  │     │
   │   └───────────────────────────────────────────┘     │
   │   signature over those exact bytes                  │
   │                                                     │
   └─────────────────────────────────────────────────────┘
        the whole envelope is ALSO signed by its author
```

Two signatures, and they say different things. The **envelope** signature says "this
device sent this". The **certificate** signature says "this authority approved this
fact". They come apart because the approver is usually not the sender — Root signs a
registration, but the *device being registered* is what posts it.

**[W]** The certificate is **signed bytes, never re-serialised JSON**. Precisely:

```
   1. parse ONLY enough to pick the verification key
        (for grant/revoke: who claims to be the authority)
   2. verify the signature over the LITERAL decoded bytes
   3. only then parse the rest
   4. record nothing before step 2 succeeds
```

> "Verify, then parse" is the usual slogan and it is not quite true here — you cannot
> know whose key to check against without reading one field. What must never happen
> is *acting on* an unverified certificate. The parse in step 1 picks a key and
> decides nothing.

**[S]** The same four checks apply to a registration certificate presented at
`POST /v1/members` ([Identity](02-identity.md)) rather than inside an op, under the
same codes. One certificate, one vocabulary, whichever door it arrives at.

### The five documents

```json
// registration — signed by Root
{"workspace_id": "…", "member_id": "…", "member_kind": "<token>",
 "sign_pk": "<b64 32B>", "sign_key_id": "<b64 8B>",
 "kex_pk":  "<b64 32B>", "kex_key_id":  "<b64 8B>",
 "registered_at_hlc": [wall_ms, counter, "<hex32>"]}

// genesis — signed by Root
{"workspace_id": "…", "root_pk": "<b64 32B>",
 "founder": { …the same key block… },
 "created_at_hlc": [...]}

// grant — signed by Root, or by a device that holds the authority role
{"workspace_id": "…", "grant_id": "…", "member_id": "…",
 "role": "<token>", "granter": "root" | "<uuid>",
 "granted_at_hlc": [...]}

// revoke — signed by Root, or by a device that holds the authority role
{"workspace_id": "…", "revoke_id": "…", "grant_id": "…",
 "revoker": "root" | "<uuid>",
 "revoked_at_hlc": [...]}

// root_handover — signed by the OUTGOING Root
{"workspace_id": "…", "from_root_pk": "<b64 32B>", "to_root_pk": "<b64 32B>",
 "handed_over_at_hlc": [...]}
```

**[W]** A handover is signed by the key it retires, never by the key it installs.

> Only the outgoing Root can attest that the succession is intended. A certificate
> signed by the incoming key would prove nothing — anyone can mint a keypair and
> claim to be somebody's successor.

**[W]** A handover carries **no id of its own**, unlike a grant or a revoke. Nothing
ever names one, and its `from_root_pk` already makes it unrepeatable: once it lands,
the Workspace's current Root has moved, so a second handover from the same key is
refused by the ordinary rule rather than by an id check.

**[W]** The `*_hlc` fields are logical clocks: `[wall_ms, counter,
member_id_as_32_hex_chars]`. The server stores them and never orders by them.

**[W]** Both key ids inside a certificate are **derivations** and MUST be
cross-checked against SHA-256 of the key beside them. A claimed id that disagrees is
a forgery attempt, not a variant spelling.

### Genesis carries its own founder's registration

**[W]** A genesis certificate embeds a full key block for the device that founded the
Workspace, and that block **is** that device's registration. The founder writes no
separate `member_register`.

> It has to work this way. The envelope is signed by the founder's key, but nothing
> earlier in the log says what that key is — genesis is op 1. So the certificate has
> to introduce the key that signed the envelope carrying it. Chicken and egg,
> resolved by putting the egg inside the chicken.

---

## 6. Roles

**[P]** The profile supplies a **role table**: a set of role tokens and, for each,
which op classes it permits.

**[W]** The core fixes four things, and a profile MUST NOT relax any of them:

| # | Rule |
|---|---|
| 1 | exactly one role is named `owner` — the **authority role** |
| 2 | `0x80` ops, when not Root-signed, require `owner` and no other role |
| 3 | an `owner` grant may only be created **and** only revoked with `granter`/`revoker` = `root` |
| 4 | an unrecognised role token is refused `unknown_role`, never ignored |

> Rule 3's symmetry is the point. If an owner could mint another owner, a compromised
> device could create an attacker-owner cheaply, while removing one still cost Root —
> which means a vault fetch and a ceremony. That asymmetry favours the attacker.
> Making both ends cost Root closes it.

**[S]** In rules 2 and 3, `root` means the Workspace's **current** Root. After a
handover, new `owner` grants and revokes of old ones are both signed by the incoming
key.

> `granter: "root"` names an authority, not a particular key. Resolving it at
> verification time is what lets a Workspace that has changed Root keep revoking the
> grants its old Root issued — which is most of the point of handing over after a
> compromise.

**[W]** The role table is **not covered by any signature**, so two peers with
different tables disagree about which ops are legitimate. It is therefore part of
profile identity: it MUST NOT be widened without changing the protocol namespace or
the certificate version. Fail-closed handling of unknown roles is what makes such a
disagreement detectable rather than silently divergent.

**[W]** Root-signed control payloads need **no role at all** — the row a matrix
cannot show.

### Member kinds

**[P]** The profile declares the legal `member_kind` tokens — for instance, "this is
a person's device" versus "this is an automated service".

**[W]** `member_kind` is required in every registration certificate. A token outside
the profile's set is refused `unknown_member_kind`.

**[P]** The profile MAY supply an admissibility rule:

```
   admits(workspace, member_kind, role) → true / false
```

**[S]** A grant the rule rejects is refused `member_kind_forbidden`, carrying
`member_kind`.

> This is how a profile makes a boundary *structural*. If some class of member must
> never reach some Workspace, the rule enforces it at the door — so it holds even if
> a future code path forgets to check.

---

## 7. The two bars

Not every route needs the same thing. Every Workspace-scoped route sits at one of
exactly two levels.

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  BAR 1 — MEMBER-GET                                             │
  │  any UNREVOKED device token whose Root derives the Workspace    │
  │  ── no permission grant required ──                             │
  │                                                                 │
  │  GET /ops   GET /members   GET /keywraps/me   WS /signal        │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │  BAR 2 — MEMBER + LIVE GRANT                                    │
  │  a live grant whose role permits the operation                  │
  │                                                                 │
  │  POST /ops (per op, by class)   GET /epoch-keys                 │
  │  PUT /keywraps (authority role)                                 │
  │                                                                 │
  │  one exception: a Root-signed control payload needs no grant    │
  └─────────────────────────────────────────────────────────────────┘
```

**[S]** Three routes sit outside the bars entirely, because they present no
credential for a bar to test:

```
   GET  /v1/vault/{locator}     nothing — knowing the locator is the claim
   PUT  /v1/vault/{locator}     a Root signature inside the body
   POST /v1/members             a Root-signed certificate inside the body
```

> `POST /v1/members` still evaluates the predicate, but against the Workspace its
> *certificate* names and the `root_pk` its body carries — which is what lets a
> founding device register keys for a Workspace that does not exist yet. The bars
> describe credentials, and that route presents none.

**[S]** "Revoked" is defined **per Workspace**: a device is revoked in a Workspace
iff it has at least one grant there and none live there. Revoked in one Workspace
means nothing in another.

**[S]** A device with **zero** grants in a Workspace is **not** revoked, and passes
bar 1.

```
   grants held here     live?     bar 1?
   ────────────────     ─────     ──────
   none                  —        ✓  pre-grant: enrolling, hasn't been granted yet
   one or more           yes      ✓  ordinary
   one or more           none     ✗  revoked
```

> The pre-grant case is what lets an enrolling device pull and replay the control log
> before it holds any permission — which it must, to discover whether the Workspace
> exists at all. It reopens nothing: reads were already limited by reachability to
> Workspaces the device's own Root derives, and the denial-of-service concern lives
> on the write path.

---

## 8. Stage 2 — permission checks on ordinary ops

This is where the [append pipeline](01-the-log.md#the-pipeline) consults this layer,
for every class but control.

**[S]** In order:

| # | Refusal | Cause |
|---|---|---|
| 1 | `409 workspace_not_created` | no genesis accepted for this Workspace |
| 2 | `403 no_live_grant` | no live grant here; `revoked: true` if there once was |
| 3 | `403 role_forbids_op_class` | grants exist, but no role permits this class; carries `op_class` and the live `roles` |
| 4 | `409 key_epoch_stale` / `key_epoch_unknown` | → [Keys](04-keys.md) |

---

## 9. Stage 4 — verifying control ops

**[S]** Framing and decoding first, in this order:

```
   invalid_body_length ─► payload_overruns_body ─► non_zero_padding
        ─► malformed_control_payload ─► unsupported_control_type
        ─► unknown_role ─► owner_grant_requires_root ─► control_chain_break
```

**[S]** `control_chain_break` is checked **before** any type-specific rule, so a
misplaced genesis with a non-zero link answers `control_chain_break` rather than
`genesis_not_first`.

**[S]** Then, **unless the payload is Root-signed**, the authority-role check for
`0x80`: `no_live_grant` or `role_forbids_op_class`.

**[S]** One rule spans types: **an author's first op must be the control op that
registers it** — a `member_register`, or the genesis that embeds one. Otherwise
`422 member_register_not_first`, carrying `author_seq`.

### `workspace_genesis`

**[S]** In order:

| # | Refusal | Cause |
|---|---|---|
| 1 | `409 genesis_not_first` | not at batch index 0, or the Workspace already exists |
| 2 | `403 workspace_not_reachable` | with `index` |
| 3 | `422 member_register_not_first` | the founder's `author_seq` is not 1 |
| 4 | `422 bad_root_signature` | Root did not sign these certificate bytes |
| 5 | `422 cert_workspace_mismatch` | the certificate names another Workspace |
| 6 | `422 cert_root_pk_mismatch` | the Root inside does not derive this Workspace |
| 7 | `422 cert_member_mismatch` | the founder named is not the envelope's author |
| 8 | `422 cert_key_mismatch` | the founder's key is not this device's registered key |

**[S]** Genesis carries **no admission check**. The device posting it already holds a
token, which it could only have obtained from a member record, which was the admitted
act ([Identity](02-identity.md)).

**[W]** `cert_root_pk_mismatch` and `bad_root_signature` **MUST remain distinct
codes.**

> A server that can only say `bad_root_signature` destroys information a skewed
> device cannot recover. The first means *this certificate names a Root that is not
> this Workspace's* — a client that built the document against the wrong key, or
> posted it to the wrong path, both with a real remedy. The second means *these bytes
> are forged* — not recoverable. Collapsing them is a contract violation, not a
> simplification.

> A second genesis is not a fork for the server to resolve: it holds no control chain
> of its own, so it refuses and leaves the tie-break to the devices that do. Two
> holders of one Root may legitimately both observe an empty log and both author one.
> Exactly one lands; the loser always gets `genesis_not_first`, including when the
> race is only caught at commit time.

### `member_register`

**[S]** In order: `member_register_not_first`, `bad_root_signature`,
`cert_workspace_mismatch`, `cert_member_mismatch`, `cert_key_mismatch`.

> No admission check here either, and for the same reason: this op is authored under
> a device token, and obtaining one is what admission gated.

### `grant`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 cert_granter_mismatch` | two causes — see below |
| `422 bad_grant_signature` | the named authority did not sign these bytes |
| `422 owner_grant_requires_root` | an `owner` grant not granted by Root |
| `422 unknown_grantee` | three causes — see below |
| `422 member_kind_forbidden` | the profile's rule rejects it |
| `409 grant_id_already_used` | a *different* op already used this grant id |

**[S]** `cert_granter_mismatch` covers: the certificate's own `granter` disagrees
with the payload's, **or** a device authority is not the posting author.

> **Authority does not travel by courier.** The payload's `granter` says which key to
> check against; the certificate names its own granter. A disagreement between them
> is a forgery attempt, not a spelling. And a device cannot post a grant claiming some
> *other* device approved it.

**[S]** `unknown_grantee` covers: no such device; a device certified by a different
Root; a device with no accepted registration.

> A grant is never held as a dangling forward reference. If the grantee is not already
> established in the log, the grant means nothing.

### `revoke`

**[S]** In order: `cert_workspace_mismatch`, `cert_granter_mismatch`,
`bad_revoke_signature`, `unknown_grant`, `already_revoked`,
`owner_revoke_requires_root`.

**[S]** `unknown_grant` is distinct from `unknown_grantee`, so a device can tell a
failed revocation from an invalid grantee.

**[S]** **Revocation is grant-granular and does not cascade.** A revoke names one
`grant_id`. Revoking the *granter* leaves the grants it issued live.

```
   Root ──grants──► alice (owner)
                       │
                       └──grants──► bob (participant)

   revoke alice's owner grant   →   bob's participant grant is UNAFFECTED
```

> Nothing re-judges a grant that was valid at the position it was signed at. That is
> what makes a late-arriving op honest rather than retroactively illegitimate — and it
> is the same rule as §10's positional verdict, seen from the other end.

### `root_handover`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 malformed_root_pk` | either key is not 32 bytes |
| `422 cert_root_pk_mismatch` | `from_root_pk` is not this Workspace's current Root |
| `422 bad_root_signature` | the outgoing Root did not sign these bytes |

**[S]** `cert_root_pk_mismatch` carries the same meaning it carries on a genesis —
**the Root this certificate names is not the one in force for this Workspace** — and
is raised here for the second of the two ways that can be true.

> Not a merged code. Both forms mean *rebuild this document against the Root the log
> actually says is current*, and the remedy is identical; only the way you arrived at
> the wrong key differs. That is the test the [code
> list](reference/refusal-codes.md) applies.

**[S]** A handover is **Root-signed, so it needs no grant** (§2), but its author must
still be a registered device: `member_register_not_first` applies unchanged.

**[S]** It **changes nothing already in the log**. Every registration stays
registered, every live grant stays live, and every past op keeps the verdict its
position gave it.

> The positional rule of §10 already decides this, and it decides it the only way
> that is coherent: nothing re-judges a document that was valid where it was signed.
> A handover that silently invalidated every grant its predecessor issued would lock
> the Workspace out of itself at the exact moment it was being rescued.

**[C]** A device MUST replay handovers when verifying the control chain, and MUST
check every certificate against the Root in force **at that certificate's position**
— not against the current one.

> Otherwise a handover retroactively forges history: certificates the old Root
> legitimately signed would fail against the new key, and a device would quarantine a
> log that is entirely honest.

### `rotate`

**[S]** In order: `malformed_control_payload` (which includes a rotation that skips
an epoch), `cert_workspace_mismatch`, `409 rotate_epoch_conflict` carrying
`from_epoch` and `expected_from_epoch`.

**[W]** `rotate` is the one served type with **no certificate and no separate
signature.**

> Every other type carries a separately signed document because its authority is
> somebody *other* than the sender — Root, or a granting device — so the document must
> travel independently of who posts it. A rotation's authority is the sender's own live
> `owner` grant, which the role rule already checks. A second signature would prove
> nothing the envelope signature does not, and would be a second thing to keep in step.

Details of what a rotation means are in [Keys](04-keys.md).

---

## 10. What a control op causes

**[S] A genesis** brings the Workspace into being for the server's own refusals:
content writes stop failing `workspace_not_created`.

**[S] A registration** records the device as registered *in this Workspace*, with its
`member_kind` from the certificate — and is what makes it appear in
`GET /v1/w/{w}/members`.

**[S] A grant** becomes live **at that op's position in the log**, and the verdict is
**positional**:

```
   log position:   … 12 ── 13 ── 14 ── 15 ── 16 ── 17 ── 18 ── 19 …
                          ▲                             ▲
                       grant                         revoke
                    at seq 13                      at seq 18

   an op at position S from this device is authorised
   iff  13 < S < 18
                       ├──────── authorised ────────┤
                  14,15,16,17 yes      12 no      19 no
```

**[S]** Formally: authorised iff `granted_seq < S` and (`revoked_by_seq` is null or
`S < revoked_by_seq`).

> Anchored on log position and **not** on the certificate's clock. Clock anchoring
> would let a revoked device backdate ops to slip under the boundary — it controls its
> own clock, but it cannot control where the server puts its op.

**[S] A revoke** closes that window at its own position, **immutably**. The mark is
written once and never moved.

> Moving it forward would *widen* the window an already-revoked grant covers.

**[S]** **Losing the last live grant** is a three-part event, all after the commit:

```
   revoke lands
       │
       ├─► the grant is marked closed
       │
       ├─► every refresh token scoped to that device is revoked
       │
       └─► every live signal socket that device holds here closes with 4403
```

> The third part matters because a socket is authenticated once, at the handshake, and
> never re-checked. Without it, a revoked device keeps learning that activity is
> happening in a Workspace it has been removed from.

**[S] A root handover** moves the Workspace's **current Root**, and nothing else. The
founding Root — the one the Workspace id derives from — is unchanged and unchangeable.

```
   before          founding = current = R₀       reachability is arithmetic
   handover        founding = R₀, current = R₁   reachability consults the log
   after           certificates verify under R₁; R₀'s past ones still verify
```

**[S]** The Workspace's vault slot must be rewritten under the new Root for recovery
to keep working → [Keys](04-keys.md). Until it is, the log has moved on and the vault
still yields the retired key.

> That gap is the sharp edge of a handover, and no server-side rule closes it: the
> vault is a different slot on a different route, and the server is forbidden to
> connect them. A client that hands over without rewriting the vault has published a
> succession it can no longer recover into.

**[S] A rotate** creates a new key epoch → [Keys](04-keys.md).

---

## 11. Repeats, again

[The Log](01-the-log.md) established that re-posting an op is free. Four consequences
land here, and all four are required:

| Replayed | Must **not** raise | Because |
|---|---|---|
| a grant | `grant_id_already_used` | the id belongs to the op that first asserted it |
| a revoke | `already_revoked` | and the boundary must not move |
| a prune | `prune_target_already_reprised` | it marked those targets itself |
| any control op | — | it must not take effect twice |

> Same argument each time: re-posting an op asserts nothing new. Without these, every
> retried ceremony — the normal path, not an edge case — reads as an attack.

---

## Next

[Keys](04-keys.md): how content stays private from the server, and which party holds
which key.
