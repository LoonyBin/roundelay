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
| a **delegation** | hands the middle three to an operational key — §6 |
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

**[W]** The two are the same key until a `root_handover` moves the second one (§10).
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

## 3. Two gates, and they are not the same gate

Before any permission question there are two coarser ones, and conflating them is
what makes a Workspace private to one identity for ever.

```
   CREATION   may this Root bring this Workspace id into being?
              ── asked once, at genesis ──
              a profile decision · §3.1

   ACCESS     may this device address this Workspace at all?
              ── asked on every other Workspace-scoped route ──
              a fact in the log · §3.2
```

> They look like one question while a Workspace has exactly one identity behind it,
> and answering both by the same derivation is what a single-user deployment wants.
> It is also what makes sharing impossible: a device belonging to somebody else is
> turned away before anyone asks whether it holds a grant, and no grant can rescue a
> request that never reaches the permission check.

### 3.1 Creation

**[S]** At `workspace_genesis`, and there only, the server asks whether the Root in
the certificate may found the id it names. **[S]** It refuses `403
workspace_not_reachable` when it may not.

```
   creatable(root_pk, workspace_id) → true / false
```

**[P]** The predicate is a **profile decision**, and there is **no permissive
default**.

> Be clear about what it does and does not bound. It decides which ids *one* identity
> may bring into being; it does not bound how many identities exist, because anyone
> can mint an Ed25519 keypair without asking. Limiting that is admission's job
> ([Identity](02-identity.md)), and a profile that leaves creation strict while
> leaving admission `open` has bounded nothing.

The core names two policies; a profile may define others.

#### Policy `derived`

**[P]** The profile freezes an ordered list of UUID namespaces. A Root's Workspace
ids are computed from them — the same answer on every device, offline, with no round
trip.

```
   root_pk ──┬── uuid5(NS₀, root_pk) ── Workspace 0
             ├── uuid5(NS₁, root_pk) ── Workspace 1
             └── …

   creatable(r, w)  ⟺  w is one of those
```

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
> genesis fails `workspace_not_reachable` with nothing to debug.

**[P]** `derived` writes the founder's public key into the Workspace id **for ever**,
where a handover cannot move it (§2). That is the right trade for a Workspace one
identity owns, and the wrong one for a Workspace a company owns and an employee
happened to create.

#### Policy `explicit`

**[P]** Any id the profile's own creation authority assigns. The server checks the
id is unused and admission ([Identity](02-identity.md)) is what gates founding.

**[P]** A profile whose Workspaces are shared, long-lived, or outlive the person who
created them SHOULD prefer `explicit`. It is the only policy under which a Workspace
id says nothing about who founded it.

### 3.2 Access

**[S]** Every **other** Workspace-scoped route asks a different question, first,
before anything else, and refuses `403 no_registration` when the answer is no:

```
   does this device hold an accepted registration in this Workspace?
```

**[S]** This is **not** a profile decision. It is read from the log, it is the same
question on every server, and a profile MUST NOT widen or narrow it.

> Membership is a signed fact, not a policy. The registration that establishes it is
> a Root-signed certificate in the log, replayable by every device, and there is
> nothing left for a deployment to decide.

**[S]** Registration is **per Workspace**. A device registered in one Workspace is a
stranger to every other, including Workspaces founded by the same Root.

**[S]** `no_registration` is distinct from `no_live_grant`. A device registered here
and holding no grant at all passes this gate — that is how an enrolling device reads
the control log before anyone has granted it anything (§8).

### The one carve-out

**[S]** An author's **first op in a Workspace** is exempt from the access gate,
because it is the op that establishes access: a `workspace_genesis`, or a
`member_register` naming the author.

> Without the exemption nothing could ever join anything. The founder's registration
> is embedded in the genesis it is posting; a joining device's registration is the
> first op it writes. Both would be refused for not yet being what they are about to
> become.

**[S]** The exemption opens nothing, because the exempt op carries a **Root-signed
certificate for the Workspace it names**. A device may present its own registration
anywhere; only the one this Workspace's Root signed is accepted.

---

## 4. Control ops

Permission changes are ops like any other — class `0x80`, in the same log, in the
same order. Server-read, like every class with bit 7 set.

**[W]** `0x80` bodies are **unencrypted JSON**, for ever. Eight types:

```
   workspace_genesis   the Workspace exists; here is its Root
   member_register     this device's keys are these keys
   grant               this device holds this role
   revoke              that grant is over
   delegate            this key may exercise root authority — §6
   revoke_delegation   that delegation is over
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

Seven of the eight control types carry a **certificate**: a frozen, separately signed
document. The eighth (`rotate`) does not, and §10 explains why.

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

### The seven documents

```json
// registration — signed by the Workspace's Root
{"workspace_id": "…", "member_id": "…", "member_kind": "<token>",
 "holder_ref":  "<b64 32B>",
 "control_pk": "<b64 32B>", "control_key_id": "<b64 8B>",
 "content_pk": "<b64 32B>", "content_key_id": "<b64 8B>",
 "kex_pk":     "<b64 32B>", "kex_key_id":     "<b64 8B>",
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

// delegate — signed by Root itself, never by another delegate
{"workspace_id": "…", "delegation_id": "…", "delegate_pk": "<b64 32B>",
 "delegated_at_hlc": [...]}

// revoke_delegation — signed by Root itself
{"workspace_id": "…", "revocation_id": "…", "delegation_id": "…",
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

### Two signing keys, by how often they are used

**[W]** A device registers **two** Ed25519 signing keys, and the class byte decides
which one signs an envelope:

```
   control_pk    server-read classes — 0x80, 0x81, 0xBF
                 occasional: a registration, a grant, a rotation
                 and the auth challenge → Identity

   content_pk    opaque classes — 0x00–0x7F
                 constant: every note, every edit, every fold
```

**[S]** The header's `author_key_id` says which key signed, and the server checks it
matches the class: a server-read envelope carrying the content key id, or an opaque
one carrying the control key id, is refused `422 author_key_class_mismatch`.

**[S]** This is a **header check, not a signature check**. The server still never
verifies an envelope signature; it compares two registered ids against one byte.

> Which is the only way the rule could exist here at all, and it is enough. A client
> verifying a pulled envelope resolves `author_key_id` to a key it learned from the
> registration, and would refuse a control op signed by a content key even if the
> server had not.

**[W]** The **auth challenge is signed by the control key** ([Identity](02-identity.md)).

> A device token authorises both planes, so if the hot key could obtain one the split
> would buy very little. Binding the challenge to the control key keeps the token as
> cold as the coldest thing it speaks for — used once per session rather than once
> per keystroke.

> The split is by *frequency*, not by sensitivity. Both keys live on the same device
> and die with it; neither has a recovery story, because re-enrolling mints new ones.
> What it buys is that a process holding the key used ten thousand times a day cannot
> author a permission change, and on a desktop or a long-running service those are
> very different exposures.

**[P]** A member kind that writes both planes — an automated folder authoring reprise
and prune ops — holds both keys and gains nothing from the split. It is a person's
device the separation is for.

### `holder_ref`: whose device this is

**[W]** Every registration names the **identity that holds the device**, alongside
the Workspace Root that signs the certificate. In a Workspace one identity owns, the
two name the same identity. In a shared one they differ: the Workspace's Root admits
the device, and `holder_ref` records whose it is.

**[W]** It is **32 opaque bytes**, and the core fixes exactly one property of them:

```
   two registrations carry the same holder_ref
   iff one identity holds both   —   within a single Workspace
```

**[P]** How the bytes are computed is a **profile row** ([profile
obligations](reference/profile-obligations.md)). The holder's Root public key is the
obvious answer and a profile that says so is conformant; so is one that names a value
the server cannot reverse, because no rule here reads the bytes.

> The field was called `holder_root_pk` until this was noticed, and the name was doing
> more than the design needed. Every rule that touches it uses **equality** — group a
> Workspace's devices by who holds them — and equality does not require the value to
> be a public key. Naming it after one committed every deployment, for ever and in a
> signed document, to publishing which identity holds which device in the clear.
>
> Which matters because that plaintext is only half of a join. The other half is the
> device keys, which are the same bytes in every Workspace a device joins and cannot
> be hidden. Closing the join takes both halves — a per-Workspace device identity,
> which is the client's to choose, and a `holder_ref` the server cannot reverse, which
> is this row. Neither half buys anything on its own, and the core's job is to leave
> both reachable rather than to decide.

**[C]** Cross-Workspace equality is **not** promised. A client MUST NOT conclude that
registrations in two Workspaces carrying the same bytes are one identity, nor that
different bytes are different identities.

**[S]** The server **stores it and never interprets it**. It grants nothing, and
appears in no **authority** check: no route, role, bar or verdict in this
specification consults it.

**[S]** One use is permitted, and it is not an authority check. A deployment bounding
what one person may consume MAY group a Workspace's registrations by `holder_ref`
**equality** ([The Log](01-the-log.md)). That reads no meaning out of the bytes — a
blinded value groups exactly as well as a plain one — and it decides how much, never
whether.

> Stated as an exception rather than folded into the rule, because "appears in no
> check" was the stronger claim and it is no longer quite true. A refusal can now
> depend on this field. It is worth being precise about which kind: counting bytes per
> author is not deciding who may write, and the field still cannot make anyone a
> member, a grantee, or an owner.

> It is attribution, not authorisation — which is exactly why it needs no consent
> from the holder. The Workspace's Root is asserting a fact about its own Workspace.
> If a *grant* named an identity, the same field would be authorising a party that
> never agreed, and it would need a counter-signature and the holder's Root out of
> its vault to join anything.

**[W]** It carries **no human-readable identifier**, whatever the profile derives it
from. No certificate in this protocol carries a name, an email address, a display
string, or any other identifier a person would recognise — not beside the holder, not
anywhere.

> Certificates go into the log. The log is append-only, replicated to every member
> device, and never deleted — and `hard_prune` does not reach it, because a control op
> can never be a prune target and so can never become reprised. A name written into a
> certificate is a name that can never be
> withdrawn: erasure becomes impossible by construction, and every member of a
> Workspace learns every other member's real identity whether the deployment wanted
> that or not.
>
> Which is why the field is deliberately only half an answer. It says *these devices
> belong to one identity*; it does not say who. Mapping a Root to a person is the job
> of whatever admitted that identity in the first place — a directory, an SSO
> provider, an HR system — and that is the right place for it, because it is the
> place that can also forget.

**[C]** Grants stay **device-granular**, and this field does not change that.
Admitting one of a person's devices and not another is a policy a deployment may
want — a managed laptop and not a personal tablet — and it stays expressible.

> What the field buys is that "which devices are Alice's" becomes derivable by
> replaying the log, rather than remembered in whichever admin console happened to
> issue the grants. Person-level operations — revoke everything Alice holds — are
> then a loop a client computes from the log, and two clients compute the same one.
>
> Without it, membership would be the one fact about a Workspace the log cannot
> answer, in a design whose whole claim is that the log is the truth.

### Genesis carries its own founder's registration

**[W]** A genesis certificate embeds a full key block for the device that founded the
Workspace — including its `holder_ref` — and that block **is** that device's
registration. The founder writes no separate `member_register`.

> It has to work this way. The envelope is signed by the founder's key, but nothing
> earlier in the log says what that key is — genesis is op 1. So the certificate has
> to introduce the key that signed the envelope carrying it. Chicken and egg,
> resolved by putting the egg inside the chicken.

---

## 6. Delegation: keeping Root cold

Root signs rarely and matters absolutely. Two of the things it signs are not rare at
all — a registration for every device that joins, a grant for every permission
change — and a key that must come out of its vault for routine administration is a
key that ends up living somewhere convenient.

**[W]** A `delegate` names a public key that may exercise **root authority** from
that op's position. Wherever this specification requires a Root signature, a live
delegate's signature is equally good — with three exceptions.

```
   DELEGABLE                          NEVER DELEGABLE
   ─────────                          ───────────────
   member_register certificates       workspace_genesis
   grant certificates, incl. owner    root_handover
   revoke certificates, incl. owner   vault records → Keys
```

**[W]** A delegation is created and revoked **only by Root itself**. A delegate
cannot delegate, and cannot revoke a delegation — its own or another's.

> The three exclusions are what keep the hierarchy from being decorative.
>
> **Handover is the remedy for compromise.** A delegate that could hand over turns a
> warm-key compromise into an unrecoverable one: the attacker moves the Workspace to
> a key you do not hold, using the very escape hatch you would have used. Root keeps
> it, and a compromised delegate is then a revoke-and-remint rather than a loss.
>
> **Genesis is once.** There is nothing routine to relieve.
>
> **The vault is the identity's own recovery**, and a delegate that could rewrite it
> could lock the identity out of itself.
>
> And a delegate cannot mint delegates, or the tree would grow branches Root never
> authorised and could only prune by handing over.

**[S]** Rule 3 of §7 is unchanged in substance: an `owner` grant is minted and
revoked under root authority at both ends. A delegate holds that authority, so both
ends now cost *the same* delegate — the symmetry that rule exists for survives, at a
lower bar.

**[S]** Where a signature is checked against root authority, the server tries the
Workspace's **current Root** first, then each delegation **live at that op's
position**. If none verifies, `422 bad_root_signature`.

**[S]** The verdict is **positional**, exactly like a grant: a certificate signed by
a delegate is judged against the delegations live where the certificate's op landed,
not where it is read.

> So revoking a delegation does not retroactively invalidate what it signed, for the
> same reason revoking a grant does not invalidate the ops it authorised. A
> registration a delegate issued in March stays valid in June.
>
> Which is also the shape of the risk, stated plainly: revoking a delegation stops it
> signing anything **new**. Everything it already signed stands, and if it was
> compromised you must go and revoke those things individually — or hand over.

**[S]** A delegation is **disposable**. It has no vault, no recovery path and no
escrow; losing the key costs one `revoke_delegation` and one `delegate`.

> Which is the reason to prefer this over relaxing who may sign what. Every other key
> here must be recoverable or an identity dies with it — Root, the master wrap key,
> the wrapping secret. A delegate is the first key in the system that may simply be
> thrown away, so it adds authority without adding a way to be locked out.

> Non-normative guidance on who should keep Root when the identity stands for an
> organisation — and on what this delegation relieves them of — is under [Keys
> §7](04-keys.md#guidance--custody-of-a-shared-identity).

---

## 7. Roles

**[P]** The profile supplies a **role table**: a set of role tokens and, for each,
which op classes it permits.

**[W]** The core fixes five things, and a profile MUST NOT relax any of them:

| # | Rule |
|---|---|
| 1 | exactly one role is named `owner` — the **authority role** |
| 2 | `0x80` ops, when not Root-signed, require `owner` and no other role |
| 3 | an `owner` grant may only be created **and** only revoked with `granter`/`revoker` = `root` |
| 4 | an unrecognised role token is refused `unknown_role`, never ignored |
| 5 | a role entry naming `0x81` confers **`prune` only**; `hard_prune` is conferred only by naming it explicitly |

### Rule 5: the one destructive lane

**[P]** A role table entry for `0x81` MAY name the payload types it permits. An entry
that names none permits `prune` and refuses `hard_prune` with
`role_forbids_prune_type`.

```
   participant : 0x01, 0x02                    writes and folds nothing
   folder      : 0x02, 0x81                    folds; cannot destroy
   folder      : 0x02, 0x81{prune,hard_prune}  folds and reclaims
```

**[W]** This is the **only** place a role is finer than a class, and it is deliberate
rather than a general mechanism. Granularity belongs in the opaque range, where a
profile declares its own classes ([The Log](01-the-log.md)) — burning a core class per
authorisation lane would exhaust `0x80–0xBF` in a hurry.

> The exception earns itself on one asymmetry. Everywhere else, a class is a lane over
> one behaviour and the worst a misgrant does is let the wrong member write the wrong
> kind of op — recoverable, because the log is append-only and a mistaken op can be
> reprised. `hard_prune` is the single operation in this protocol that destroys, so an
> unqualified grant that silently included it would be the one misgrant with no repair.
>
> Which is also why the default runs the safe way. Every profile written before this
> type existed grants `0x81` unqualified and keeps meaning exactly what it meant: fold,
> do not destroy.

**[S]** The server reads `0x81` bodies, so it enforces rule 5 by reading the `type` it
already parses. No new inspection, and nothing about the check depends on a body it
may not open.

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

## 8. The two bars

Not every route needs the same thing. Every Workspace-scoped route sits at one of
exactly two levels.

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  BAR 1 — MEMBER-GET                                             │
  │  any UNREVOKED device registered in this Workspace              │
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

> `POST /v1/members` evaluates neither bar. It is gated by the certificate in its
> body — creation on the founding branch, an existing Workspace and its current Root
> on the joining one ([Identity](02-identity.md)). The bars describe credentials, and
> that route presents none.

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
> before it holds any permission — which it must, to discover what it has joined. It
> reopens nothing: reads are already limited to Workspaces this device is registered
> in, and a registration is a Root-signed certificate somebody deliberately issued.

---

## 9. Stage 2 — permission checks on ordinary ops

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

## 10. Stage 4 — verifying control ops

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
> devices holding one Root may legitimately both observe an empty log and both author
> one.
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

**[S]** `unknown_grantee` covers: no such device; a device with no accepted
registration **in this Workspace**.

> A grant is never held as a dangling forward reference. If the grantee is not already
> established in the log, the grant means nothing.
>
> Note what is *not* on that list: whose device it is. A grant may name any device
> registered here, whatever identity holds it. That is what makes a Workspace
> shareable, and it is safe because the registration it depends on was signed by this
> Workspace's own Root.

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
> is the same rule as §11's positional verdict, seen from the other end.

### `delegate` and `revoke_delegation`

**[S]** Both are **signed by Root itself**. A signature by a live delegate is refused
here, and only here, under the same code — a delegate that could delegate is a
delegate that could outlive its own revocation.

**[S]** `delegate`, in order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 malformed_root_pk` | `delegate_pk` is not 32 bytes |
| `422 bad_root_signature` | the current Root did not sign these bytes |
| `409 delegation_id_already_used` | a *different* op already used this id |

**[S]** `revoke_delegation`, in order: `cert_workspace_mismatch`,
`bad_root_signature`, `unknown_delegation`, `already_revoked`.

**[S]** `unknown_delegation` is distinct from `unknown_grant`, so a client can tell a
failed delegation revocation from a failed grant revocation.

**[S]** A delegation MUST NOT name a key that is any device's registered signing key
in this Workspace, and MUST NOT name the Workspace's current Root.

> Both would blur two authorities into one key. A device whose signing key also held
> root authority could mint its own grants, and rule 3's symmetry would be a
> formality. Root naming itself is simply a no-op with a revocation attached.

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

> The positional rule of §11 already decides this, and it decides it the only way
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

## 11. What a control op causes

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

### What revocation does not reach

**[S]** The server-side cut is **immediate and total**. From the revoking position a
revoked device answers `no_live_grant` on every bar-1 route — it cannot pull new ops,
and it cannot pull old ones either. Its refresh tokens are dead and its sockets are
closed. Only an unexpired access token outlives the revoke, and every route re-tests
the bar, so it buys nothing.

It is **not a cryptographic cut**. The device keeps every epoch key it ever held and
every op it already pulled, and both stay readable to it for ever. Nothing in an
append-only log can be unsent, and no rule here pretends otherwise — which is why the
next line is the only remedy this layer has.

**[C]** A revoke SHOULD therefore be followed by a `rotate`.

> Until one lands, content written **after** the revocation is sealed under an epoch
> key the revoked device still holds, and its confidentiality rests entirely on the
> server declining to serve it.
>
> That is a guarantee this specification refuses to make anywhere else. The threat
> model says a hostile or compromised server can withhold but never grant; leaning on
> it to withhold from a revoked device inverts exactly that, and makes a policy check
> the only thing standing between a removed employee and next month's writes — one
> stolen backup, one colluding member, one server bug away from nothing.
>
> Rotate and the cut becomes arithmetic instead: the wrap set for the new epoch is
> minted for the members who hold grants when it is minted, and the revoked device is
> not among them. It never receives `K(w, n+1)` and no amount of access would help.
>
> What no rotation reaches is the past. Everything up to the revoking position was
> legitimately readable when it was read and stays readable, on whatever disk it
> landed on. Revocation ends a relationship; it does not rewrite one.

**[S]** A revoke closes grants, never the **registration**. A revoked device remains a
registered member — it still appears in `GET /v1/w/{w}/members`, and it still passes
the access gate (§3.2) while failing bar 1.

> Which is why `no_registration` and `no_live_grant` are different codes. *You were
> never let in* and *you were let in and then removed* are different facts about a
> device, and only the second one leaves evidence in the log.

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

**[S] A delegation** becomes live **at that op's position**, and the verdict is
positional in both directions — a certificate it signed is judged against the
delegations live where that certificate's own op landed.

```
   log position:   … 12 ── 13 ── 14 ── 15 ── 16 ── 17 ── 18 ── 19 …
                          ▲                             ▲
                      delegate                    revoke_delegation
                      at seq 13                      at seq 18

   a certificate signed by that key, in an op at position S,
   carries root authority  iff  13 < S < 18
```

**[S]** A `revoke_delegation` closes that window at its own position, **immutably**,
and **changes nothing the delegation already signed**. Registrations it issued stay
accepted; grants it minted stay live.

> Which is the honest shape of the risk. Revoking a delegation stops it signing
> anything new and does not undo a thing. If it was compromised rather than merely
> retired, the grants and registrations it issued have to be found and revoked one by
> one — or the Workspace hands over, which is why Root keeps that.

**[S] A rotate** creates a new key epoch → [Keys](04-keys.md).

---

## 12. Repeats, again

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
