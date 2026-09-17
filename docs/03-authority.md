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
| an **amendment** certificate | this device's keys are now these other keys |
| a **grant** for the authority role | the only way to create one |
| a **revoke** of the authority role | the only way to remove one |
| a **role table** | the only way to change the role vocabulary in band — §7 |
| a **handover** certificate | the only way to move a Workspace to a new Root |
| a **delegation** | hands the middle four to an operational key — §6 |
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

### The founding Root, and the current one

**[W]** A Workspace id is bound at genesis to the Root that **founded** it, and that
binding never moves. How it is made is the creation policy's business (§3.1):
`derived` computes the id from the founding Root's public key, `explicit` binds it by
the profile's own assignment. Under either, the founder of an id is settled once and
nothing later revisits it.

```
       founding root_pk ──────►  bound to the Workspace id, for ever
                          │
   current root_pk ───────┴───►  the key every certificate is checked against
                                  first (§6)
        (materialised from the log — the same one, until a handover)
```

**[W]** The two are the same key until a `root_handover` moves the second one (§10).
The first never moves: a Workspace's founding Root is fixed at genesis.

> Which is why there is normally no pinning step in this layer and no window during
> which a Workspace's Root is provisional. The creation question is answered before
> the Workspace exists — under `derived` by arithmetic every server computes
> identically from nothing it had to be told, under `explicit` by the profile's own
> assignment — and no later op reopens it.
>
> A handover is the one exception, and it is deliberate. Without it a Workspace's
> Root could never be replaced, so a compromised Root would be permanent — no
> revocation, no rotation, no remedy anywhere in the system. The price is that a
> Workspace which has used the escape hatch answers reachability from materialised
> state rather than from the creation predicate — under `derived`, the one place the
> arithmetic stops being enough.

---

## 3. Two gates, and they are not the same gate

Before any permission question there are two coarser ones, and conflating them is
what makes a Workspace private to one identity for ever.

```
   CREATION   may this Root bring this Workspace id into being?
              ── asked once, at genesis ──
              a profile decision · §3.1

   ACCESS     may this device address this Workspace at all?
              ── every other Workspace-scoped route, once it exists ──
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
   root_pk ──┬── uuid8(NS₀, root_pk) ── Workspace 0
             ├── uuid8(NS₁, root_pk) ── Workspace 1
             └── …

   creatable(r, w)  ⟺  w is one of those
```

**[W]** `uuid8` is **this** construction, and RFC 9562 leaves version 8 to the
application precisely so that it can be:

```
   d  = SHA-256( namespace 16B ‖ root_pk 32B )
   id = d[0..16], then
          octet 6  ←  0x80 | (octet 6 & 0x0F)      version 8
          octet 8  ←  0x80 | (octet 8 & 0x3F)      variant, RFC 9562
```

**[W]** The name is the **32 raw bytes of Root's Ed25519 public key** — not a base64,
hex or any other spelling of them.

> Version 5 is the obvious answer, and it is SHA-1. A Workspace id is signed into
> every certificate and every envelope header the Workspace will ever carry, in a log
> that is never rewritten, so a deprecated primitive there is permanent by
> construction. Nothing that made `derived` worth having moves: the id is still
> arithmetic over the founding key, still computed offline, still the same answer on
> every device, still with no round trip.
>
> Both operands are fixed width, so the concatenation is injective without a length
> prefix and the framing rule of [Keys §2](04-keys.md#the-framing-rule) is not being
> evaded — there is no second way to read these 48 bytes.

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

**[S]** The gate is asked of a Workspace that **has an accepted genesis**. Before one
exists there is nothing to be registered in, so no route refuses `no_registration` for
want of a registration that could not exist yet.

**[S]** Where no genesis has landed, each route answers by its own rule instead:
**reads** answer as an empty Workspace does — an empty page, an empty member list
([The Log](01-the-log.md#9-reading-get-v1wworkspace_idops),
[Identity](02-identity.md)); the **signal socket** is accepted and behaves as a
subscription to an empty Workspace, its first poke arriving when the genesis does; and
**writes** are answered by the [append pipeline](01-the-log.md#the-pipeline) —
`409 workspace_not_created` at stage 2, or accepted as the op that brings the
Workspace into being, under the carve-out below.

> An empty answer discloses nothing an empty Workspace does not disclose anyway, and
> the enrolment ceremony branches on exactly this observation: a device holding a token
> and no permissions reads first, and creates only if the read came back empty.
> Refusing would make the gate contradict itself — the device about to found the
> Workspace cannot be registered in it, because there is no log for a registration to
> have been accepted into.

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

**[S]** The exemption opens nothing, because the exempt op carries a certificate **for
the Workspace it names, signed under that Workspace's own root authority** (§6). A
device may present its own registration anywhere; only the one this Workspace's
authority signed is accepted.

---

## 4. Control ops

Permission changes are ops like any other — class `0x80`, in the same log, in the
same order. Server-read, like every class with bit 7 set.

**[W]** `0x80` bodies are **unencrypted JSON**, for ever. Ten types:

```
   workspace_genesis   the Workspace exists; here is its Root
   member_register     this device's keys are these keys
   member_amend        this device's keys are now these keys
   grant               this device holds this role
   revoke              that grant is over
   role_table          the role vocabulary is now this table — §7
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
bytes** — the unpacked payload, not the envelope, not a re-serialisation. The
function is the linking op's suite's ([Compatibility](05-compatibility.md)); under
the v1 suites it is SHA-256.

```
   control ops form their own chain, across all authors:

     genesis ──► register ──► grant ──► register ──► grant ──► revoke
        │           │           │          │           │         │
      zero        hash of     hash of    hash of     hash of   hash of
      link        genesis     register   grant       register  grant
```

**[W]** Control ops form **one chain per Workspace, and the server enforces it**.
Every non-genesis control payload's `prev_control_hash` names the **immediately
preceding accepted control op's payload** — the **control tip** at that op's position.
Within a batch the tip advances as the batch walks, so an enrolment batch's second
control op links its first. A genesis has no predecessor: the zero-link rule below is
where the chain starts. A link that names anything else is `control_chain_break`
(§10).

> The server has to enforce it, or the property does not exist to be read. Two ops
> racing on the same predecessor would both land, the stored links would stop forming a
> chain, and the reader's rule below would quarantine an entirely honest log. Linearity
> is the property; refusing the loser is what maintains it.

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

**[C]** A reader replaying the control log MUST verify the links form **one unbroken
chain from genesis**: each link resolves to the payload of the control op immediately
before it, and only the genesis has none. A break is a **truncated or tampered
history**, not a gap to skip.

> Linearity is what makes a withheld *middle* op loud. The zero rule catches a history
> that starts late; without this one, a history with a hole in it passes, because an op
> nothing happens to link can be dropped and the ops on either side still verify.
>
> And a hole is not a gap in the record — grants and revokes take effect **positionally**
> (§11), whether or not anything links them. So the op a hostile server withholds is a
> live permission the reader never learns about, which is exactly the thing this layer
> exists to make underivable by the server.

### A type this reader does not serve

**[C]** A reader replaying the control log that meets a **load-bearing** control type
it does not serve MUST **stop deriving authority at that position.** Everything
derived up to it stands. No authority-dependent verdict may be produced for any later
position — not a grant, not a revocation, not a delegation, not the current Root. The
condition is **surfaced**, under `control_type_not_served` ([refusal
codes](reference/refusal-codes.md)), which means *the log is newer than this reader*.

**[C]** It MUST NOT be skipped.

```
   … ── 41 ── 42 ── 43 ── 44 ── 45 …
                     ▲
                 a type this reader does not serve

   positions ≤ 43    authority derived, and it stands
   positions  > 43   no authority verdict, at all
```

> Skipping diverges two readers' authority state, which is the shared-state partition
> this layer exists to prevent. An op nobody understands is still an op that may
> grant, revoke, delegate or move the Root, so a reader that walks past one and keeps
> answering is answering from a state the writer never had — and answering
> confidently, because nothing about its own view looks wrong.
>
> Stopping is cheap because the chain rule holds the reader's place. The op's link
> still verifies — a hash over bytes needs no understanding of them — so the reader
> knows exactly where it stopped and what the tip there was, and resumes from that
> position once it has been upgraded. Nothing is refetched, and nothing is
> quarantined.

**[S]** The server's verdict is a different one, and unchanged: a control type outside
its served set is refused `422 unsupported_control_type` at the door (§10). A reader
meets one only because some *other* server accepted it.

### The criticality reservation

**[W]** A control type whose name begins **`note_`** is **advisory**, for ever. It
bears no authority, alters no derived state, and a reader that does not serve one MUST
**hash-chain past it without interpreting it.**

**[W]** Every other type is **load-bearing**, and gets the verdict above. No
load-bearing type may ever be named `note_*`. The partition is fixed here, in v1, and
no later version may cross it.

**[W]** **v1 serves no advisory type.** The reservation is not a feature; it is a
place kept.

> The lesson is X.509's, and it cost a decade: an extension mechanism whose
> criticality was decided per document, by a bit that older software could quietly
> ignore. The choice has to be legible **from the name alone**, and it has to be
> legible to the readers that will actually meet the future types — which are the v1
> readers, because they are the ones that never update. A reservation made in v3 would
> reach nobody who needs it.
>
> Chaining past one is safe on two properties this document already has. The link is
> over payload bytes, so a reader computes it without parsing them; and `type` is
> mandatory in every payload for ever (above), so an unparsed payload still says which
> family it belongs to. One field decides it, and nothing else is read.
>
> So the promise has a shape: **v3 ships `note_something`, and every v1 reader already
> knows what to do with it** — carry it in the chain, derive nothing from it, keep
> answering. Without the reservation the same op stops every v1 reader in the fleet
> dead, and the only safe number of purely informational control ops is zero.

**[W]** `note_` is spelled with an underscore because it is a **control type token**,
and every one of those is snake_case, as are the prune types. The protocol's
hyphenated vocabularies — signing domains, extension NAMEs, role tokens,
`member_kind` tokens, the namespace — are kebab-case; a prefix that straddled the
two shapes would be a third convention.

---

## 5. The certificates

Nine of the ten control types carry a **certificate**: a frozen, separately signed
document. The tenth (`rotate`) does not, and §10 explains why.

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
   1. SHAPE, before anything else: does the payload parse, is its key set
        the closed set for its type, is the certificate the document that
        type names
   2. pick the verification key — from the payload, or from the type;
        never from an unverified certificate's claim about its authority
   3. verify the signature over the LITERAL decoded bytes, framed under
        the document's own domain — <ns>/grant/v1 and the rest → Keys §2
   4. only then read the certificate's contents, decide authority, record
```

**[W]** The preimage is `framed("<ns>/<document>/v1", the certificate bytes)` ([Keys
§2](04-keys.md#2-domain-separation-what-makes-every-signature-unambiguous)). The domain
is what stops one document's signature verifying as another's.

> "Verify, then parse" is the usual slogan and it is not quite true here — shape has
> to be settled first, or there is nothing to verify. The invariant is narrower, and
> it is the one that matters: **never act on an unverified certificate.** Steps 1 and
> 2 refuse malformed documents and choose a key; they decide no authority and record
> nothing.
>
> The line is worth naming. Shape is *which keys are present*; what a key **says** is a
> value. And the rule on values is not that none is read early — it is that **no value
> is judged for what it says before the signature.** A role token or a member kind
> against the profile's vocabulary, a grantee or an id against the log: those all wait
> for step 4 (§10). What may be read above it is only whether the document is
> **addressed here at all**.
>
> Two families are read above the signature, and both refuse documents a perfect
> signature would not have saved. The first is the genesis **creation** question — may
> this Root bring this id into being (§3.1), which is why `workspace_not_reachable`
> precedes `bad_root_signature` at both doors ([Identity](02-identity.md)). The second
> is the cross-checks that bind a document to **the address it arrived at** —
> `cert_workspace_mismatch`, `cert_granter_mismatch` on a grant or a revoke,
> `cert_root_pk_mismatch` on a handover, `cert_member_mismatch` on an amend — read
> early on the seven types only an op can carry. The two documents the other door also
> accepts run signature-first, in the same order under the same codes at both doors
> (§10, [Identity](02-identity.md)). Beside them, a `delegate_pk` or `from_root_pk`
> that is not 32 bytes, and a role table that breaks one of §7's five rules, are shape,
> judged in their own type's sequence.
>
> The handover case is the one that *must* sit there. A device skewed across a handover
> builds its document against the retired Root; judged after the signature it would be
> told `bad_root_signature` — the code this specification reserves for *forged, and no
> remedy* — instead of *rebuild against the Root the log reports*, which is the entire
> remedy for skew (§10).
>
> Step 2 reads no certificate on a grant or a revoke: the authority claim is the
> **payload's** `granter` or `revoker`. The one certificate it reads is a genesis's own
> `root_pk` — bound to the Workspace id by the creation predicate, arithmetic under
> `derived` and the profile's own assignment under `explicit` (§3.1), rather than taken
> on trust.
>
> Which is why the seven op-only types read the address first — their keys come from the
> log, and a document aimed at the wrong Workspace or naming the wrong authority is
> better answered as misaddressed than as forged — while the door-shared two verify
> first: a genesis at no cost to any remedy, since it verifies under a key inside the
> very document being verified, and a registration because one certificate must answer
> in one order whichever door it arrives at, which prices a wrong-Workspace post as
> `bad_root_signature`. That is the one place door parity outbids the addressing
> family, and it is paid knowingly.

**[S]** The same four checks apply to a registration certificate presented at
`POST /v1/members` ([Identity](02-identity.md)) rather than inside an op, under the
same codes. One certificate, one vocabulary, whichever door it arrives at.

**[S]** Step 2 picks the same **authority** at both doors — root authority (§6), never
a single fixed key — and can only ask for it in the terms its door has. An op has a
position, so its certificate is judged against the delegations live **there**. The
route has none, so it is judged against those live **as it evaluates**, and the op the
certificate is later carried in is judged again where it lands
([Identity](02-identity.md), which fixes the exact candidate order at that door).

> Which is not two rules. It is one rule — a delegation authorises from its own
> position — asked by a door that stands inside the log and by a door that stands
> before it. The route's answer buys the ordering it always bought, and the log's
> answer is still the one that decides.

### The nine documents

```json
// registration — signed by the Workspace's Root
{"workspace_id": "…", "member_id": "…", "member_kind": "<token>",
 "holder_ref":  "<b64 32B>",
 "control_pk": "<b64 32B>", "control_key_id": "<b64 8B>",
 "content_pk": "<b64 32B>", "content_key_id": "<b64 8B>",
 "kex_pk":     "<b64 32B>", "kex_key_id":     "<b64 8B>",
 "registered_at_hlc": [wall_ms, counter, "<hex32>"]}

// amendment — signed by the Workspace's Root, or by a live delegate
{"workspace_id": "…", "member_id": "…", "amend_id": "…",
 "keys": {"control": {"pk": "<b64 32B>", "key_id": "<b64 8B>"},   // any
          "content": {"pk": "<b64 32B>", "key_id": "<b64 8B>"},   //   subset,
          "kex":     {"pk": "<b64 32B>", "key_id": "<b64 8B>"}},  //     ≥ 1
 "amended_at_hlc": [...]}

// genesis — signed by Root
{"workspace_id": "…", "root_pk": "<b64 32B>",
 "founder": {"member_id": "…", "member_kind": "<token>",
             "holder_ref": "<b64 32B>",
             "control_pk": "<b64 32B>", "control_key_id": "<b64 8B>",
             "content_pk": "<b64 32B>", "content_key_id": "<b64 8B>",
             "kex_pk":     "<b64 32B>", "kex_key_id":     "<b64 8B>",
             "registered_at_hlc": [wall_ms, counter, "<hex32>"]},
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

// role_table — signed by Root itself, never by a delegate
{"workspace_id": "…",
 "roles": [{"role": "<token>", "classes": [1, 2],       "prune_types": []},
           {"role": "owner",   "classes": [1, 2, 128, 129],
                                            "prune_types": ["prune", "hard_prune"]}],
 "adopted_at_hlc": [...]}
```

**[W]** An amendment's `keys` is an object whose members are drawn from the closed
set **`control`, `content`, `kex`** — **at least one present**, no others, each a
closed pair of `pk` and `key_id`. It is the one carrier in this document that is
closed over a *subset*, and the subset is what says which keys the amendment touches.

> A key the amendment does not name is a key it does not move, which is why absence
> carries meaning here and nowhere else. The alternative — three mandatory members and
> a convention for "unchanged" — is a second spelling of the current value, sitting in
> a signed document, waiting to disagree with the log.
>
> The closure is over **v1's** three key kinds, and that is the point of stating it
> rather than leaving the object open. A device that one day carries a fourth key —
> a post-quantum signing key, say — does not widen this document: it rides
> `<ns>/member-amend/v2`, under which these bytes do not verify and those bytes do
> not verify here ([Keys §2](04-keys.md#2-domain-separation-what-makes-every-signature-unambiguous)).
> Closed set now, new domain later, and no version field inside anything signed.

**[W]** A role table's `roles` is an array of entries, each a **closed set of exactly
three keys**. `classes` holds class **integers**, never hex strings — the same rule
`ext_binding` already states ([The Log](01-the-log.md#3-the-class-byte)). `prune_types`
is present in every entry, and `[]` is rule 5's default: `prune`, never `hard_prune`.

**[W]** The `founder` block is a **closed set of exactly ten keys**: the registration
certificate's own set minus `workspace_id` — `member_id`, `member_kind`, `holder_ref`,
`control_pk` and `control_key_id`, `content_pk` and `content_key_id`, `kex_pk` and
`kex_key_id`, `registered_at_hlc`. **All ten present**, no substitutions and no
additions, judged as shape like every other closed set (§5) — a founder with a key
missing is `malformed_control_payload`, never a founder with fewer keys.

> Minus that one field because the genesis already carries it, once. A nested copy
> would be a second spelling of a single value, and the only thing to do with a second
> spelling is cross-check it against the first — which `cert_workspace_mismatch`
> already does to the one that is there.

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

**[W]** Every key id inside a certificate is a **derivation** — the **first 8 bytes of
SHA-256** of the key beside it ([Identity](02-identity.md)) — and MUST be
cross-checked against it. A claimed id that disagrees is a forgery attempt, not a
variant spelling.

**[S]** The verdict is `malformed_control_payload`: it is arithmetic over the
document's own literals, so it is **shape**, settled at step 1 and above the
signature. It binds every certificate that carries a key id — a registration, a
genesis's founder block, an amendment.

### How an op carries one

**[W]** A certificate travels as **base64 bytes and a detached signature**, under the
two names [Identity](02-identity.md) already uses at `POST /v1/members`: `cert_b64`
and `cert_sig_b64`. The bytes are the signed bytes, never a re-serialisation.

```json
// genesis · member_register · member_amend · role_table
// delegate · revoke_delegation · root_handover
{"type": "member_register",
 "prev_control_hash": "<hex64>",
 "cert_b64":     "<b64>",
 "cert_sig_b64": "<b64 64B>"}

// grant — and revoke, with "revoker" in place of "granter"
{"type": "grant",
 "prev_control_hash": "<hex64>",
 "granter": "root" | "<uuid>",
 "cert_b64":     "<b64>",
 "cert_sig_b64": "<b64 64B>"}

// rotate — the one type with no certificate
{"type": "rotate",
 "prev_control_hash": "<hex64>",
 "workspace_id": "…",
 "from_epoch": 2,
 "to_epoch":   3,
 "keywrap_digest_b64": "<b64 32B>"}
```

**[W]** The whole key set, per type:

| Type | Keys, beyond `type` and `prev_control_hash` |
|---|---|
| `workspace_genesis` | `cert_b64`, `cert_sig_b64` |
| `member_register` | `cert_b64`, `cert_sig_b64` |
| `member_amend` | `cert_b64`, `cert_sig_b64` |
| `grant` | `granter`, `cert_b64`, `cert_sig_b64` |
| `revoke` | `revoker`, `cert_b64`, `cert_sig_b64` |
| `role_table` | `cert_b64`, `cert_sig_b64` |
| `delegate` | `cert_b64`, `cert_sig_b64` |
| `revoke_delegation` | `cert_b64`, `cert_sig_b64` |
| `root_handover` | `cert_b64`, `cert_sig_b64` |
| `rotate` | `workspace_id`, `from_epoch`, `to_epoch`, `keywrap_digest_b64` |

**[W]** **Every set is closed.** A missing key, or one outside the set — a key
belonging to another type, a key this document does not define — is
`malformed_control_payload`, on the rule that closes every payload in this protocol
([Compatibility](05-compatibility.md)).

**[W]** The certificate a payload carries MUST be the document its `type` names.
Anything else is `malformed_control_payload` — a shape verdict, settled at step 1.

> Nothing cryptographic rests on this rule. The signing domains ([Keys](04-keys.md))
> already make a mis-carried certificate unverifiable: a revoke document inside a grant
> payload dies at the signature whichever way this fell. And the mechanism is only that
> certificates carry no `type` field of their own, so the closed key set is how the
> server tells which of the nine it is holding.
>
> What the rule buys is **code honesty.** Without it, a client that built its payload
> around the wrong document falls through to `bad_grant_signature` or
> `bad_root_signature` — codes this specification reserves for *these bytes are forged*,
> which has no remedy (§10). `malformed_control_payload` says *rebuild this payload
> around the right document*, which does.

**[W]** Only `grant` and `revoke` name their authority in the payload, because only
they have a choice of one — `"root"`, or the uuid of a device holding the authority
role. That is the value `cert_granter_mismatch` compares against the certificate's own
(§10). `"root"` resolves to **root authority**: the Workspace's current Root, then each
delegation live at that op's position (§6). A uuid resolves to that device's registered
`control_pk` (below). Everywhere else the verification key follows from the type, and
no field is needed to find it:

```
   workspace_genesis   the root_pk INSIDE its own certificate — op 1 has to
                       introduce the key that checks it
   member_register     root authority: the Workspace's current Root, then each
                       delegation live at this op's position
   member_amend        root authority, exactly as a registration — §6
   role_table          the current Root itself — never a delegate — §6
   delegate            the current Root itself — never a delegate — §6
   revoke_delegation   the current Root itself — never a delegate — §6
   root_handover       the current Root itself, which is what from_root_pk
                       must already name
```

**[W]** `rotate` carries `workspace_id` **in the payload**, and it is the only type
that does.

> Every other type's Workspace binding rides inside its certificate, and that is what
> `cert_workspace_mismatch` compares against the envelope's header. A rotate has no
> certificate to carry one, so the payload makes the claim itself — same check, same
> code, one document fewer.

### Two signing keys, by how often they are used

**[W]** A device registers **two** Ed25519 signing keys, and **bit 7 of the class
byte** decides which one signs an envelope:

```
   control_pk    every class with bit 7 SET — 0x80, 0x81, 0xBF, and any
                 extension class the deployment has enabled in 0xC0–0xFF
                 occasional: a registration, a grant, a rotation
                 and the auth challenge → Identity

   content_pk    every class with bit 7 CLEAR — the opaque range, 0x00–0x7F
                 constant: every note, every edit, every fold
```

**[W]** The rule is **on the bit, not on the list.** An extension class is
server-read by construction ([The Log](01-the-log.md)), so it is signed by the
control key without this document having to name it — and no class a deployment
enables later arrives with this assignment undefined.

**[S]** The header's `author_key_id` says which key signed, and the server checks it
against that bit: a bit-7-set envelope carrying the content key id, or a bit-7-clear
one carrying the control key id, is refused `422 author_key_class_mismatch`.

**[S]** This is a **header check, not a signature check**. The server still never
verifies an envelope signature; it compares two registered ids against one byte.

> Which is the only way the rule could exist here at all, and it is enough. A client
> verifying a pulled envelope resolves `author_key_id` to a key it learned from the
> registration, and would refuse a control op signed by a content key even if the
> server had not.

**[W]** The **auth challenge is signed by the control key in force**
([Identity](02-identity.md)) — the registration's, until a `member_amend` installs
another (§10).

> A device token authorises both planes, so if the hot key could obtain one the split
> would buy very little. Binding the challenge to the control key keeps the token as
> cold as the coldest thing it speaks for — used once per session rather than once
> per keystroke.

**[W]** A **grant or revoke certificate signed by a device authority is signed with
that device's control key.** The payload's `granter` — or `revoker` — names the
device, and the server resolves it to that device's registered `control_pk` and
verifies the certificate bytes under that key. A signature under anything else,
including that device's own content key, is `bad_grant_signature` or
`bad_revoke_signature`.

> The same argument as the challenge, one step further. Minting a permission change
> is the coldest thing a device ever does, and a certificate the hot key could sign
> would put every grant in the Workspace one compromised editor process away.
>
> The other authorities are not device keys at all: Root signs its own certificates,
> and a delegate signs with the delegation key — which §10 forbids from being any
> device's registered signing key.

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
Workspace — the ten fields enumerated above, `holder_ref` among them — and that block
**is** that device's registration. The founder writes no separate `member_register`.

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
delegate's signature is equally good — with four exceptions.

```
   DELEGABLE                          NEVER DELEGABLE
   ─────────                          ───────────────
   member_register certificates       workspace_genesis
   member_amend certificates          root_handover
   grant certificates, incl. owner    role_table
   revoke certificates, incl. owner   vault records → Keys
```

**[S]** `member_amend` is delegable on the **same custody argument as a registration**:
it says which keys a device holds, an admitting authority is the party that says so,
and a Root that must come out of its vault every time somebody's laptop is replaced is
a Root that stops living in a vault.

**[S]** "Root-signed", said of a control payload anywhere in this document, means
**signed under root authority** — so the permission bypass carries too: a payload a
live delegate signed is accepted regardless of the author's permissions, exactly as a
Root-signed one is (§2, rule 2 of §7, bar 2 of §8).

> Which the delegable list above already forces. A device a delegate has just
> certified holds no grant in the Workspace it is joining — that is what joining
> means — so if the bypass read *Root* literally, the one op this delegation exists to
> authorise would be the one op the device could not post.

**[W]** A delegation is created and revoked **only by Root itself**. A delegate
cannot delegate, and cannot revoke a delegation — its own or another's.

> The four exclusions are what keep the hierarchy from being decorative.
>
> **The role table is the authority vocabulary**, not an exercise of authority. A
> delegate that could rewrite it could hand itself every class Root never authorised,
> and could hollow out rule 3 without minting a single grant — by redefining what
> `owner` permits. Delegation relieves Root of routine signing; it does not hand over
> what signing means.
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

**[S]** `POST /v1/members` is the one door with **no position to be judged at** — it
runs before the op exists, and often before the joining device is anything to the
Workspace at all. There the same authority is materialised **live as the route
evaluates the request**, and the certificate is judged again, positionally, when it
lands as a `member_register` op ([Identity](02-identity.md)). A `workspace_genesis`
never reaches this question: it is not delegable, so that branch tries the carried
`root_pk` and nothing else.

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

**[P]** The profile supplies the **initial role table**: a set of role tokens and, for
each, which op classes it permits. From the first `role_table` op onward the **log**
supplies it instead.

**[W]** The core fixes five things, and neither a profile nor a `role_table` may relax
any of them:

| # | Rule |
|---|---|
| 1 | exactly one role is named `owner` — the **authority role** |
| 2 | `0x80` ops, when not Root-signed, require `owner` and no other role |
| 3 | an `owner` grant may only be created **and** only revoked with `granter`/`revoker` = `root` |
| 4 | an unrecognised role token is refused `unknown_role`, never ignored |
| 5 | a role entry naming `0x81` confers **`prune` only**; every other payload type is conferred only by naming it explicitly |

### Rule 5: the one destructive lane

**[P]** A role table entry for `0x81` MAY name the payload types it permits. An entry
that names none permits `prune` and refuses `prune_ext` and `hard_prune` with
`role_forbids_prune_type`.

```
   participant : 0x01, 0x02                    writes and folds nothing
   folder      : 0x02, 0x81                             folds; cannot destroy,
                                                        cannot reach extensions
   folder      : 0x02, 0x81{prune,hard_prune}           folds and reclaims
   folder      : 0x02, 0x81{prune,prune_ext,hard_prune} all three lanes
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

**[S]** In rules 2 and 3, `root` names the root authority of §6, resolved at the
op's position — the **current** Root or a delegation live there, never the founding
key. After a handover, new `owner` grants and revokes of old ones verify under the
incoming key, or a delegation it has since minted.

> `granter: "root"` names an authority, not a particular key. Resolving it at
> verification time is what lets a Workspace that has changed Root keep revoking the
> grants its old Root issued — which is most of the point of handing over after a
> compromise.

### The table in force, and how it changes

**[W]** A `role_table` op carries a **complete replacement table** — every role token
with its op classes, every `0x81` entry with its payload types (§5). Never a patch.

**[W]** The table in force is **positional**, like everything else here:

```
   log position:   … 1 ── 2 ── … ── 30 ── 31 ── … ── 58 ── 59 …
                   ▲                ▲                 ▲
                genesis         role_table        role_table

   the profile's initial table governs    1 … 30
   the table op 30 carries governs       31 … 58
   the table op 58 carries governs       59 …
```

**[S]** Formally: the table in force at position `S` is the one carried by the latest
`role_table` op at a position **strictly below** `S`, and the profile's initial table
where there is none. The same boundary a grant has (§11), for the same reason.

**[S]** Every judgement that reads a role reads the table in force **at the position
it is judging** — `role_forbids_op_class` and `role_forbids_prune_type` at stage 2,
`unknown_role` on a grant at stage 4. **[S]** Rule 4 is unchanged and stays **fail
closed per position**: a token the table in force *there* does not name is
`unknown_role`, never ignored.

**[S]** A `role_table` is signed by **Root itself**, never by a delegate (§6), and is
therefore Root-signed for the purposes of §2 — it needs no grant.

**[S]** A role a later table stops naming does not un-authorise anything already
written. A device still holding a live grant for it keeps the grant — nothing
re-judges a grant (§11) — and its later ops are refused `role_forbids_op_class`,
carrying that token among the live `roles`.

> Which is the honest reading of the state: the grant is still there, and there is no
> longer a role behind it. `unknown_role` would be the wrong verdict, because that
> code judges a **grant certificate's** token where the grant lands, and this one was
> in the table when it did.

> Rule 1 is what stops the mechanism being a lockout. Every table names exactly one
> `owner`, so no Workspace can install a table with no authority role — and the worst
> a careless table can do, an `owner` entry that names no classes, costs one more Root
> signature to undo, because a `role_table` never needed a grant in the first place.

**[W]** The **initial** table is still **not covered by any signature**, so two peers
configured with different ones disagree about which ops are legitimate. **[P]**
Changing it after deployment is a **fork**, in either direction and without exception
([profile obligations](reference/profile-obligations.md)). There is no widening of it
that is merely a configuration change.

**[W]** The in-band mechanism is `role_table`, and it is the only one. It is a signed
op in the log, so every device replays it and derives the same table at the same
position; a deployment that wants a role to gain a class edits no configuration and
posts one. Fail-closed handling of unknown roles is what makes a *configuration*
disagreement detectable rather than silently divergent, and the in-band path is what
makes having one unnecessary.

> The rule this replaces said a widening needed a new protocol namespace or a new
> certificate version — which is a fork wearing a smaller word. It was the right
> verdict for a table that lived only in configuration, and the wrong one to leave
> standing, because the change a deployment actually wants — *let this role write this
> class* — is not a change to the protocol at all. Now it is an op: signed by Root,
> ordered against every other authority change, replayable by a device that has been
> in a drawer for two years, and retroactive to nothing.

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
   POST /v1/members             a certificate signed under root authority,
                                inside the body
```

> `POST /v1/members` evaluates neither bar. It is gated by the certificate in its
> body — creation on the founding branch, an existing Workspace and its current Root
> on the joining one ([Identity](02-identity.md)). The bars describe credentials, and
> that route presents none.
>
> The vault row above it is the narrower claim on purpose: a vault record is one of
> the three documents §6 withholds from delegates, so there it really is **Root**, and
> not the authority Root may hand out.

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
> in, and a registration is a certificate this Workspace's own root authority
> deliberately issued.

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

**[S]** "No role permits this class" is asked of the **table in force at this op's
position** (§7) — the profile's initial table, or the latest `role_table` below it.

**[S]** The `roles` a refusal carries are **sorted lexicographically** — here, and on
`role_forbids_prune_type` (§7), the other code that carries them.

> Determinism, on the precedent the `fields` list of an unknown-field refusal already
> sets ([Compatibility §4](05-compatibility.md#4-unknown-fields-are-refused)). The set
> a device holds has no natural order, so without a stated one two servers answer the
> same state with different bytes, and anything that compares refusals — a test, a
> cache, a client that dedupes its alarms — sees a difference that is not there.

---

## 10. Stage 4 — verifying control ops

**[S]** Framing and decoding first, in this order:

```
   invalid_body_length ─► payload_overruns_body ─► non_zero_padding
        ─► malformed_control_payload ─► unsupported_control_type
        ─► control_chain_break
```

**[S]** `control_chain_break` refuses **two things**: the zero-link rule of §4 — a zero
on a non-genesis type, anything else on a genesis — and a link that is not the hash of
the **control tip at this op's position**.

**[S]** It carries `expected_prev_control_hash`, the link the op should have named.
The field is **absent** where there is none to name: on a genesis, whose only legal
link is the zero link, and before a genesis, where there is no tip at all.

**[S]** The tip comparison is asked only of a Workspace with an **accepted genesis**,
because before one there is nothing to compare against. A non-genesis control op
arriving there is refused by the rules that already answer it —
`409 workspace_not_created` on a `member_register`, `member_register_not_first` on
anything else. The zero-link half is shape, and is asked either way.

**[S]** `control_chain_break` is checked **before** any type-specific rule, so a
misplaced genesis with a non-zero link answers `control_chain_break` rather than
`genesis_not_first`.

> Everything in that chain runs **above authority**: framing, decoding, a served type,
> a link that fits. The tip comparison reads the log and judges nothing it finds there
> — no value, no permission. Two codes that look like they belong in the chain do not,
> and both sit in the grant sequence below, under `bad_grant_signature`.
>
> `owner_grant_requires_root` is an authority verdict, and nothing decides who may do
> what from bytes whose signature has not verified. `unknown_role` judges a **value**
> out of a certificate for what it says (§5) — and it is a `grant`-only check, which
> the line above already says the chain runs before. `unknown_member_kind` is the same
> kind of vocabulary check on a registration certificate, and it is not in the chain
> either.
>
> Refusal order is observable, so each of them can only be in one place.

**[S]** This is also the verdict a **concurrency loser** gets. Two devices that read
the same tip and both build against it are both well-formed; the one that commits
second named a tip that has moved, and is refused.

> Every concurrency hazard in this layer has a named verdict — `author_chain_conflict`
> for the author's own chain ([The Log](01-the-log.md#stage-5--the-author-chain)),
> `rotate_epoch_conflict` for epochs ([Keys](04-keys.md)), and this for the control
> chain — and not one of them is a retry of the same bytes. The remedy is always
> rebuild and re-sign, which is why the code stays deterministic: what comes back is a
> different request.

**[C]** A device that can read the log MUST **re-read** before rebuilding, and not
merely re-link against `expected_prev_control_hash`. The tip moved because somebody
else's control op landed, and what that op says may change what this one should be —
or whether it should be written at all.

> The field is there for the device that **cannot** read. A joining device's
> `member_register` is exempt from the access gate (§3.2) but not from the chain, and
> it holds no read on the Workspace until that very op lands; without the field its
> first op could never be built at all. With it, one refusal tells it the tip and the
> second attempt lands.
>
> Which prices the disclosure honestly. Any device holding a token and the Workspace id
> can learn the tip by posting a `member_register` naming itself, because the chain
> check sits above the certificate check. What it learns is the hash of bytes it cannot
> read — a control-plane change detector and nothing more, since the payload it hashes
> carries a signature nobody can guess. The alternative was to run this one op's chain
> check below its own certificate, and a conditional refusal order costs more than the
> detector does.

**[S]** A **repeat** is never judged against the tip: a re-posted control op names the
tip it was built against, which has since moved — §12.

**[S]** Then, **unless the payload is Root-signed** — which a live delegate's
signature satisfies (§6) — the authority-role check for `0x80`: `no_live_grant` or
`role_forbids_op_class`.

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
| 6 | `422 cert_member_mismatch` | the founder named is not the envelope's author |
| 7 | `422 cert_key_mismatch` | the founder's key is not this device's registered key |
| 8 | `422 unknown_member_kind` | the founder's kind is not in the profile's set |

**[S]** Genesis carries **no admission check**. The device posting it already holds a
token, which it could only have obtained from a member record, which was the admitted
act ([Identity](02-identity.md)).

**[S]** A genesis raises **no `cert_root_pk_mismatch`**. The op carries exactly one
`root_pk` — the certificate's own — and check 2 has already asked the creation
predicate of it (§3.1). The only other way this Workspace could have a different Root
in force is that it already exists, and that is check 1.

> The check once compared two keys, because `workspace_not_reachable` was asked of the
> Root bound to the poster's token and this one of the certificate's own. The server
> keeps no Root beside a device any more ([Identity](02-identity.md)), so there is one
> key here and one check that judges it — and under `explicit` there would be no
> derivation to compare it against in any case. A Root that may not found the id it
> names is `workspace_not_reachable`; a Workspace that is already founded is
> `genesis_not_first`.

> A second genesis is not a fork for the server to resolve. Both documents claim to be
> the beginning, and the chain rule cannot separate two ops that have no predecessor —
> so the server takes the one that lands and leaves the tie-break to the devices. Two
> devices holding one Root may legitimately both observe an empty log and both author
> one.
> Exactly one lands; the loser always gets `genesis_not_first`, including when the
> race is only caught at commit time.

### `member_register`

**[S]** In order: `409 workspace_not_created`, `member_register_not_first`,
`bad_root_signature`, `cert_workspace_mismatch`, `cert_member_mismatch`,
`cert_key_mismatch`, `unknown_member_kind`.

**[S]** `workspace_not_created` comes first because nothing about the op can be
judged against a Workspace that does not exist — there is no root authority to verify
under. The route's joining branch already answers the same code for the same cause
([Identity](02-identity.md)): one certificate, one verdict, whichever door.

> No admission check here either, and for the same reason: this op is authored under
> a device token, and obtaining one is what admission gated.

> Both sequences put `unknown_member_kind` last for the reason `unknown_role` sits
> under `bad_grant_signature`: it judges a value **for what it says** — a token against
> the profile's vocabulary — and no such judgement runs before the signature. What runs
> above it here is only the first of §5's early families — the creation question at 2.
> These are the two documents the other door also accepts, so they run signature-first
> and their address cross-checks sit below it with every other read (§5). The identity
> checks precede the vocabulary one because they ask whether this document belongs here
> at all.

**[S]** `cert_member_mismatch` here is **the certificate naming a device other than
the envelope's author**. Registrations are self-posted: the carve-out that exempts
this op from the access gate exempts a `member_register` *naming the author* (§3.2),
and this check is what holds the op to that.

> Otherwise the exemption would be a hole rather than a carve-out. A device could post
> somebody else's registration as its own first op, and the one rule that lets an
> unregistered author write at all would be doing it for an author its own document
> does not name.

### `member_amend`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 cert_member_mismatch` | the certificate names a device other than the envelope's author |
| `422 bad_root_signature` | root authority did not sign these bytes |
| `409 amend_id_already_used` | a *different* op already used this amend id |

**[S]** An empty `keys`, a member outside the closed three, or a `key_id` that is not
the derivation of the `pk` beside it, is `malformed_control_payload` at step 1 — shape,
like every other closed set (§5), and so above this sequence.

**[S]** An amend is **self-posted**, and `cert_member_mismatch` is what holds it to
that. There is no unknown-member verdict to raise.

> The author of a control op is already a device with an accepted registration here —
> the access gate and `member_register_not_first` between them see to it — so a
> certificate naming anybody else is answered as misaddressed rather than as a missing
> member. And the device that must hold the new secret keys is the natural device to
> post the document installing them: a third party posting one would brick a member
> that never held them.

**[S]** An amend is **per Workspace**, exactly as a registration is. A device
registered in three Workspaces that wants a new control key in all three posts three
amends, one per log.

> It could not be otherwise without breaking what everything here rests on. A reader
> derives authority from **this** Workspace's log and nothing else, so a key change
> recorded in another Workspace's log is a key change no reader here can see — and
> every op signed under the new key would be unverifiable to exactly the devices that
> were told the log is the truth.

**[W]** An amend **replaces**, and the replacement is positional in both directions:

```
   log position:   … 12 ── 13 ── 14 ── 15 ── 16 ── 17 …
                          ▲
                    member_amend{control} at seq 13

   an envelope from this device at position S, bit 7 set, verifies under
        the OLD control key   iff  S < 13
        the NEW control key   iff  S > 13
```

**[W]** A replaced key **stops signing new ops from that position, and keeps verifying
its old ones for ever.** There is no window in which both sign, and no option.

> One behaviour, because two would be a choice the writer makes and every reader has
> to guess. An overlap sounds kind to a device mid-rotation and is not: it is a period
> in which the key the amend exists to retire may still author, which is the whole of
> what a compromised key needs.
>
> Nothing is re-judged backwards, for the reason §11 gives about every other verdict
> here. An op signed in March by a key an amend retired in June was signed by that
> device, and stays signed by it.

**[C]** A reader resolves `author_key_id` against the keys in force at the **op's**
position. **[C]** One that resolves to **no** key in force there is refused
`unknown_author_key` ([refusal codes](reference/refusal-codes.md)), and the op is not
authentic — the same stance as `bad_signature`, under a different code because it is a
different diagnosis.

> `bad_signature` means *these bytes are forged*, and it has no remedy. This one means
> *I have no key to check them against here*, which has a second cause worth telling
> apart: a `member_amend` this reader was never served. A truncated history and a
> forgery want the same refusal and entirely different investigations.

**[S]** The server verifies no signature, here as everywhere ([The Log
§8](01-the-log.md#8-what-the-server-does-not-check)). Stage 1's class check compares
`author_key_id` against **every** id that device has held for each class, so an amend
never turns an honest stale client into `author_key_class_mismatch`.

**[S]** An amend of the **`control`** key revokes every refresh token scoped to that
device and closes its live signal sockets here, at the commit — the revoke cascade of
§11 without the grant half. An amend of `content` or `kex` does neither.

> The amend exists because the old key may be in somebody else's hands, and a token
> that key already obtained would outlive it otherwise. The challenge is signed by the
> control key (§5), so cutting the tokens is what makes the retirement reach the
> credential as well as the log.

**[S]** The **auth challenge** is verified against the device's control key in force
**in any Workspace it is registered in** — the registration's, where no amend has
landed. A key amended away in every one of them stops obtaining tokens.

> That route has no Workspace in its path and no position to be judged at, so it asks
> the only question it can, the same way `POST /v1/members` does (§6).

**[C]** Which prices the remedy honestly, and it is worth stating rather than
discovering: a device rotating its control key **because that key was exposed** MUST
amend in **every** Workspace it is registered in. Until it has, the retired key still
buys a token somewhere.

**[C]** A device MUST keep every **sealing** private key it has ever held. Wraps
minted before a `kex` amend name the old key id and open under nothing else
([Keys](04-keys.md)).

### `grant`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 cert_granter_mismatch` | two causes — see below |
| `422 bad_grant_signature` | the named authority did not sign these bytes |
| `422 unknown_role` | the certificate's role token is not in the profile's set |
| `422 owner_grant_requires_root` | an `owner` grant not granted by Root |
| `422 unknown_grantee` | two causes — see below |
| `422 member_kind_forbidden` | the profile's rule rejects it |
| `409 grant_id_already_used` | a *different* op already used this grant id |

**[S]** `cert_granter_mismatch` covers: the certificate's own `granter` disagrees
with the payload's, **or** a device authority is not the posting author.

> **Authority does not travel by courier.** The payload's `granter` says which key to
> check against; the certificate names its own granter. A disagreement between them
> is a forgery attempt, not a spelling. And a device cannot post a grant claiming some
> *other* device approved it.

**[S]** `unknown_grantee` covers: **no such device anywhere**; and a device that does
exist — a shell, or a member of some other Workspace — with **no accepted registration
in this Workspace**.

> A grant is never held as a dangling forward reference. If the grantee is not already
> established in the log, the grant means nothing.
>
> A shell is not a third cause, it is the second one. Both are the same absence read
> off the same place: this Workspace's own log, which knows registrations and nothing
> else. The device registry could tell a stranger from a shell, and it is not consulted
> — it is authoritative for nobody (§1), and a grant that branched on it would be a
> permission decided by server state rather than by the log.
>
> Note what is *not* on that list: whose device it is. A grant may name any device
> registered here, whatever identity holds it. That is what makes a Workspace
> shareable, and it is safe because the registration it depends on was signed under
> this Workspace's own root authority.

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

**[S]** Both are **signed by Root itself**, so a live delegate's signature is refused
`bad_root_signature` — as it is on a genesis or a handover, the other documents §6
withholds from delegates. A delegate that could delegate is a delegate that could
outlive its own revocation.

**[S]** `delegate`, in order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 malformed_root_pk` | `delegate_pk` is not 32 bytes |
| `422 bad_root_signature` | the current Root did not sign these bytes |
| `422 delegate_pk_in_use` | two causes — see below |
| `409 delegation_id_already_used` | a *different* op already used this id |

**[S]** `revoke_delegation`, in order: `cert_workspace_mismatch`,
`bad_root_signature`, `unknown_delegation`, `already_revoked`.

**[S]** `unknown_delegation` is distinct from `unknown_grant`, so a client can tell a
failed delegation revocation from a failed grant revocation.

**[S]** A delegation MUST NOT name a key that is any device's registered signing key
in this Workspace, and MUST NOT name the Workspace's current Root. Both are refused
`422 delegate_pk_in_use`.

> Both would blur two authorities into one key. A device whose signing key also held
> root authority could mint its own grants, and rule 3's symmetry would be a
> formality. Root naming itself is simply a no-op with a revocation attached.
>
> One code for both, because a client learns the same thing and does the same thing:
> mint a fresh keypair and delegate that. Neither form is `bad_root_signature` — the
> signature is Root's and it verifies — and neither is `malformed_root_pk`: 32 bytes
> is exactly what this key is.
>
> It sits **below the signature** because it judges a **value** for what it says —
> what this key already is to this Workspace — and §5 admits no such judgement above
> it. Above `delegation_id_already_used` for the reason `unknown_role` sits above
> `grant_id_already_used`: a document's own claims are settled before its id is
> booked.

**[S]** The check reads the log **at the delegate op's own position**, and the verdict
is positional like every other in this layer (§11). A key that is nobody's registered
signing key where the delegation lands does not become one retroactively: a device
that registers it afterwards leaves the delegation, and everything it has signed,
untouched.

> The alternative is the retroactive rewrite §11 exists to forbid — a registration
> arriving in June silently unmaking a delegation from March and every certificate it
> signed in between.
>
> Which bounds what the rule buys, and the bound is worth stating. Disjointness is
> enforced where the delegation lands and nowhere else; a client that wants it to hold
> for ever mints the delegation key fresh, registers it nowhere and amends nothing to
> it. Nor is any key
> barred for ever — a handover retires a Root, and the key it retires is delegable
> after it. The remedy for this refusal is still a different document, never a retry
> of this one.

### `root_handover`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 malformed_root_pk` | either key is not 32 bytes |
| `422 cert_root_pk_mismatch` | `from_root_pk` is not this Workspace's current Root |
| `422 bad_root_signature` | the outgoing Root did not sign these bytes |

**[S]** `cert_root_pk_mismatch` means **the Root this certificate names is not the one
in force for this Workspace**, and this is one of the two occasions the core raises it
on. The other is at `POST /v1/members`, where a `member_register` certificate presents
a `root_pk` that is not that Workspace's current Root ([Identity](02-identity.md)).

> Not a merged code. Both mean *rebuild this document against the Root the log
> actually says is current*, and the remedy is identical; only the door you arrived at
> differs. That is the test the [code list](reference/refusal-codes.md) applies.

**[W]** `cert_root_pk_mismatch` and `bad_root_signature` **MUST remain distinct
codes.**

> A server that can only say `bad_root_signature` destroys information a skewed
> device cannot recover. The first means *this certificate names a Root that is not
> this Workspace's* — a client that built the document against the wrong key, which
> has a real remedy. The second means *these bytes are forged* — not recoverable,
> save for the one documented race (§6: a delegation revoked between the doors,
> repaired by a freshly issued certificate). Collapsing them is a contract
> violation, not a simplification.

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

### `role_table`

**[S]** In order:

| Refusal | Cause |
|---|---|
| `422 cert_workspace_mismatch` | names another Workspace |
| `422 malformed_role_table` | the table breaks a core rule, or an entry is misshapen |
| `422 bad_root_signature` | the current Root itself did not sign these bytes |

**[S]** `malformed_role_table` is **shape**, decided from the certificate's own bytes
and nothing else, so it sits above the signature exactly as `malformed_root_pk` does
on a `delegate`. It covers, all of them:

```
   an entry whose key set is not the closed three
   a role failing ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$, or outside 1–32 bytes
   a repeated role token
   a classes member that is not an integer in 0–255, or repeated
   a prune_types member outside {prune, prune_ext, hard_prune}, or repeated
   a non-empty prune_types on an entry whose classes does not name 129
   not exactly one entry named owner                        — rule 1
   an entry other than owner naming 128                     — rule 2
```

> Distinct from `malformed_control_payload`, which keeps the outer payload and the
> certificate's own key set, because the remedies are different sizes. *Your payload
> carries a key it should not* is a serialisation bug; *your table has two owners* is
> a table to redesign, and it is the one a profile author porting a configured table
> will meet.
>
> The last two are values judged for what they say, and they are shape here on the
> precedent a rotation that skips an epoch already sets (below). A **self-contained**
> consistency check over a document's own literals reads no log, decides no authority
> and records nothing, which is the whole of what §5 asks of a check above the
> signature.

**[W]** The token pattern is the protocol's one token shape, the same one
`PROTOCOL_NAMESPACE` and an extension NAME already carry
([Keys](04-keys.md#the-namespace), [The Log](01-the-log.md#3-the-class-byte)).

**[W]** A table MAY name a class the deployment does not serve, and naming one confers
nothing: an op of an unserved class is refused `unsupported_op_class` at stage 1
whatever any table says.

> Deliberately not a refusal. A table is in the log for ever and judged positionally,
> so binding its validity to the deployment's current class set would let a table that
> was legal in March become illegal in June because a profile dropped an opaque class
> — the retroactive rewrite §11 exists to forbid, arriving through the back door.

**[W]** A `role_table` carries **no id of its own**, as a handover does not. Nothing
ever names one, and installing the same table twice is installing it once — so there
is no repetition to refuse.

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
founding Root — the one the Workspace id is bound to (§2) — is unchanged and
unchangeable.

```
   before          founding = current = R₀       reachability is the founding binding
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

**[S] A member amend** replaces the keys it names **at its own position**, and nothing
earlier: every op below it keeps verifying under the keys it was signed with, for
ever. Where `control` is one of them, three more things follow at the commit:

```
   amend{control} lands
       │
       ├─► the old control key stops signing new ops here
       │
       ├─► every refresh token scoped to that device is revoked
       │
       └─► every live signal socket that device holds here closes with 4403
```

> The same cascade a lost last grant runs (above), minus the grant half, and for the
> same reason: a credential the retired key already obtained would otherwise outlive
> the retirement.

**[S] A role table** replaces the role vocabulary **from its own position**, and
changes the verdict of nothing already in the log. Grants stay live, ops stay
legitimate where they landed, and the only thing that moves is what the *next* op is
judged against.

> Worth saying out loud for this one, because it is the rule people expect a role
> change to break. Narrowing a role does not retroactively delegitimise a year of
> writes; it decides what may be written next.

**[S] A rotate** creates a new key epoch → [Keys](04-keys.md).

---

## 12. Repeats, again

[The Log](01-the-log.md) established that re-posting an op is free. Six consequences
land here, and all six are required:

| Replayed | Must **not** raise | Because |
|---|---|---|
| a grant | `grant_id_already_used` | the id belongs to the op that first asserted it |
| a revoke | `already_revoked` | and the boundary must not move |
| an amend | `amend_id_already_used` | the id belongs to the op that first asserted it |
| a `prune` or `prune_ext` | `prune_target_already_reprised` | it marked those targets itself |
| any control op | `control_chain_break` | its link named the tip it was built on, and the tip has moved since (§4) |
| any control op | — | it must not take effect twice |

**[S]** A replayed `role_table` needs no exemption of its own. It books no id, and
installing one table twice is installing it once.

> Same argument each time: re-posting an op asserts nothing new. Without these, every
> retried ceremony — the normal path, not an edge case — reads as an attack.

---

## Next

[Keys](04-keys.md): how content stays private from the server, and which party holds
which key.
