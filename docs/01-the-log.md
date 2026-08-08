# The Log

*What is stored, and how it is shaped.*

This layer is the whole point of the server. Every layer after it exists to decide
who may add to the log and to keep its contents private; nothing else the server
does matters if this layer is wrong.

Read [the overview](README.md) first for conventions and error shapes.

---

## 1. Ops

An **op** is one record of change, authored by one device.

That is all the server knows about it. What an op *means* — a field set to a
value, a row deleted, twelve rows merged — is a fact about the application, and
the server has no access to it. Ops carry application data the way an envelope
carries a letter.

Every op is:

- **signed** by the device that wrote it, so its origin is provable;
- **usually sealed**, so nobody but the intended readers can open it;
- **immutable** once written — the log is never edited;
- **positioned twice**: once in its author's own sequence, once in the shared log.

---

## 2. The envelope

An op on the wire is an **envelope**: a fixed header, an opaque body, a
signature.

```
 ┌──────────────────────── 158 bytes ────────────────────────┐
 │ HEADER — always in the clear, always this shape           │
 ├─────┬─────┬──────────────┬────────┬──────────────┬────────┤
 │class│suite│ workspace_id │key_epoch│    op_id     │ author │ …
 │ 1B  │ 1B  │     16B      │   4B    │     16B      │  16B   │
 └─────┴─────┴──────────────┴────────┴──────────────┴────────┘
 ┌───────────────────── variable ──────────────────────┐
 │ BODY — opaque when the class has bit 7 clear        │
 │        readable when it is set                      │
 └─────────────────────────────────────────────────────┘
 ┌────────── 64 bytes ──────────┐
 │ SIGNATURE (Ed25519)          │
 └──────────────────────────────┘
```

**[W]** The full header, in canonical order. Fixed widths, big-endian integers:

| Offset | Size | Field | What it is |
|---:|---:|---|---|
| 0 | 1 | `op_class` | the class byte — §3 |
| 1 | 1 | `suite` | the sealing construction: `0x00` none, `0x01` sealed. **Which values are legal depends on the class** → §3, [Keys](04-keys.md) |
| 2 | 16 | `workspace_id` | which log this belongs to |
| 18 | 4 | `key_epoch` | which key generation sealed it |
| 22 | 16 | `op_id` | the author's own id for this op |
| 38 | 16 | `author_member_id` | which device wrote it |
| 54 | 8 | `author_key_id` | which of that device's keys signed it |
| 62 | 8 | `author_seq` | position in *this author's* chain, from 1 |
| 70 | 32 | `prev_author_hash` | hash of this author's previous envelope |
| 102 | 32 | `observed_head` | reserved; all-zero in v1 |
| 134 | 24 | `nonce` | encryption nonce; all-zero when unsealed |

The header is constant width, so no length prefixes are needed anywhere: the
envelope's own length gives the body's.

```
  body length = total length − 158 (header) − 64 (signature)
              = total length − 222
```

**[W]** The signature covers `header || body` and is made with the author's
signing key. Its exact construction is in [Keys](04-keys.md); what matters here is
that **the server does not check it** (§8).

### The body: framing and padding

Inside the body, before any encryption:

```
  ┌────────────┬─────────────────────┬──────────────────────┐
  │ payload_len│      payload        │  zero padding        │
  │   4 bytes  │     N bytes         │  up to a size class  │
  └────────────┴─────────────────────┴──────────────────────┘
```

**[P]** Bodies are padded up to the nearest **size class** — a short ladder of
fixed lengths declared by the profile — or, above the largest, to the next
multiple of a fixed step.

> Padding is a confidentiality mechanism, not a bandwidth one. Without it, body
> length leaks how much was written. A coarse ladder is the padding working: each
> extra size class hands an observer one more bit about payload size.

**[W]** Three rules bind anyone who unpacks a body: the length must be a legal
size class, `payload_len` must not overrun the body, and the padding must be all
zero.

**[S]** The server unpacks the body of a class **with bit 7 set**, and enforces
all three there. It MUST NOT unpack a body whose class has bit 7 clear.

**[C]** A client MUST enforce all three on every body it unpacks — on the
decrypted plaintext, when the op is sealed.

**[S]** On *every* class, including those it never unpacks, the server enforces
a **length floor**: an envelope shorter than header + smallest size class +
signature is refused `envelope_too_short`. This follows from the size classes
alone and reads no body byte.

---

## 3. The class byte

The class is a single byte in every op's header. **Its top two bits carry
structure; the low six select a value within it.**

```
   bit 7 ─── the server reads the body
   │ bit 6 ─── defined outside the core
   │ │
   ▼ ▼
   0 0 · · · · · ·    0x00–0x3F    opaque      ·  core-assigned
   0 1 · · · · · ·    0x40–0x7F    opaque      ·  profile-defined
   1 0 · · · · · ·    0x80–0xBF    server-read ·  core-assigned
   1 1 · · · · · ·    0xC0–0xFF    server-read ·  implementation extension
```

**[W]** **Bit 7 is the single most important boundary in the system.** A server
decides whether it may unpack a body by testing one bit — not by consulting a
table it might misread, and not by a rule that a later editor can loosen. Every
class with bit 7 clear is opaque, for ever, by construction.

**[W]** The assigned values in v1:

```
  class   name          reads?   what it is
  ─────   ───────────   ──────   ─────────────────────────────────
   0x01   content         ✗      ordinary application data
   0x02   reprise         ✗      restates the ops it replaces  → §7
   0x80   control         ✓      who exists, who may write  → Authority
   0x81   prune           ✓      "these ops are reprised"
   0xBF   ext_binding     ✓      binds one extension class to a name
```

**[W]** The gap in `0x80–0xBF` is **allocation direction, not an oversight.** Two
families live in the core's server-read range and grow toward each other:

```
   0x80  control        ─────►   log semantics ascend
   0x81  prune
    ⋮                            growth room
   0xBF  ext_binding    ◄─────   protocol self-description descends
```

> A class that governs *ops* is a different kind of thing from a class that
> governs *classes*, and interleaving them would mean renumbering one family the
> first time the other grew. Filling this range from the middle would undo that.
> If the two ever meet, 64 server-read classes are genuinely in use, which is
> information rather than an arbitrary boundary.

**[W]** Anything not assigned, declared or enabled is refused
`unsupported_op_class`. **Fail closed is the rule at every level of this byte.**

**Every server-read class must be written under a construction the server can
open** — it has to *act* on those payloads. In v1 that set is exactly `{0x00}`, so
`suite` is pinned above bit 7 and carries no information there.

> The rule is on the **capability**, not on the value. "Plaintext for ever" is the
> right answer today and the wrong statement of why: what the server needs is to
> read the payload, not for the payload to be in the clear. A construction the
> server can open would widen the legal set without touching the principle — see
> [Keys](04-keys.md).

> Everything the server can read is metadata about *permissions and housekeeping*.
> Nothing it can read says anything about what the application stores. A prune op
> names positions, author sequence numbers and hashes — all of which the server
> already holds — and nothing about what any op said.

### What a class value actually decides

Bit 7 decides how the server **handles** an op. Within a quadrant, the value
decides **who may author one** — and nothing else.

**[S]** `0x01` and `0x02` are indistinguishable to the server: same handling, same
storage, same prune eligibility, same read filter. They differ in exactly one
code path, `role_forbids_op_class`, and that is the whole reason `0x02` exists.
A profile can withhold `0x02` from a role that holds `0x01`, or the reverse.

> This is worth stating plainly because the names mislead. "Content" and
> "reprise" sound like a taxonomy of meaning, and to the server they are not:
> they are two authorisation lanes over one behaviour. A folding service that
> may fold history but may not author data is the case the split was built for.

**[P]** So the opaque range is where granularity lives. A profile that needs
finer lanes than "may write" and "may fold" declares its own classes in
`0x40–0x7F` — see [profile obligations](reference/profile-obligations.md).

**[W]** The ceiling on this mechanism: a class says who may write an op, never
what is inside one. The server cannot read an opaque body, so a member holding a
class may put anything at all in it. Classes are lanes, not predicates.

### Profile-defined classes — `0x40–0x7F`

**[P]** A profile MAY assign classes in this range. **[S]** The server treats
every one of them **exactly as `0x01`**: never unpacked, sealed or plaintext by
the ordinary suite rules, eligible as a prune target, hidden by prune marking,
and admitted only by a role that names it.

**[S]** A class in this range that the profile has not declared is refused
`unsupported_op_class`, like any unassigned value.

> There is no collision hazard across profiles. `PROTOCOL_NAMESPACE` is globally
> unique and feeds every signing domain, so two deployments' ops cannot verify
> against each other whatever they call `0x45`.

### Implementation extensions — `0xC0–0xFF`

**[S]** This range is the escape hatch: a server implementation MAY define
server-read classes here for behaviour the core did not anticipate.
**Disabled by default.** Five rules bind it.

| # | Rule |
|---|---|
| 1 | **[P]** The profile MUST enable each class explicitly and give it a **NAME** — `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, 1–32 bytes, unique within the namespace. The NAME is never optional. An unenabled class is refused `unsupported_op_class`. |
| 2 | **[W]** Ops of the class are signed under the domain `<namespace>/ext/<name>/v1`. |
| 3 | **[S]** A member declares its understanding of the class by writing an **`ext_binding`** op (`0xBF`) **carrying the NAME**, and it is judged positionally, exactly like a grant. |
| 4 | **[S]** An `ext_binding` whose NAME is not byte-identical to what this server implements for that class is refused `ext_name_mismatch`, carrying `index`, `op_class` and the `expected` name. **A class is never bound under a name the server does not agree with.** |
| 5 | **[S]** An extension MUST NOT alter the visibility, ordering or interpretation of any op outside `0xC0–0xFF`, **except** that it MAY hide ops — and any op it hides MUST carry the same attestation a prune carries: author, author sequence and envelope hash. |

> **Rules 2 and 4 cover different failures, and the second is the one that bites.**
> The signing domain protects *readers*: a client built against `audit-marker`
> cannot verify an op written under `retention-sweep`. But **the server does not
> verify signatures** (§8), so the domain never reaches the party that acts on a
> server-read op.
>
> And every implementation's first extension will be `0xC0`. Move a log — or a
> client — from a server where `0xC0` means one thing to one where it means
> another, and without rule 4 the second server processes those ops under the
> wrong meaning, destructively, before any reader is in a position to notice.
> With it, the very first `ext_binding` refuses and somebody fixes it. **The NAME
> is what turns a silent divergence into a loud one**, which is why it is
> mandatory in the profile and on the wire, not in one place or the other.
>
> Rule 5 is the other one that is easy to get wrong, and the reason is not
> distrust of the deployment. A server that simply withholds ops is *detected*:
> the author chain breaks and a device notices. A class that removes ops while
> producing no attestation is not detected — a device enrolling two years later
> sees a hole it has nothing to check against, and accepts it. Destructive is fine
> here. Unverifiable is not.

**[S]** A server MUST advertise the extension classes it implements in its served
sets. **[S]** A server that implements none MUST behave exactly as though the
range were unassigned, and MUST pass the whole conformance suite with ops of an
unknown extension class present in the log.

### Binding a class: `ext_binding`

An `ext_binding` is **not** a permission. Permission is the role table, as for
every other class. It is a **semantic handshake**: the author asserting what it
believes the class means, so a client and a server that disagree find out before
anything acts.

**[S]** A binding is scoped to **`(Workspace, member, class)`**, with a start
position and a write-once end position — the shape a grant already has. A
member's op of an extension class is judged against **that member's own** live
binding, and against no one else's.

**[S]** One binding per class exists **server-side**, from the profile. Member
scoping does not let a class mean two things at once; it means each member must
agree with that one binding independently, and a member whose software disagrees
is locked out loudly instead of being silently reinterpreted.

**[S]** **Binding of record.** Every op of an extension class is judged against
the NAME in its author's live binding. If the server's current implementation of
that class no longer answers to that name, the op is refused
`422 ext_name_mismatch`. **A server MUST NOT reinterpret an op under a meaning
its author never agreed to.**

> Checking the name only when the binding lands is not enough:
>
> ```
>    t0   member binds     "0xC5 = publish-to-world"    server agrees  ✓
>    t1   operator reconfigures  0xC5 → delete-permanently
>    t2   member writes 0xC5     meaning publish
>         → refused. Without this rule, the server deletes.
> ```
>
> Reconfiguring stays legal. It invalidates disagreeing bindings, and those
> members cannot use the class until they bind again.

#### Why member-scoped, and not per Workspace

**Because skew is permanent** ([Compatibility](05-compatibility.md)). A
Workspace-wide binding is a value that can move under an author who has not
caught up:

```
   member B  binds  0xC5 = destroy          ─┐  B is a newer app
   member A  is 400 ops behind and has        │  A has not seen B's op
             never seen it                    │
   member A  writes 0xC5 meaning publish    ◄─┘  server destroys
```

No client-side check can prevent that, because every client's view of the log is
stale by construction — that is the premise the whole compatibility layer is
built on. Member scoping moves the check to a point where staleness is
impossible: **A learns at its own write, synchronously, and never needs to have
seen B's op at all.**

```
   B binds  "0xC5 = destroy"     ✓  server agrees
   A binds  "0xC5 = publish"     ✗  ext_name_mismatch, expected = destroy
   A writes 0xC5 regardless      ✗  ext_class_not_active
```

**[C]** A client MUST NOT author an op of an extension class for which it holds
no live binding of its own carrying the name it believes. It MUST NOT infer one
from another member's binding.

> An implementation MAY additionally repeat the NAME inside its own extension
> payload, which makes the check local to the op rather than a state lookup.
> Non-normative: the core does not require it, because extension payloads are the
> implementation's business and every op would carry the cost for ever —
> occasionally rounding up a whole size class.

#### When a binding takes effect

**[S]** A class is bound for a member **from the position of that member's
`ext_binding`**, and an op of that class at any earlier position is refused
`422 ext_class_not_active`, carrying `index` and `op_class`.

**[S]** Within a batch this is decided by **arrival order**, not by the batch as a
whole. Stages 2–4 already run per op in arrival order.

```
   batch  [ ext_binding(0xC5) , 0xC5 op ]     ✓  the binding is already committed
   batch  [ 0xC5 op , ext_binding(0xC5) ]     ✗  ext_class_not_active at index 0
```

> Exactly the shape a prune already has with its own reprise, which may be
> "earlier in this batch". Stating it matters because the alternative reading —
> judging the batch as a set — would let an op be validated against a binding that
> did not exist when it was written, and positional judgement is the one thing
> every other authority rule in this system agrees on.

**[S]** A binding ends at the position of the `unbind` that closes it. Ops of that
class between start and end are valid for ever; ops after it are refused. **Ending
a binding is not a rollback** — whatever the extension already did stays done, just
as revoking a grant does not unwrite what that device authored.

#### The `ext_binding` payload

**[W]** `0xBF` bodies are **unencrypted JSON**, for ever, on the same rule as every
other server-read class. Two types:

```
   bind      this member reads this class as this name
   unbind    that reading is over
```

```json
{"type": "bind", "op_class": 197, "name": "retention-sweep"}
```

```json
{"type": "unbind", "op_class": 197}
```

**[W]** `op_class` is an **integer**, not a hex string — JSON has no hex literal,
and a string would invite two spellings of one value. `197` is `0xC5`.

**[W]** **There is no `binding_id`, and no chain link.**

> Both absences are deliberate, and both come from the same place. A grant needs a
> `grant_id` because a device may hold several at once, so a revoke has to name
> which. A member has **at most one live binding per class** by rule, so the class
> *is* the key and `unbind` needs nothing else.
>
> And a control op carries `prev_control_hash` because control ops form a chain
> across all authors, where a link points at bare bytes with no surrounding
> context. A binding is per-member and already sits in its author's own chain
> through `prev_author_hash` on the envelope. A second chain would attest nothing
> the first does not.

**[W]** `type` is mandatory in both, and stays mandatory for ever — a payload that
does not say what it is cannot gain a third type later without ambiguity.

##### Stage 3 — what the server checks

**[S]** In order, all `422` with `index` unless noted:

1. framing: `invalid_body_length`, `payload_overruns_body`, `non_zero_padding`
2. shape: `malformed_ext_binding_payload`, then `unsupported_ext_binding_type`

**[S]** Shape rules, all `malformed_ext_binding_payload`: an unrecognised key; a
missing `type`, `op_class` or — on `bind` — `name`; a `name` on an `unbind`; an
`op_class` outside **192–255**; a `name` failing
`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$` or outside 1–32 bytes.

**[S]** Then, per type:

| Type | Refusal | Cause |
|---|---|---|
| `bind` | `ext_class_not_enabled` | the deployment does not permit this class; carries `op_class` |
| `bind` | `ext_name_mismatch` | the server implements this class under another name; carries `op_class` and `expected` |
| `bind` | `409 ext_class_already_bound` | this member already holds a live binding for this class |
| `unbind` | `ext_class_not_bound` | this member holds no live binding for this class |

**[S]** `ext_class_not_enabled` is distinct from `unsupported_op_class`, which
answers about the op's **own** class. A `0xBF` op is always a served class; what it
*names* may not be.

**[S]** An `unbind` is looked up under `(Workspace, author, op_class)`. **A member
can only unbind its own binding** — another member's is not found, and answers
`ext_class_not_bound`.

> The same rule a prune already follows with its own reprise. A binding is a
> statement about what *this* member understands, so no one else is in a position
> to withdraw it.

**[S]** A member MAY bind a class again after unbinding it, with the same name or a
different one. Each `bind`/`unbind` pair is one interval, and an op is judged
against the interval its position falls in.

```
   member A    bind 0xC5 "publish"          unbind            bind 0xC5 "archive"
               │                            │                 │
        ───────●════════════════════════════●─────────────────●═══════════════►
                    ops read as publish        refused             ops read
                                                                  as archive
```

> Which is what an app upgrade looks like: the client's understanding of a class
> changed, so it closes the old reading and opens a new one. Ops written under the
> old interval keep their old meaning for ever, because meaning is positional here
> exactly as authority is.

---

## 4. Workspaces

A **Workspace** is the unit of partition: one log, one set of permissions, one
sequence of encryption keys.

```
  User "alice"
  ├── Workspace  a1b2c3…        ┌───┬───┬───┬───┬───┬───┐
  │   (main data)               │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ ← its own log
  │                             └───┴───┴───┴───┴───┴───┘
  │                              own grants · own key epochs
  │
  └── Workspace  d4e5f6…        ┌───┬───┬───┐
      (settings, say)           │ 1 │ 2 │ 3 │ ← a different log
                                └───┴───┴───┘
                                 own grants · own key epochs
```

Nothing crosses a Workspace boundary. Positions restart at 1. A device revoked in
one is unaffected in the other. A key rotation in one does not touch the other.

**[P]** *How many Workspaces a user has, and how their ids are chosen, is a
profile decision* — see [Authority](03-authority.md), which owns the reachability
rule, and [profile obligations](reference/profile-obligations.md).

**[S]** A Workspace does not exist because someone named it. It exists when a
signed **genesis** op is accepted into it (Authority). Before that, reads return
nothing and writes are refused.

---

## 5. Two positions, and why both exist

Every op sits in two orderings at once. Confusing them is the most common way to
misread this specification.

```
   THE LOG (one per Workspace)          per-author chains woven through it
   ───────────────────────────          ─────────────────────────────────

   seq 1   ← device A, author_seq 1     A: 1 ──2 ─────────3
   seq 2   ← device B, author_seq 1        │  │           │
   seq 3   ← device A, author_seq 2     B: 1 ──2 ──3
   seq 4   ← device B, author_seq 2
   seq 5   ← device B, author_seq 3     each device's ops form an unbroken
   seq 6   ← device A, author_seq 3     hash-linked chain of its own
```

**`author_seq` — the author's own chain.** Starts at 1, strictly contiguous, no
gaps ever. Each op carries the hash of its author's previous envelope, so a
device's output is a tamper-evident chain. A gap means a device's chain is broken
and something is wrong.

**`seq` — the transport position.** Assigned by the server when an op is stored.
It is a **cursor and nothing else**: never causality, never an input to merging,
never evidence of anything. Holes in it are meaningless.

**[W]** Ordering for *merge* purposes lives inside the payload — a logical clock
the server never reads. `seq` never participates.

> The temptation is to treat `seq` as time. It is not: two devices writing
> concurrently get positions in whatever order their requests arrived, which says
> nothing about which change happened first. `seq` answers exactly one question —
> "what have I not fetched yet?"

---

## 6. Writing: `POST /v1/w/{workspace_id}/ops`

**Credential:** a device (member) token → [Identity](02-identity.md).

```json
→ {"ops": ["<base64 envelope>", "<base64 envelope>", …]}

← {"results": [{"op_id": "…", "seq": 41, "duplicate": false},
               {"op_id": "…", "seq": 42, "duplicate": false}]}
```

**[S]** `results` is positional — one entry per submitted op, in order. `seq` is
the position the op now occupies.

### The batch is all-or-nothing

**[S]** **The whole batch commits, or none of it does.** One refusal rejects every
op in the request, including ops that would have been fine alone. There is no
partial success.

### Ops are walked in order, and earlier ops count for later ones

**[S]** Ops are validated and applied **in arrival order**, and the effects of
earlier ops in the same batch are visible to later ones.

```
  POST { ops: [ genesis, register, grant, content ] }
                  │        │         │        │
                  │        │         │        └─ authorised by the grant at index 2
                  │        │         └─ needs the registration at index 1
                  │        └─ needs the Workspace created at index 0
                  └─ creates the Workspace
```

> This is what lets a brand-new device post its entire enrolment as one request.
> The alternative — four round trips, each depending on the last — is four chances
> to be interrupted halfway.

### The pipeline

Validation runs in five stages. This is where the layers meet, so the diagram
marks which layer owns each stage:

```
   ┌── STAGE 0 ─────────────────────────────────── Authority ──┐
   │  Is this Workspace reachable for this user?             │
   │  Is the batch within the size ceiling?                  │
   └────────────────────────┬────────────────────────────────┘
                            ▼
   ┌── STAGE 1 ─────────────────────────────────── The Log ──┐
   │  EVERY op, header only, no body read:                   │
   │  decodes? long enough? served suite and class?          │
   │  right Workspace? authored by this token's device?      │
   └────────────────────────┬────────────────────────────────┘
                            ▼
   ┌── STAGE 2 ─────────────────────────── Authority and 4 ───┐
   │  every class but control:                               │
   │  does the Workspace exist? does the role allow it?      │
   │  is the key epoch current enough?                       │
   └────────────────────────┬────────────────────────────────┘
                            ▼
   ┌── STAGE 3 ─────────────────────────────────── The Log ──┐
   │  prune and ext_binding: read the body, check it         │
   └────────────────────────┬────────────────────────────────┘
                            ▼
   ┌── STAGE 4 ─────────────────────────────────── Authority ──┐
   │  control ops: read the body, verify every certificate   │
   └────────────────────────┬────────────────────────────────┘
                            ▼
   ┌── STAGE 5 ─────────────────────────────────── The Log ──┐
   │  author chain: is each op the next in its author's      │
   │  sequence?                                              │
   └────────────────────────┬────────────────────────────────┘
                            ▼
                      commit, then notify
```

**[S]** Stage 1 runs over **every op in the batch** before any op reaches stage 2.
Stages 2–4 run **per op in arrival order**, and the first failure refuses the
batch. Stage 5 runs once every op has passed 2–4.

> That ordering is observable, so it is protocol. A batch of `[prune with no
> targets, content op with no permission]` answers about index 0; a batch of
> `[content op with no permission, unparseable base64]` answers about index 1,
> because stage 1 is a complete pass.

### Stage 0 and 1 refusals

| Refusal | Cause |
|---|---|
| `403 no_registration` | this device is not registered in this Workspace |
| `413 batch_too_large` | more ops than the advertised ceiling |
| `422 malformed_base64` | not base64 |
| `422 truncated_envelope` | under 158 bytes — no header |
| `422 envelope_too_short` | header present, but no legal body could fit |
| `422 unsupported_op_class` | unknown, reserved, undeclared or unenabled class |
| `422 unsupported_suite` | unknown suite byte, or one this class forbids |
| `422 encrypted_control_op` | a `0x80` op that is sealed → [Keys](04-keys.md) |
| `422 encrypted_prune_op` | a `0x81` op that is sealed → [Keys](04-keys.md) |
| `422 workspace_mismatch` | header names a different Workspace than the URL |
| `403 author_member_mismatch` | header names a different device than the token |

**[S]** All of them carry the zero-based batch `index`.

> `workspace_mismatch` is the header-versus-URL cross-check: parsed fields are
> checked *against* the envelope bytes and never trusted *over* them.
> `author_member_mismatch` is one comparison and no cryptography — a token speaks
> for exactly one device, and that device is the only author it can post as.

**[S]** An empty `ops` array returns `{"results": []}` and changes nothing.

Stages 2 and 4 belong to [Authority](03-authority.md); the epoch check in stage 2
belongs to [Keys](04-keys.md). Stages 3 and 5 are below.

### Stage 5 — the author chain

**[S]** Each op's `author_seq` must be exactly one more than that author's current
highest. Otherwise: `409 author_chain_conflict`, carrying `index`, `author_seq`
and `expected_author_seq`. **The whole batch fails.**

> A gap means the writing device's chain is broken, and accepting the rest would
> make the break permanent. `expected_author_seq` is load-bearing, not a courtesy:
> a device compares it against what the server already acknowledged, to tell an
> ordinary conflict from a server that lost its writes.

**[S]** There is a second form of the same code with **none of those three
fields**, raised when a concurrent request for the same author committed in
between. The absence says "no verdict" precisely; a guessed number would be read
as a rollback.

**[S]** Neither form is ever a `500`. The device's next move is to re-pull either
way.

### Repeats are free

**[S]** An op is identified by `(workspace, author, op_id)`. A repeat — in a later
request or **within the same batch** — returns `duplicate: true` with the position
the op already holds, and applies nothing a second time.

**[S]** Within one batch the **first** occurrence is not a repeat: it is stored
and returns `duplicate: false`. Every later occurrence returns `duplicate: true`
with that same position.

> Retrying is the normal path, not an edge case: a device that loses its
> connection mid-request has no idea whether the batch landed. Idempotency is what
> makes "just send it again" correct. [Authority](03-authority.md) lists four
> further exemptions that follow from this rule.

### What a successful write causes

Not just storage. In order, after the commit:

```
   ops stored verbatim
        │
        ├── control ops → Workspace exists / device registered /
        │                 permission granted or revoked / new key epoch
        │                                                  → Authority, 4
        │
        ├── prune ops   → named ops marked reprised
        │
        ├── if any permission was fully revoked:
        │        that device's tokens die, its live sockets close
        │
        └── if anything was new (not a pure repeat):
                 every subscriber is poked  ────────────────► §10
```

**[S]** Ops are stored **byte-identical** and served back byte-identical. The
envelope is the truth; every field the server parsed out of it is an index.

**[S]** The poke happens **after** the commit, and only if at least one op was
new.

> Before the commit, a woken subscriber pulls and finds nothing — the poke is
> wasted. And a pure repeat is not news.

---

## 7. Replacing old ops: reprise and prune

Over time a Workspace accumulates ops that no longer matter individually: a
hundred edits to one record, when only the result is interesting. A **reprise** —
a `0x02` op — states their combined effect again, in one op. **Prune** — a `0x81`
op — then says which ops that reprise replaces.

**A reprise says the same thing again; it never says something new.** Two motives
lead there, and the core distinguishes neither:

| Variant | Why | What changes |
|---|---|---|
| **compaction** | a hundred edits, one interesting result | fewer ops to replay and store |
| **version upgrade** | the payload encoding moved on | the same facts, in the current encoding |

> Both are one operation to the server — many ops replaced by one it cannot read.
> Which you meant is a fact about your application, and belongs in the payload
> where the server cannot see it and does not need to. Naming the class after
> either motive, as an earlier draft did, was the mistake this name fixes.
> Evolving the payload encoding is set out under
> [evolving the payload schema](#guidance--evolving-the-payload-schema).

```
   before      1  2  3  4  5  6  7          all seven still needed
                                            to reconstruct the record

   reprise     1  2  3  4  5  6  7  8       8 = class 0x02, holds the fold
                                     ▲
   prune       1  2  3  4  5  6  7  8  9    9 = class 0x81, "8 reprises 2,3,5,6"
               ▓     ▓     ▓  ▓             ▓ = marked, hidden from normal reads
                                            — but still stored, and still fetchable
```

**[S]** A prune **deletes nothing.** The named op is marked; the default read hides
it; `include_reprised=true` serves it back. Destroying the bytes is a **second,
separate op** — `hard_prune`, below — which can only ever target an op a prune has
already marked.

> Two steps because the reverse order is impossible. A soft mark is recoverable, a
> destroyed byte is not, so the recoverable step goes first and always lands first.

### The prune payload

**[W]** `0x81` bodies are unencrypted JSON, and every one is **self-identifying**:

```json
{"type": "prune",
 "reprise": {"op_id": "<uuid>"},
 "targets": [{"seq": 2,
              "author_member_id": "<uuid>",
              "author_seq": 7,
              "envelope_hash": "<hex64>"}]}
```

**[W]** `type` is **mandatory in every `0x81` payload, for ever**, and an unknown
value is refused `unsupported_prune_type`. Two types in v1: `prune` and `hard_prune`.

> Same rule as `0x80`, for a related reason. A payload that has to be *inferred* from
> which fields are present is one that two implementations will infer differently the
> first time a field becomes optional — and here the two types differ by whether bytes
> survive.

Why a target is more than a position: a reprise removes ops from the *middle* of
each contributing author's chain, not from the front.

```
   author A's chain:   1 ── 2 ── 3 ── 4 ── 5
                            ▓         ▓        pruned from the middle

   a fresh device sees:  1 ── ? ── 3 ── ? ── 5
                              ▲         ▲
                              needs proof these were legitimately removed,
                              AND the hash to link 3 back past the hole
```

**[W]** So each target carries all four: the position (for the server), the author
and their sequence number (to locate the hole), and the envelope hash (so a
verifier can chain past it).

**[W]** Three **shape** rules bind author and reader alike, refused wherever the
bytes are held:

| Rule | Refusal |
|---|---|
| at least one target | `prune_targets_empty` |
| no duplicate by `seq`, **and** none by `(author, author_seq)` | `prune_duplicate_target` |
| at most 1000 targets | `prune_targets_too_many` |

> Duplicates are refused at decode so that a later rowcount check has exactly one
> remaining explanation — a concurrent prune. Otherwise a race and a malformed
> payload become indistinguishable.

### `hard_prune`: reclaiming the bytes

A reprised op still occupies disk. It is invisible to every ordinary read and to
every device that enrols after it, and it is charged for like anything else. A
`hard_prune` says: **those bytes may go.**

**[W]** Same class, same target shape, no reprise of its own:

```json
{"type": "hard_prune",
 "targets": [{"seq": 2,
              "author_member_id": "<uuid>",
              "author_seq": 7,
              "envelope_hash": "<hex64>"}]}
```

**[S]** The server drops the **envelope bytes** for each target and keeps a
**tombstone**: op id, transport position, author, `author_seq`, and the position of
the prune that reprised it. Three things depend on the tombstone surviving:

```
   uniqueness   (workspace, author, op_id) still refuses a re-append,
                so a destroyed op cannot be resurrected as a new one

   positions    seq stays stable, so every `since` cursor keeps working

   audit        the gap has a name, and the op that authorised it is findable
```

> Which is also the honest limit on what is reclaimed. A tombstone is a few dozen
> bytes and an envelope is a size class; hard-pruning recovers the payload, never the
> row. A Workspace of a hundred million tiny ops does not shrink to nothing.

**[S]** Four rules, each fail-closed:

| Rule | Refusal |
|---|---|
| the target is already marked reprised | `hard_prune_target_not_reprised` |
| the target is not itself a `0x81` op | `hard_prune_target_is_prune` |
| `envelope_hash` matches the op held at that `seq` | `prune_target_attestation_mismatch` |
| the shape rules of the prune payload, unchanged | `prune_targets_empty`, `prune_duplicate_target`, `prune_targets_too_many` |

**[S]** A target whose bytes are **already gone** is not an error. It is the
concurrent case — two folders reclaiming the same span — and it applies nothing a
second time, exactly like a repeat.

**[S]** `include_reprised=true` no longer returns a hard-pruned op. The position is
absent from the page, and the `hard_prune` that removed it is in the log.

#### Why prune ops may never be targets

**[W]** Rule 2 is not tidiness. A soft prune carries `envelope_hash` for every op it
marks, and that hash is *the only thing* that lets a verifier chain past the hole it
created, above. Destroy the prune and every hole it authorised becomes unexplainable:
a reader meets a gap in an author's chain with nothing to bridge it and no signed
statement that the removal was legitimate.

> So the evidence outlives the evidence's subject, deliberately. Prune ops accumulate
> for ever and that is the price of the archive being *checkable* rather than merely
> absent. They are small, bounded at 1000 targets each, and they are the reason a
> hostile server still cannot quietly drop an op it dislikes: no `hard_prune` naming
> it, no legitimate gap.

#### What a hard prune costs, stated plainly

**[C]** It is **irreversible**, and it is the only operation in this protocol that
is. Everything else appends. A client MUST NOT offer it as an automatic background
behaviour without the Workspace's own policy behind it, and MUST NOT present it as
"cleaning up".

**[S]** The server **never initiates one.** It runs no scheduled reclamation, applies
no retention window, and deletes nothing on its own judgement — the same rule as
everywhere else in this specification, and the reason deletion could be added here at
all without the server becoming an actor.

> Retention therefore stops being something an operator quietly configures and
> becomes something a Workspace decides and signs. A deployment that wants a
> permanent archive grants `hard_prune` to no role, and the archive is permanent by
> construction rather than by promise.

### Guidance — a prune discloses a grouping

*Non-normative. No rule here binds anyone; this is a design note for whoever
builds a client.*

A prune is readable by the server, by necessity. Its contents are content-free —
positions, author positions, hashes, all of which the server already holds. But
**the set itself carries information**: it says *these ops are reprised by that
one*.

If a client folds one record at a time, that set is an equivalence class:

```
   the server sees                    and can infer
   ──────────────                     ─────────────
   prune A reprises  2, 3, 5, 6     ops 2,3,5,6 concern one thing
   prune B reprises  4, 8, 9        ops 4,8,9 concern another thing
   prune C reprises  7, 10          ops 7,10 concern a third

                                      ⇒ this Workspace has ≥3 records
                                      ⇒ the first is the most edited
                                      ⇒ edits to it cluster on Tuesdays
```

Still no idea *what* any record is or *what* changed — but the shape of the data
leaks: roughly how many records exist, which are hottest, and when activity on
each one clusters. For most applications that is uninteresting. For some — a
medical journal, a legal matter file — "how many matters, and which one got busy
last week" is exactly what you did not want to publish.

**This is a consequence of how a client chooses to fold, not of the protocol.**
The core says nothing about what a reprise covers; the word *record* appears
nowhere in the wire format. So the choice is yours:

| Approach | Leaks | Costs |
|---|---|---|
| one reprise per record | the full partition, as above | nothing extra — simplest, and the honest default |
| batch several records per reprise | a coarser partition — unions, not classes | larger snapshots; reprises more at once |
| fold rarely, in big sweeps | fewer, coarser groupings | more history for a fresh device to replay before the sweep |
| decouple reprising from edit activity | breaks the timing correlation | reprising runs when it is not needed |

The obvious fix — encrypting the prune — is **not available**, and deliberately
so: the server must read a prune to act on it, which is why sealed prunes are
refused outright (`encrypted_prune_op`). Padding the target set with decoys does
not work either: every target is cross-checked against a stored op, so a decoy
must be a real op you are genuinely willing to reprise.

> The honest framing is that reprising trades metadata for storage. A client that
> never folds leaks no grouping at all and keeps every op for ever. Somewhere
> between those is the right answer for your application, and only you can pick it.

### Guidance — evolving the payload schema

*Non-normative. No rule here binds anyone; this is a design note for whoever
builds a client.*

Every application eventually changes the shape of what it writes. On a mutable
store that is a migration: rename the column, keep a down migration, and the old
name survives nowhere. **A log does not work that way.** Ops are immutable and
signed, so there is no in-place edit, and the naïve consequence is that every
future reader must understand every shape the application has ever written.

**Rewriting and re-signing the history is not an option** — not an expensive one,
an unavailable one. A member can only re-sign its **own** ops, so a rewrite needs
every device that ever wrote to still exist and cooperate. A device revoked two
years ago with its key wiped can never re-sign anything, and nobody can do it for
them. Any plan that begins "we re-emit the chain" ends there.

What works is four moves, in order of how much they buy.

**1. Keep names off the wire.** If the payload encoding keys fields by stable
numeric tag rather than by name, a rename is a source-code change with no log
consequence at all: the tag is unchanged, history is untouched, nothing needs to
know. Retire tags permanently, never reuse them. This costs nothing and removes
the majority of what would otherwise be migrations.

**2. Version every payload, and upcast at decode.** What is left after (1) is
genuine semantic change — a field splits, units change, two records merge — and no
encoding trick avoids that. Carry a schema version in the payload and hold a chain
of pure `v1→v2→v3` functions at the decode boundary.

```
   op(v1) ─┐
   op(v2) ─┼─► upcast chain ─► current shape ─► the rest of the application
   op(v3) ─┘        ▲
                    └── the only place that knows any version ever existed
```

> **The upcasters are where migrations went.** Old knowledge does stay in the
> codebase for ever, and that is the tax. It is a small one if version-awareness
> is confined to this boundary, and it turns into the fork you feared the moment
> it leaks into business logic instead.

**3. Fold forward to shorten the chain.** A reprise is written in whatever
encoding is current when it is written. Prune the ops it reprises, and because
the default read is `include_reprised=false`, **a fresh device never sees the old
encoding at all.**

```
   before   v1 v1 v1 v2 v2            a new device replays five shapes
   fold                    ●          ● restates them, in v3
   prune    ▓  ▓  ▓  ▓  ▓  ●          a new device replays one
```

Nothing is edited and no signature breaks — you appended an op and attested what
it replaces. Note what this *doesn't* require: prune targets may be **anyone's**
ops, so a single member holding the folding role does this for the whole
Workspace. No agreement among members, no re-signing, and no user prompt, because
nothing here is a decision a user could evaluate.

> The core has no opinion about *why* a fold was written. Reclaiming storage and
> re-encoding a record are the same operation to the server — many ops replaced by
> one. Which of them you meant belongs in the payload, where the server cannot see
> it and does not need to.

**4. Expand and contract across the change.** Write both shapes for a transition
window, read either, then stop writing the old one. Standard practice, and it is
the *new writes* that contract — historical ops are never touched.

#### What this leaves, honestly

The history view is served by `include_reprised=true` and returns the original
bytes for ever, so the upcast chain has to survive as long as a user may ask to see
their own history. Folding cleans the **sync path**, not the archive. That is a
real residual cost, but a bounded one: the upcasters leave the path every new
device walks and become archive-reading code.

#### And the rollback story inverts

Worth stating because the intuition points the wrong way. On a mutable store a
rename destroys the old name, and rolling back needs the down migration to
reconstruct it. Here nothing historical was ever modified, so **shipping the
previous version of the application reads every old op correctly, with no
migration and no work.**

The only exposure is ops written in the new shape during the window before the
rollback — a far smaller surface than a whole table, and one that fail-closed
decoding plus the transition window in (4) already covers.

### Stage 3 — what the server checks

**[S]** In order, all `422` with `index`:

1. framing: `invalid_body_length`, `payload_overruns_body`, `non_zero_padding`
2. shape: `malformed_prune_payload` and the three rules above
3. `prune_reprise_not_found` — the named reprise is neither earlier in this
   batch nor already stored **under this same author**
4. per target, in payload order:

| Refusal | Cause |
|---|---|
| `prune_target_not_found` | no such position |
| `prune_target_is_control` | control ops are the permission record |
| `prune_target_is_prune` | a prune is itself the evidence of removal |
| `prune_target_is_server_read` | any other class with bit 7 set |
| `prune_target_attestation_mismatch` | author, sequence or hash disagrees with what is stored |
| `prune_target_already_reprised` | already reprised |
| `prune_target_is_its_own_reprise` | an op cannot reprise itself |

**[S]** The general rule behind the first three: **no op whose class has bit 7 set
may be a target.** Everything the server reads is permissions or housekeeping, and
folding any of it away would destroy the evidence that makes removal auditable at
all. The two named codes cover the core-assigned cases; extension classes are
refused under the third.

**[S]** The named reprise, by contrast, may be **any opaque class** — `0x01`,
`0x02`, or a profile-defined one. The server cannot read the fold either way, so
constraining its class would prove nothing beyond what the author's own signature
already commits them to.

> A prune vouches for **its own** reprise — someone else's does not count.
>
> Checking attestations at the door is the entire argument for the server reading
> this payload: a forged one poisons chain verification for every device that
> enrols later, and such a device has nothing to check it against.

---

## 8. What the server does *not* check

**[S]** The server MUST NOT verify, and MUST NOT refuse an op for:

| Not checked | Why not |
|---|---|
| the envelope signature | it does not know which key to trust; the log does, and every reader checks |
| `prev_author_hash` | chain verification is reader state, built from the log that reader has seen |
| `observed_head` | reserved in v1 |
| the `nonce` on an unsealed op | a content-blind server has no basis to judge it |
| `author_key_id` against the registered key | a device may rotate its signing key; the log is the authority |
| padding on opaque bodies (bit 7 clear) | it never unpacks them |

**[S]** These fields are parsed for indexing and stored verbatim. **A replacement
MUST NOT turn any of them into a refusal.**

**[C]** Signature verification, chain verification and the `observed_head` rule
are the **reader's** obligations, and a client MUST perform all of them.

> This is the property most likely to be "fixed" into an interoperability failure.
> An implementer who adds signature verification will reject ops that every
> conforming server accepts — most visibly from a device that rotated its key —
> under a code no client recognises. **The server is a store, not a notary.**

---

## 9. Reading: `GET /v1/w/{workspace_id}/ops`

**Credential:** a device token, unrevoked. No permission grant needed —
see [Authority](03-authority.md) on the three bars.

```
  ?since=41              exclusive; default 0
  &limit=500             1 … the advertised maximum
  &include_reprised=    "true" or "false"; default false
```

```json
← {"ops": [{"seq": 42, "envelope": "<base64>"},
           {"seq": 43, "envelope": "<base64>"}],
   "has_more": true}
```

**[S]** Ascending by position. `has_more` is exact: true iff at least one further
op exists under the same filter.

**[S]** **`since` is purely the client's.** The server stores no cursor and
remembers nothing about who has read what.

```
   log:      1  2  3  4  5  6  7  8  9
                        ▲
   device X keeps its own cursor here, sends since=5, gets 6..9
   the server forgets the question immediately
```

**[S]** A `limit` outside range, or an `include_reprised` value that is not
exactly `true` or `false`, is `422 malformed_request` — **never clamped**.

> Clamping would let a device built against a larger deployment silently receive
> short pages and mistake them for the end of the log.

**[S]** **Reading a Workspace that does not exist yet returns an empty page, not
an error.**

> That asymmetry is deliberate: writing to a non-existent Workspace is
> `409 workspace_not_created`, but *reading* one is how a device discovers it needs
> to create it. The enrolment ceremony branches on exactly this observation, while
> holding a device token and no permissions at all.

**[S]** `include_reprised=true` drops the filter and serves the whole log,
reprised ops included — the **history view**. Same credential bar as any other
read, and no higher.

**[C]** The history view is **not a retention promise.** A `hard_prune` destroys
reprised bytes permanently, so an op this view returns today may be absent tomorrow —
with the `hard_prune` that removed it in the log, and its position tombstoned. A
client that needs history to survive MUST keep its own copy. Nothing on the server
undertakes to hold one.

> Worth stating flatly because the filter name suggests otherwise. `include_reprised`
> says *do not hide what is here*; it has never said *this is everything that was
> ever written*, and since `hard_prune` those two readings come apart.

> A prune hides history from the *sync* path so a fresh device need not replay it.
> The user is still owed that history on request. Widening what is served is not
> widening who may ask.

### The ordering guarantee that is easy to miss

**[S]** **A read MUST NOT return position S while any position below S is still
uncommitted.**

```
   two concurrent writes
   ─────────────────────
   request P is given position 100 ──────────┐  slow
   request Q is given position 101 ──┐       │
                                     ▼       │
                              101 commits    │
                                     │       │
        a read here returns 101 ─────┘       │
        the device advances its cursor to 101│
                                             ▼
                                      100 commits
                                             │
        …and is never served again ──────────┘   since is exclusive,
                                                 and no server cursor exists
```

> Without this rule the transport silently, permanently loses ops. Nothing detects
> it. An implementation must either allocate positions under the same serialisation
> as the commit, or withhold any position at or above the lowest in-flight one.

**[S]** A read MUST NOT observe a partially committed batch.

---

## 10. Being told there is news: `WS /v1/w/{workspace_id}/signal`

A subscription that carries **no data at all** — only the fact that something
happened.

```
   client                                    server
     │                                         │
     │──── connect ───────────────────────────►│   accepted before auth
     │                                         │
     │──── first frame: device token ─────────►│
     │                                         │
     │◄─── empty frame ────────────────────────│   auth ack AND "go sync"
     │                                         │
     │         (someone else appends)          │
     │◄─── empty frame ────────────────────────│   poke
     │                                         │
     │──── GET /ops?since=… ──────────────────►│   the actual data moves
     │                                         │   over HTTP, as always
     │            (nothing happens)            │
     │◄─── "ping" ─────────────────────────────│   keepalive, idle only
     │                                         │
```

**[S]** The server sends exactly two kinds of frame and nothing else:

| Frame | Meaning |
|---|---|
| **empty text frame** | *a poke* — sync from your cursor now |
| `ping` | keepalive, sent only while idle |

**[S]** **No frame ever carries a position, an author, a count or an envelope.**
The Workspace is in the URL.

> A poke reveals only that activity happened — strictly less than the read it
> provokes already reveals. The keepalive fires only in the *absence* of news, so
> it is the exact complement of a poke and adds nothing to the leak surface. It is
> application-level rather than a protocol ping because protocol pings are
> invisible to browser clients.

**[S]** The token arrives as the **first frame**, not a header.

> A browser cannot set `Authorization` on a WebSocket, and a query string would
> write the token into every proxy log along the path.

**[C]** A client MUST NOT treat a successful connection as authentication success.
Acceptance always precedes the check; the immediate empty frame is the
acknowledgement.

**[S]** Pokes **coalesce**: N appends before the subscriber wakes deliver one
poke, and the following read sweeps up everything. **The server keeps no
per-subscriber state** — no cursor, no memory of who saw what.

**[S]** Inbound frames after the handshake are ignored.

**[S]** A socket is authenticated **once**, at the handshake, and never
re-checked. Token expiry does **not** close it; **revocation does**.

> The asymmetry is deliberate. An expired token means the device should refresh
> before its next HTTP call — it does not mean this subscription became
> illegitimate. A revocation does mean exactly that.

**[S]** Close codes — a client's reconnect logic branches on these exact numbers,
so they are protocol:

| Code | Cause | What a client should do |
|---|---|---|
| `4400` | no token in time, or a binary first frame | protocol error — fix the client |
| `4401` | invalid token, or not a device token | park until the token refreshes |
| `4403` | Workspace unreachable, or device revoked | terminal — do not retry blindly |

**[S]** `4403` deliberately merges two causes the HTTP surface keeps apart. It is
the **one sanctioned exception** to "codes are never merged", because the socket
carries no body to disambiguate with and the client's response is identical
either way.

**[S]** A deployment running more than one process MUST put a shared broker behind
the fan-out, or subscribers silently miss pokes delivered to whichever process
owns the writer's connection.

---

## 11. Storage requirements this layer imposes

**[S]** Uniqueness of `(workspace, author, op_id)` and of `(workspace, author,
author_seq)` MUST be enforced by the storage layer, not by application code.

> The write path reads the author's current head and then inserts. Two concurrent
> batches can both read the same head and both believe they own the next slot — a
> write skew no amount of application logic closes. And a forked author chain is
> unrecoverable, because `prev_author_hash` would name two different successors.

**[S]** A batch's walk MUST see one consistent snapshot: what a later op is judged
against is what earlier ops in the same batch established, plus what was committed
when the batch began.

The complete list of what a server must remember is in [retained
state](reference/retained-state.md).

### Bounding what a Workspace consumes

A deployment has finite disk and the log only grows. The core says almost nothing
about how consumption is bounded, and exactly three things about what bounding it may
never do.

**[S]** A deployment MAY refuse a write because the Workspace has consumed its
allowance, under `402 workspace_quota_exhausted`. It carries **no**
`retry_after_seconds`, because waiting is not the remedy.

**[S]** The refusal says nothing else. No amount, no allowance, no plan, no price, no
URL — a deployment's commercial surface is not protocol, and a code that carried one
would be a code every client had to parse differently per server.

**[S]** It does **not** distinguish over-allowance from unpaid.

> Those differ only to the operator. To a client both mean *this Workspace will not
> accept more bytes right now*, both are handled by surfacing and not retrying, and
> collapsing them keeps a billing relationship out of a protocol refusal.

**[S]** Three things it may never gate, whatever the deployment's arrangement:

| Never refused for consumption | Because |
|---|---|
| `GET …/ops` — reading your own log | otherwise non-payment destroys availability, and the data was never really yours |
| every vault route → [Keys](04-keys.md) | it holds the identity's own recovery; gating it locks somebody out of their Root, unrecoverably |
| authentication — challenge, token, refresh | a member who cannot log in cannot read either, which is the first rule wearing a hat |

> This is the whole of the exit path, and it is the reason the list exists rather
> than being left to each operator's judgement. "The server is trusted with nothing"
> is false the moment it can be trusted with your continued payment. A deployment may
> stop accepting your writes; it may not hold your history hostage, and it may not
> stand between you and the key that would let you leave.

**[S]** And two op classes are never refused for consumption, even when every other
write is:

| Never refused | Because |
|---|---|
| `0x80` control | revoking a compromised device is a security remedy. Gating it on payment makes non-payment a way to keep an attacker's grant alive |
| `0x81` prune and `hard_prune` | it is the remedy *for this refusal*. Refusing it seals the Workspace under its own ceiling with no way back |

> The second was a deadlock walked straight into: a Workspace over its allowance
> refuses writes, the way back under the allowance is to write a `hard_prune`, and a
> `hard_prune` is a write. The exemption is what makes the ceiling recoverable rather
> than terminal, which was the entire argument for having one.

**[S]** The exemption is narrow enough not to be a hole. Both classes are small,
bounded, role-gated, and neither can carry application data.

*Non-normative:* because **the batch is all-or-nothing** (§6), the exemption only
helps a client that sends recovery ops in a batch of their own. A `hard_prune`
batched alongside a content op is refused with it. Nothing breaks — the refusal is
correct and says so — but the batch that would have freed space did not land.

### Whose bytes were they

**[S]** Where a deployment bounds what a single **member** may add rather than the
Workspace as a whole, the refusal is `402 member_quota_exhausted` — a distinct code,
because the remedy is a different one and belongs to a different person.

> Collapsing the two would tell two hundred people the Workspace is out of space when
> one runaway sync loop is the whole problem. A client can only say which happened if
> the codes differ, and "which happened" is the only part the user can act on.

**[S]** Attribution needs **no new state**. Every envelope names its author in the
header, and `holder_ref` groups a Workspace's devices by the identity holding them
([Authority](03-authority.md)), so per-device and per-person accounting both fall out
of what the server already keeps. Grouping by `holder_ref` equality is the one use of
that field the server may make — it still never interprets it, and it still authorises
nothing.

**[S]** There is **no account-level refusal**. A deployment whose allowance is pooled
across many Workspaces — one organisation paying for forty — refuses under
`workspace_quota_exhausted` in whichever Workspace the write landed.

> The Workspace is the only thing whose bytes this protocol counts. There is no
> account here, no payer and no billing relationship, so there is nothing else for a
> refusal to name.

**[C]** A client meeting either code MUST NOT re-attempt it **unchanged**. Neither is
deterministic — reducing what the Workspace holds changes the answer — so a client
SHOULD present folding and `hard_prune` as the recovery available to it (§7). The
reason that op exists is that the alternative was a Workspace with no way back under
a ceiling.

> Which makes these the awkward pair in the retry vocabulary, and worth naming.
> **Terminalise** is for a refusal a retry cannot change ([Compatibility](05-compatibility.md));
> `retry_after_seconds` is for one that clears on its own. A quota is neither: waiting
> never clears it and stopping for good is wrong, because the client can do something
> that makes the same request succeed. Act, then retry — the one shape neither of the
> other two describes.

**[S]** Quota state is **server-side and authoritative for nothing.** It is not in
the log, no op records it, no device derives anything from it, and a replay
reconstructs the Workspace without it — exactly like a rate-limit counter.

### Guidance — a shared Workspace is a shared fate

> **Non-normative.** The core bounds nothing and requires no deployment to.

A Workspace with two hundred members and no per-member bound is one where any member
can stop the other one hundred and ninety-nine, usually by accident — a sync loop, a
bulk import, a folder that never folds. The protocol makes that expressible and takes
no view on it.

Two things are worth deciding before it happens rather than after:

- **Someone present must be able to recover.** `hard_prune` is conferred only by a
  role entry that names it ([Authority](03-authority.md)). A deployment that bounds
  consumption and grants it to nobody has built a ceiling with the ladder locked in
  the operator's office.
- **The bound and the payer are different questions.** Who pays for a Workspace is
  out of band and invisible here; who may fill it is a role table. An organisation
  paying for forty Workspaces still bounds each one separately, because the Workspace
  is the only thing whose bytes this protocol can count.

---

## Next

[Identity](02-identity.md): who is allowed to send any of this.
