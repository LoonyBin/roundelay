# Reference — Profile obligations

**[P]** A profile MUST supply every row. **[S]** A core implementation MUST refuse
to start with any of them unset.

> There are no defaults, because every silent default here is either a security hole
> or a convergence bug. A guessed protocol namespace would let two unrelated
> deployments' signatures verify against each other; a guessed creation rule would
> let one identity mint Workspace ids that belong to another.

| # | Obligation | Constraint | Defined in |
|---|---|---|---|
| 1 | `PROTOCOL_NAMESPACE` | `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, 1–32 bytes, globally unique | [Keys](../04-keys.md) |
| 2 | Workspace **creation** policy | `derived` with frozen namespaces, `explicit`, or a profile-defined predicate; access is not a profile decision | [Authority](../03-authority.md) |
| 3 | Where admission is enforced | *that* founding registration is gated and by what layer — `open` is a legal answer; the **mechanism** is never declared | [Identity](../02-identity.md) |
| 4 | Initial role table | role tokens and their op classes; each token `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, 1–32 bytes; MUST contain exactly one `owner`; an entry for `0x81` MAY name payload types, and confers `prune` only when it does not; replaced in band from the first `role_table` op ([Authority](../03-authority.md#7-roles)) | [Authority](../03-authority.md) |
| 5 | Member-kind set | the legal `member_kind` tokens | [Authority](../03-authority.md) |
| 6 | Grant-admissibility rule | optional; absent means admit everything | [Authority](../03-authority.md) |
| 7 | Body size classes and oversize step | ascending positive integers | [The Log](../01-the-log.md) |
| 8 | Deploy label format | optional; opaque to clients either way | [Compatibility](../05-compatibility.md) |
| 9 | Opaque class set | the classes the profile assigns in `0x40–0x7F`; optional, absent means none | [The Log](../01-the-log.md) |
| 10 | Enabled extension classes | the set of classes in `0xC0–0xFF` the deployment permits — **may be empty**, but every member carries a mandatory NAME | [The Log](../01-the-log.md) |
| 11 | `holder_ref` derivation | how a registration's 32 opaque bytes are computed; the holder's Root public key is a legal answer, and so is anything the server cannot reverse | [Authority](../03-authority.md) |

**[P]** A profile SHOULD name itself `<namespace>/<revision>`, and **[S]** a server
MUST report that name as `profile` in `GET /health`.

**[S]** A server MUST likewise report **row 10** there, as `extension_classes` —
each enabled class number mapped to its NAME, `{}` when the row is empty
([Compatibility §7](../05-compatibility.md#7-discovery-the-health-endpoints)). Row 1
is reported as `protocol_namespace` ([Keys](../04-keys.md)), and row 8 governs the
format of the `version` field.

**[S]** Rows **9 and 10** surface once more, in `served_sets.op_classes` — every class
byte the server accepts, numbers only, with nothing to say which range a byte came from.
That is the whole of it: beyond its name, those four rows are what `GET /health` says
about a profile, and the rest is the profile document's to publish.

> The names live in `extension_classes` and nowhere else, which is the split that
> matters. An extension class needs a NAME because two implementations must agree what
> `0xC5` *means* before either writes one; an opaque class needs none, because the
> server treats it exactly as it treats `0x01` and only the application reads it. What
> both need is the number, so a client knows before batching whether the byte will be
> refused.

## What a profile is no longer asked

**[P]** A profile MUST NOT specify how a vault locator or wrapping secret is derived,
and a core implementation MUST NOT provide a place to declare it.

**[P]** A profile MUST NOT specify an admission *mechanism*, and the core defines no
field, header or format for one. Row 3 records where the gate lives, never how it
decides.

> Row 11 asks for a derivation and these two forbid one, which is not a contradiction:
> the test is whether two implementations have to agree. A vault secret is computed on
> one device and consumed by the same device, so nothing breaks if two clients differ.
> A `holder_ref` is written by one client and compared by another, so a deployment
> whose clients differ has silently stopped grouping anybody's devices.

> Not an omission — a boundary. The derivation happens on the device, the server
> cannot observe it, and anything a profile said about it would be a claim no
> implementation could check. Guidance for choosing one is in
> [Keys](../04-keys.md), where it is marked non-normative and stays that way.
>
> This is also why there is no escrow magic and no key-derivation floor here. Both
> existed to constrain a blob the core specified the inside of. It no longer does.

## Two rows that constrain more than they look

Neither is a new rule. Both are consequences a profile author is better off meeting
here than discovering in production.

### Row 2 — a deployment that provisions per Workspace cannot use `derived`

Under `derived`, a Root's Workspace ids are computable offline: anyone holding a
keypair founds theirs without asking anybody. Nothing external observes it, so a
deployment that provisions, quotas or bills per Workspace acquires Workspaces it never
issued and cannot attribute to an account.

`explicit` is the only policy with an issuing step — *any id the profile's own
creation authority assigns* ([Authority](../03-authority.md)) — and that authority is
where provisioning attaches. `creatable(root_pk, workspace_id)` is consulted at every
genesis and sees both halves, so the grouping is recorded once, before the Workspace
exists.

**[P]** Admission does **not** substitute for this. It is consulted once per
*identity*, at its founding device's registration, so an organisation founding forty
Workspaces is admitted once and thirty-nine are never seen by the gate.

### Row 11 — an unreversible `holder_ref` costs headcount

The row buys one thing: a `holder_ref` that groups a person's devices inside one
Workspace and nowhere else. That is also exactly what it costs. Nothing can then tell
that a holder in one Workspace is the same person as a holder in another, so anything
counted **per person across an account's Workspaces** — seats, per-user allowances,
"how many employees are actually using this" — stops being computable from the log.

> Worth weighing rather than discovering, because it is one fact seen from two sides.
> The property that stops an observer correlating a person across Workspaces is the
> property that stops the operator counting them, and no configuration separates the
> two.

## Changing a profile after deployment

**[P]** Changing rows **1, 4, 5 or 7** once a deployment has peers is a **protocol
fork**, not a configuration change.

One of them has a *retroactive* effect, and it is the one most likely to be changed
carelessly:

```
   row 7   body size classes
           │
           └─► every op already signed padded to the OLD ladder.
               Changing it makes them all illegal to every reader.
```

**[P]** Row 7 has **no additive direction**. *Adding* a class is retroactive too: a
new top class moves where the oversize step begins, so every op already padded above
the old ladder now sits at a length no reader will accept — the same damage, arriving
from the direction that looks safe.

> Said plainly because row 9 below does split on direction, and the habit
> transfers. It does not transfer here. Nothing about row 7 is a served set: the ladder
> is not a vocabulary a reader can refuse one member of, it is arithmetic every reader
> applies to every op ever written.

**[P]** Row 3 is the exception that looks like a fork and is not, in either
direction. **Widening** it breaks nothing, because admission is consulted once, when
an identity's founding device registers, and never recorded. **Narrowing** it strands nobody either: it refuses new
identities and leaves every existing one untouched.

> Row 3 is also the only row that declares a fact about the deployment rather than
> about the protocol. It exists so that "what stops anyone filling my disk" cannot be
> left unanswered by accident — not so that two implementations can agree, because on
> this question they never have to.

**[P]** Rows 4, 9 and 10 each carry a verdict finer than the row. What is a fork is
only ever what is **retroactive**, or what two peers judge differently:

| Change | Verdict |
|---|---|
| **any** change to the configured table (row 4), in either direction | a **fork** — the initial table is what a peer that has replayed no `role_table` judges against |
| adding or removing a class **in band**, by a `role_table` op | neither; the table lives in the log and is judged positionally, like a grant |
| adding an opaque class (row 9) | a served-set widening; nothing already written becomes illegal |
| **removing** an opaque class (row 9) | a **fork** — every op already written under it becomes illegal to every reader |
| enabling or disabling an extension (row 10) | neither; the binding lives in the log and is judged positionally, like a grant |

> The **in-band** path is what makes rows 9 and 10 usable at all. A class nobody may
> author is a class nobody can use, and admission lives in the role table — so if the
> only way to let a role write a new class were to edit the configured one, enabling an
> extension would cost a fork of the profile, and the mechanism would be dead on
> arrival. It costs one Root-signed `role_table` op instead: ordered against every
> other authority change, replayed by every device, and retroactive to nothing — which
> is the test the other rows already apply.
>
> Row 4's own split hardened in the process. The configured table is covered by no
> signature, so *adding* a class to it is not the safe direction it looks like: two
> peers configured differently disagree about which ops are legitimate, and neither has
> anything to compare against. Adding one in the log carries no such hazard, because
> every reader replays the same op.
>
> Which is also why the token pattern in row 4 is load-bearing rather than tidiness.
> A `role_table` certificate refuses any token outside it
> ([`malformed_role_table`](../03-authority.md#role_table)), so a profile that
> configured a token the pattern rejects would have configured a table no in-band op
> could ever express — and its first change would have to be a fork after all.

**[P]** Row 9's verdict is the **server's**, and the "nothing" is worth naming. The
server serves the byte the moment the profile declares it, and no op already in the log
becomes illegal. What does happen is that every reader built before the declaration
refuses the new class's ops `unsupported_op_class` — for as long as it goes un-updated,
which for a device in a drawer is for ever
([Compatibility §1](../05-compatibility.md#1-the-premise-skew-is-permanent)).

> That is a widening rather than a fork because of **who owns both halves**. An opaque
> class carries application content, read by the application's own clients; the
> deployment that declares the class is the deployment that ships the readers, and it
> is choosing its own rollout. Nobody else's data is invalidated and nobody else's
> reader is surprised. The trade is real and it is the application's to make — which is
> not the same as no trade, and reads that way if left as "breaks nothing".

**[P]** Changing **row 11** invalidates nothing already signed, and is still close to
irreversible. Registrations written under the old derivation carry values that no
longer equal the new ones, so a holder's older devices group apart from their newer
ones — for ever, in an append-only log. The repair is to re-register every device, and
there is no partial version of it.

> Which makes it the one row whose damage is silent on both sides. Nothing refuses,
> no signature fails, and the symptom is that "Alice's devices" quietly returns two
> answers depending on when you look.

> Row 10 is not a fork precisely because the profile is not the record. The profile
> says what this deployment *permits* and under what NAME; a `0xBF` `ext_binding`
> op says which **member** agreed to that name, and from which position. Turning a
> class off in configuration refuses new ops without rewriting the meaning of old
> ones — and a replay still reconstructs what was true when each op was written.

## The dependency runs one way

**[S]** The core never depends on a profile. Every rule in the five layers and in
this file is complete without opening a profile document, and removing one leaves the
specification consistent.

**[P]** A profile depends on the core freely. It exists to answer questions the core
refuses to answer, and cites them by section.

**[P]** Profiles ship **separately from this specification**, in their own
repositories. This one carries no profile but the sketch below, which is fictional.

> Which is why every illustration in the core names a fictional `acme` rather
> than a shipped profile. An example that has to exist is a dependency wearing a
> different hat, and the first sign of one is a core rule that stops making sense
> when a file is deleted.

## A minimal profile, in full

Every row answered, no optional row taken up — the smallest thing that starts:

| # | Obligation | `acme/p1` |
|---|---|---|
| 1 | namespace | `acme` |
| 2 | creation | `derived`, one frozen namespace — one Workspace per identity |
| 3 | admission | in the server, at the founding registration; an invite token |
| 4 | initial role table | `owner`, `participant` |
| 5 | member kinds | `{device}` |
| 6 | grant admissibility | absent — admit everything |
| 7 | size classes | `512, 4096`; oversize step `4096` |
| 8 | deploy label | `^\d+\.\d+\.\d+$` |
| 9 | opaque classes | none |
| 10 | extension classes | none |
| 11 | `holder_ref` | the holder's Root public key, verbatim |

> Three rows answered "none", which is an answer rather than an omission — a server
> started against this table serves `0x01`, `0x02`, `0x80`, `0x81` **and `0xBF`**,
> and refuses every other class byte.
>
> `0xBF` is on that list because it is core-assigned, and a core class is served
> whatever a profile says. An empty row 10 does not withdraw the class; it empties
> what a binding may **name**. So an `ext_binding` posted here is a well-formed op of
> a served class, and it is refused `ext_class_not_enabled` — carrying the `op_class`
> it asked for — never `unsupported_op_class`, which answers about the op's own class
> ([The Log §3](../01-the-log.md#3-the-class-byte)). The distinction is the whole
> reason the two codes exist, and this is the profile where it is easiest to
> collapse.
>
> Nothing here is borrowed from anywhere; the table is the whole profile.

