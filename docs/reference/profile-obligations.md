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
| 4 | Role table | role tokens and their op classes; MUST contain exactly one `owner`; an entry for `0x81` MAY name payload types, and confers `prune` only when it does not | [Authority](../03-authority.md) |
| 5 | Member-kind set | the legal `member_kind` tokens | [Authority](../03-authority.md) |
| 6 | Grant-admissibility rule | optional; absent means admit everything | [Authority](../03-authority.md) |
| 7 | Body size classes and oversize step | ascending positive integers | [The Log](../01-the-log.md) |
| 8 | Deploy label format | optional; opaque to clients either way | [Compatibility](../05-compatibility.md) |
| 9 | Opaque class set | the classes the profile assigns in `0x40–0x7F`; optional, absent means none | [The Log](../01-the-log.md) |
| 10 | Enabled extension classes | the set of classes in `0xC0–0xFF` the deployment permits — **may be empty**, but every member carries a mandatory NAME | [The Log](../01-the-log.md) |
| 11 | `holder_ref` derivation | how a registration's 32 opaque bytes are computed; the holder's Root public key is a legal answer, and so is anything the server cannot reverse | [Authority](../03-authority.md) |

**[P]** A profile SHOULD name itself `<namespace>/<revision>`, and **[S]** a server
MUST report that name as `profile` in `GET /health`.

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

**[P]** Row 3 is the exception that looks like a fork and is not, in either
direction. **Widening** it breaks nothing, because admission is consulted once, when
an identity's founding device registers, and never recorded. **Narrowing** it strands nobody either: it refuses new
identities and leaves every existing one untouched.

> Row 3 is also the only row that declares a fact about the deployment rather than
> about the protocol. It exists so that "what stops anyone filling my disk" cannot be
> left unanswered by accident — not so that two implementations can agree, because on
> this question they never have to.

**[P]** Rows 4, 9 and 10 split on direction. Only the retroactive direction is a
fork:

| Change | Verdict |
|---|---|
| **adding** a class to a role (row 4) | a widening — nothing already written becomes illegal |
| **removing** a class from a role (row 4) | a **fork** — retroactive |
| adding an opaque class (row 9) | a served-set widening; breaks nothing |
| **removing** an opaque class (row 9) | a **fork** — every op already written under it becomes illegal to every reader |
| enabling or disabling an extension (row 10) | neither; the binding lives in the log and is judged positionally, like a grant |

> Row 4's split is what makes rows 9 and 10 usable at all. A class nobody may
> author is a class nobody can use, and admission lives in the role table — so if
> *every* change to row 4 were a fork, enabling an extension would require forking
> the profile to let anyone write it, and the mechanism would be dead on arrival.
> Adding a class invalidates nothing already written, which is the test the other
> rows already apply.

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
| 4 | role table | `owner`, `participant` |
| 5 | member kinds | `{device}` |
| 6 | grant admissibility | absent — admit everything |
| 7 | size classes | `512, 4096`; oversize step `4096` |
| 8 | deploy label | `^\d+\.\d+\.\d+$` |
| 9 | opaque classes | none |
| 10 | extension classes | none |
| 11 | `holder_ref` | the holder's Root public key, verbatim |

> Three rows answered "none", which is an answer rather than an omission — a server
> started against this table serves `0x01`, `0x02`, `0x80` and `0x81`, and refuses
> every other class byte. Nothing here is borrowed from anywhere; the table is the
> whole profile.

