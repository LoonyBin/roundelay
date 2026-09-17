# Roundelay — the specification

Read this page first. It tells the whole story in about ten minutes, and every
other document is one layer of it in full.

---

## 1. The one-paragraph version

Devices write to their own local store and keep working offline. Every change is
described as an **op** — a small, signed, usually encrypted record — and appended
to a shared **log**. Other devices pull the log and replay it. The server in the
middle stores the log and hands it back in order. It cannot read what most ops
say, does not know what the application is about, and is trusted with nothing
except *keeping and ordering bytes*.

---

## 2. The picture

```
    Device A                  Device B                  Device C
 ┌────────────┐            ┌────────────┐            ┌────────────┐
 │ signs ops  │            │ signs ops  │            │ signs ops  │
 │ seals ops  │            │ seals ops  │            │ seals ops  │
 │ holds keys │            │ holds keys │            │ holds keys │
 └─────┬──────┘            └─────┬──────┘            └─────┬──────┘
       │  append                 │  pull                   │  pull
       │  ▲ poke                 │  ▲ poke                 │  ▲ poke
       ▼  │                      ▼  │                      ▼  │
 ╔═════════════════════════════════════════════════════════════════╗
 ║                      ROUNDELAY SERVER                           ║
 ║                                                                 ║
 ║   Workspace log        1 ──2 ──3 ──4 ──5 ──6 ──7 ── …           ║
 ║                        append-only, ordered, never edited       ║
 ║                                                                 ║
 ║   It holds:   ciphertext it has no key for                      ║
 ║               signatures it does not verify                     ║
 ║               an index it rebuilt from the few ops it may read  ║
 ╚═════════════════════════════════════════════════════════════════╝
```

Three things follow from that picture, and they explain most of the design:

**The server is a store, not a notary.** It does not check envelope signatures.
Verification belongs to the device that pulls, because only that device knows
which keys it has decided to trust. A server that "helpfully" verified would
reject ops every other server accepts.

**The server cannot read content.** Bodies are encrypted to a key it never
receives. The classes it must *act* on are the exception, and one bit of the class
byte says which those are — they are plaintext for ever, by rule.

**The server is authoritative for nobody.** It keeps an index of who may write
what, so it can refuse writes cheaply. But the signed log is the truth, and every
device works out for itself who may write what by replaying that log.

---

## 3. The five layers

Read them in this order. Each one only depends on the ones above it.

```
┌───────────────────────────────────────────────────────────────────┐
│  THE LOG             what is stored, and how it is shaped         │
│                      ops · envelopes · Workspaces · append · pull │
├───────────────────────────────────────────────────────────────────┤
│  IDENTITY            which key is speaking                        │
│                      Root · devices · certificates · tokens       │
├───────────────────────────────────────────────────────────────────┤
│  AUTHORITY           what they are allowed to write               │
│                      Root · genesis · grants · roles              │
├───────────────────────────────────────────────────────────────────┤
│  KEYS                how it stays private, and who holds what     │
│                      signatures · suites · epochs · wraps · vault │
├───────────────────────────────────────────────────────────────────┤
│  COMPATIBILITY       how all of the above is allowed to change    │
│                      versions · skew · discovery                  │
└───────────────────────────────────────────────────────────────────┘
```

| Document | Answers |
|---|---|
| [The Log](01-the-log.md) | What is an op? What is a Workspace? How do I write and read? |
| [Identity](02-identity.md) | What is the identity? Who is a device? How does each prove it? |
| [Authority](03-authority.md) | Who decides what a device may write, and how is that decision recorded? |
| [Keys](04-keys.md) | What is signed, what is encrypted, and which party holds which key? |
| [Compatibility](05-compatibility.md) | What happens when a device is two years older than the server? |

Reference material, extracted so the narrative does not carry it:

- [Refusal codes](reference/refusal-codes.md) — all 125, with status, cause and whether a retry can help
- [Glossary](reference/glossary.md) — every term, defined once
- [Retained state](reference/retained-state.md) — what a server must remember
- [Profile obligations](reference/profile-obligations.md) — the eleven decisions a deployment must make
- [Conformance](../conformance/checklist.yaml) — 250 machine-readable items

---

## 4. Core plus profile

The specification is deliberately incomplete. A running server is **core plus
exactly one profile**.

```
   ┌─────────────────────────────┐
   │        THE CORE             │   the transport, the trust model,
   │  (the five layers)          │   the refusal vocabulary
   └──────────────┬──────────────┘
                  │  eleven questions it refuses to answer
                  ▼
   ┌─────────────────────────────┐
   │        A PROFILE            │   namespace · Workspace topology
   │  e.g. acme/p1               │   admission · roles
   └─────────────────────────────┘   member kinds · size classes …
```

There are **no defaults**. A server refuses to start with any profile decision
unset, because a silent default there is either a security hole or a convergence
bug — a wrong guess about the protocol namespace, for instance, would let two
unrelated deployments' signatures verify against each other.

Two servers on different profiles are different protocols that happen to share a
shape. By design, they cannot verify each other's signatures at all.

A profile is filled in row by row under [profile
obligations](reference/profile-obligations.md). Profiles ship in their own
repositories; this one defines the core and nothing else.

---

## 5. How to read the rules

Prose in these documents comes in two kinds, and telling them apart matters.

**Normative rules** are tagged with who they bind:

| Tag | Binds | Example |
|---|---|---|
| **[S]** | the server | *[S] The server MUST NOT verify envelope signatures.* |
| **[C]** | a client | *[C] A client MUST verify every envelope it pulls.* |
| **[W]** | the wire format, so both | *[W] Hex values are lowercase.* |
| **[P]** | the profile | *[P] The profile MUST declare an initial role table.* |

MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

**Everything else is rationale** — the reasoning behind a rule, set off in prose
or in a quote block:

> Like this. It carries no requirement of its own.

The rationale is not decoration. Several rules look arbitrary until you read why,
and a maintainer who simplifies one without the reasoning in front of them will
reintroduce exactly the defect it was written to prevent. A rule that appears
*only* in rationale is a bug in these documents.

---

## 6. Conventions used everywhere

These apply in all five layers, so they are stated once here.

### Paths and versions

Every functional route lives under a contract-version segment: `/v1/…`. Only
`GET /health` and `GET /health/db` sit outside it, because a client must be able
to ask what the server supports before it knows what the server supports.
A route is never added to a version already being served — a new route ships under a
new version — so whether a server has a route is always answered by
`contract_versions`, never by a `404` a client has to interpret.
[Compatibility](05-compatibility.md) explains the scheme.

### Errors

**[S]** Every refusal, on every route, has the same shape:

```json
{"detail": {"code": "author_member_mismatch", "index": 3}}
```

`code` is a stable machine-readable name from the [code
list](reference/refusal-codes.md). Extra fields are per-code. There is no second
error shape — a client that branches on `detail.code` never meets a bare string.

**[C]** A client **ignores** any member of a response it does not recognise, in a
refusal detail as anywhere else, and never refuses the response for carrying it
([Compatibility §4](05-compatibility.md#4-unknown-fields-are-refused)).

| Status | Means |
|---|---|
| `200` | Success — or an idempotent repeat of something already done |
| `201` | Something was created |
| `401` | The credential is missing, expired, or of the wrong kind |
| `402` | The Workspace has consumed its allowance; waiting will not help |
| `403` | The credential is fine; it does not permit this |
| `404` | No such thing, or no such contract version |
| `409` | A state conflict — re-read and decide again |
| `413` | Too big |
| `422` | Well-formed JSON, invalid contents |
| `429` | Rate limited; `retry_after_seconds` says how long |
| `503` | The backing store is unavailable — any route may answer it; `GET /health/db` is where you ask |

**[S]** `401` responses carry `WWW-Authenticate: Bearer`.

### Values on the wire

**[W]** Binary values in JSON are **standard base64, padded**, validated
strictly. A stray character or missing padding is a refusal, never something to
repair.

**[W]** Hex values are **lowercase**, exact length. UUIDs in signed documents are
**canonical lowercase 8-4-4-4-12** — no braces, no `urn:uuid:` prefix, no
uppercase, no missing dashes.

> Refusing rather than normalising is not fussiness. Two implementations that
> normalise differently disagree about which payloads are legal; one then applies
> an op the other quarantines. That is a convergence bug, and it surfaces as data
> loss on one device, days later.

**[W]** Where a field is an integer it is a JSON integer — never a float, never a
boolean, never a string. Ranges:

| Field | Range |
|---|---|
| `epoch`, `from_epoch`, `to_epoch`, `key_epoch`, `after_epoch` | 0 … 2³²−1 |
| `since` → [The Log](01-the-log.md) | 0 … 2⁶³−1 |
| prune `seq`, prune `author_seq` → [The Log](01-the-log.md) | 1 … 2⁶³−1 |
| vault `version` → [Keys](04-keys.md) | 1 … 2⁶³−1 |
| `limit` | 1 … the server's advertised maximum |
| HLC `wall_ms` | −2⁶³ … 2⁶³−1 |
| HLC `counter` | 0 … 2⁶³−1 |

**[W]** Shaped strings:

| Field | Pattern |
|---|---|
| hex-64 (`prev_control_hash`, `expected_prev_control_hash`, `envelope_hash`) | `^[0-9a-f]{64}$` |
| HLC member id | `^[0-9a-f]{32}$` |
| canonical UUID | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` |
| `member_kind`, role token | `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, 1–32 bytes |
| authority (`granter`, `revoker`) | `root`, or a canonical UUID |

**[S]** Timestamps the server originates are RFC 3339, `Z` offset, millisecond
precision. Timestamps it merely echoes are opaque and returned byte-identically.

### Transport

**[S]** HTTP/1.1 or later, JSON bodies, TLS in production — the protocol carries
bearer tokens and assumes a confidential channel without providing one.

**[S]** A deployment serving browsers SHOULD enable CORS with an origin
allow-list. Tokens ride `Authorization`, never cookies, so a deployment with no
browser client MAY omit CORS entirely.

> A wildcard origin and `allow-credentials` are mutually exclusive in every
> browser. A deployment that sets both has switched its own CORS off.

**[S]** A deployment SHOULD bound total request body size and MUST document the bound.
A body over it is refused `413 request_too_large`, on any route. The batch ceiling
limits the *count* of ops, not their size, and answers `batch_too_large` instead.

> The bound is the deployment's to choose; the code is not. The vocabulary is closed,
> so the one limit every route shares needs a name in it — otherwise each deployment
> invents its own, and a client cannot tell "too big" from "malformed" anywhere.

### Clocks

**[S]** The server needs a wall clock for token expiry, nonce lifetimes and rate
windows. Skew between processes must be small relative to the shortest of those.

**[S]** The server MUST NOT use its own clock to order, judge or reject ops.
Ordering lives inside the payload, which the server never reads.

---

## 7. The invariants

If you remember nothing else, remember these. Every rule in every layer serves
one of them.

**The log is append-only and never edited.** No op is ever rewritten, no signature
breaks, no position moves. Reprising an op hides it from ordinary reads; a
`hard_prune` op can later destroy those hidden bytes, and only those — the server
never deletes on its own initiative, only what a signed op in the log instructed.

**The server never reads content.** It reads envelope headers, and the bodies of the
classes it must act on — the few with bit 7 set: control, prune, `ext_binding`, and
any extension class the profile enables. Nothing else, ever.

**The server verifies less than it stores.** No envelope signature check, no
chain check. Those belong to whoever pulls.

**The server's index is authoritative for nobody.** Tampering with server-side
state cannot elevate anyone's authority, because devices derive authority from
the signed log themselves.

**Everything fails closed.** An unknown suite, op class, control type, role,
member kind, or request field is a refusal — never a shrug. A field that is
permitted-and-ignored is one a future reader might start honouring, and two
implementations disagreeing about whether it counts is a convergence bug. The one
reservation is the `note_*` control types, advisory for ever and chained past rather
than interpreted by a reader ([Authority](03-authority.md)) — a place kept in v1, with
no member in it.

> The direction is part of the rule. Those are all things a **caller sends**, and the
> failure is a party acting on less than it was given. A field the **server** adds to a
> response is ignored rather than refused ([Compatibility
> §4](05-compatibility.md#4-unknown-fields-are-refused)) — nobody was asked to act on
> it, and refusing the answer for saying more than expected freezes every response
> shape at its earliest reader.

**Refusal codes are protocol.** They may not be narrowed, merged, or invented
locally. A client that meets an unfamiliar code surfaces it verbatim.

**Races never surface as internal errors.** Every concurrency hazard has a named,
documented verdict. A `500` is a bug, not a state.

### And one thing that is not an invariant

**Metadata is not protected.** The server sees when every op arrived, which device
wrote it, which identity holds that device, who holds which permission and when it
changed. Across an organisation those fields compose into an org chart with a clock
attached, and holding every key yourself does not change it: the server cannot order
ops it cannot see arrive. [Keys](04-keys.md) sets out the whole list, what it adds up
to, and the little that can be reduced.

---

## 8. What this server does not do

**[S]** Out of scope, permanently. A deployment that adds any of these has
changed the system into something else:

- interpreting, validating or indexing application content
- merging or ordering entity state — that is entirely the client's
- remembering what any device has read
- deleting anything a signed `hard_prune` op did not name
- retention policy, scheduled reclamation, or any deletion it decided on its own
- holding any key that opens any envelope, wrap or vault record
- notifications, scheduled work, or any background process at all
- an operator surface — the routes here are the members' own plane: a device token,
  or a certificate, signature or locator the caller carries, or nothing at all where
  nothing is disclosed. None of them is an operator's, so provisioning, billing and
  support tooling read the deployment's own storage rather than an API this
  specification defines
