# Compatibility

*How all of the above is allowed to change.*

The four layers before this one describe a system at one moment. This one is
about time: what happens
when a device that has been in a drawer for two years wakes up and talks to a
server that has moved on four times.

---

## 1. The premise: skew is permanent

Not a deploy window. Not a migration period. **Permanent.**

```
   server                    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  always current
                             ▲       ▲       ▲       ▲
   device A  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┘       │       │       │        updated last week
   device B  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┘       │       │        updated last year
   device C  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┘       │        in a drawer
   device D  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┘        never updating again
```

**[S]** Skew is handled **in code**, never by controlling deploy order.

> No sequencing rule, staging window, or minimum-version gate reaches device D.
> Any design that depends on "we will roll out the client first" has already failed
> for someone.

Two consequences run through everything below:

**Nothing is ever silently dropped.** A reader that meets something it does not
understand refuses under a **named code** and keeps the bytes. It never accepts and
discards.

> The failure this prevents is worse than an error: a server older than its client
> accepting a write, throwing away the field it did not recognise, and answering
> `200`. A `200` that lost a column is silent and unrecoverable.

**Retirement is additive-first.** A new shape ships, old readers keep using the old
one, and support for the old shape is **indefinite by default**. Removing one is an
explicit decision to break the devices that still speak it — never a milestone
reached automatically, because the fleet never stops producing an old shape on its
own.

### The one exception that was taken

This specification's `v1` was **rewritten in place, once**, before any deployment
existed — when the identity provider was removed and a Root keypair became the
identity. Routes and a whole credential kind disappeared without a deprecation
period. There were no peers, so no device was broken.

**[S]** That is the complete list of exceptions. From that point the rule above
applies without one, and a second in-place rewrite of a served version is a fork,
not a decision available to a maintainer.

> Recorded because an undocumented exception is indistinguishable from a precedent.
> Someone will find that `v1` once changed shape and reason that it may again — and
> they will find it under deadline, which is exactly when this rule is worth the most
> and defended the least. The circumstance that made it safe was that the set of
> devices speaking the old shape was **empty**, and that circumstance is not
> recoverable.

---

## 2. Two layers of versioning, and why they differ

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 1 — the server surface                                    │
  │  routes, request bodies, query parameters, responses             │
  │                                                                  │
  │  VERSIONED ON THE PATH:   /v1/w/{w}/ops                          │
  │  translated ONCE, server-side, when /v2 ships                    │
  └──────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 2 — what is inside an envelope                            │
  │  payload representation, certificates, wraps                     │
  │                                                                  │
  │  VERSIONED IN BAND:   new signing domain / suite byte /          │
  │                       op class / control type                    │
  │  the server CANNOT translate this, ever                          │
  └──────────────────────────────────────────────────────────────────┘
```

The split is forced, not chosen.

A URL prefix versions the *framing* of `GET /v1/w/{w}/ops` — the JSON around the
envelopes. It cannot version what is **inside** an envelope, for two independent
reasons: the server is forbidden to read it ([The Log](01-the-log.md)), and it
could not rewrite it even if allowed, because the envelope is covered by a
signature it cannot forge.

> The cost is real: an in-band change means a new signing domain, freshly frozen
> test vectors on every implementation, and served-set edits in every codec.
> Deliberately more friction than a URL bump. It is accepted because the cheap
> alternative is a server that reads content, which is the one thing this whole
> design exists to avoid.

---

## 3. Path versioning

**[S]** Every functional route lives under a contract-version segment. This
specification defines **`v1`**, so they live at `/v1/…`.

**[S]** `GET /health` and `GET /health/db` are **outside** the prefix.

> A client must be able to ask what the server supports *before* it knows what the
> server supports. Putting discovery behind the thing being discovered is a
> bootstrap failure.

**[S]** When `/v2` ships, `/v1` keeps working and the server translates internally
— **mapped once, server-side**, not per client.

**[S]** A request whose first path segment matches `^v[0-9]+$` but is not served:

```json
404
{"detail": {"code": "unsupported_contract_version",
            "requested": "v2", "served": ["v1"]}}
```

**[S]** `served` is ascending.

**[S]** A first segment that is *not* version-shaped — `api`, `V2`, `v01`, `v1x` —
is an ordinary unrouted path: `404 not_found`. A served version with an unknown
suffix, like `/v1/nope`, is likewise `404 not_found`.

```
   /v1/w/…/ops     ✓  served
   /v2/w/…/ops     ✗  404 unsupported_contract_version   "I'm newer than you"
   /v1/nope        ✗  404 not_found                       "no such route"
   /api/w/…/ops    ✗  404 not_found                       "that's not a version"
```

> A bare `404` for an unserved version is indistinguishable from a mistyped URL. A
> client must be able to tell **"this server is older than me"** — recoverable,
> surface it to someone — from **"I built the wrong URL"**, which is a bug in the
> client.

---

## 4. Unknown fields are refused

**[S]** On the versioned surface, an unrecognised field in a request body — **at
any nesting depth** — is refused:

```json
422
{"detail": {"code": "unknown_request_field",
            "fields": ["epoch_note", "wraps.0.rotation_hint"]}}
```

**[S]** Paths are dot-separated, with bare decimal indices for array positions,
rooted at the request body. **Every** offending path is reported in one response,
sorted lexicographically, so a client learns all its problems in one round trip.

**[S]** An unrecognised **query parameter** is refused under the same code, with the
parameter name as a single-segment path.

**[S]** A duplicate JSON object key is refused `422 malformed_request` — never
resolved last-wins.

### Where the check sits

**[S]** After credential resolution. Before authorisation.

```
   request
      │
      ▼
   resolve credential ──────► 401 if bad
      │
      ▼
   unknown-field check ─────► 422 if unknown fields          ◄── HERE
      │
      ▼
   reachability, permissions ► 403 if not allowed
      │
      ▼
   do the thing
```

> Ordering matters in **both** directions. Before authentication, the check is a
> free oracle that lets anyone enumerate a route's accepted fields. After
> authorisation, a caller with both a malformed request and no access is told only
> that they lack access — and fixes the wrong thing.

**[S]** This applies to request bodies and query parameters. It does **not** apply
to op envelopes, whose bodies are opaque and whose extensibility is the in-band
mechanism.

**[W]** Inside a control payload, a prune payload, an `ext_binding` payload or a
certificate, an unrecognised key is likewise refused — `malformed_control_payload`,
`malformed_prune_payload` or `malformed_ext_binding_payload`.

---

## 5. In-band versioning: the served sets

**[W]** Three sets define what an implementation understands. Anything outside
fails closed.

| Set | v1 |
|---|---|
| suites | `0x00` plaintext, `0x01` encrypted |
| op classes | `0x01` content, `0x04` reprise, `0x80` control, `0x81` prune, `0xBF` ext_binding |
| control types | `workspace_genesis`, `member_register`, `grant`, `revoke`, `delegate`, `revoke_delegation`, `root_handover`, `rotate` |
| ext_binding types | `bind`, `unbind` |

**[W]** Op class **`0x03` is reserved** — claimed for a future core assignment,
and refused until something claims it properly.

**[W]** Two ranges of the class byte are **not** core-assigned and so are not part
of this table — see [The Log](01-the-log.md#3-the-class-byte):

| Range | Owner | Advertised |
|---|---|---|
| `0x40–0x7F` opaque | the profile declares them | with the profile |
| `0xC0–0xFF` server-read | the implementation defines them, the profile enables them | ✓ in the served sets |

**[S]** An implementation that defines none of the second range MUST behave as
though it were unassigned. Neither range weakens the served-set rule: an undeclared
or unenabled value is refused `unsupported_op_class` exactly like an unknown one.

**These sets *are* the versioning mechanism.** Widening one is how a new
representation ships:

```
   want a new payload shape?
        │
        ├─► new signing domain          "<ns>/grant/v2"
        │   old certificates still verify under v1;
        │   a downgrade attempt is a SIGNATURE FAILURE,
        │   not a parsing ambiguity
        │
        ├─► new suite byte              a new sealing construction
        │
        ├─► new op class                a new kind of record
        │   0x00–0x3F opaque, 0x80–0xBF server-read
        │
        └─► new control type            a new kind of permission change

   in every case: old readers refuse it under a named code and keep the bytes
```

**[S]** A new **server-read** behaviour ships as a core widening in `0x80–0xBF`,
never as a profile decision. A core implementation must be able to run any
profile, and it cannot do that if profiles dictate what it parses.

> The `0xC0–0xFF` extension range is the pressure valve on that rule, and it has
> the exit most private-use ranges lack. The usual failure is that a good
> extension gets adopted, cannot be promoted because its encoding is baked into
> deployed data, and lives for ever as a second-class citizen. Here the class byte
> is inside the signed envelope, so old ops genuinely cannot be relabelled — but
> reprise and prune already replace old encodings with new ones. Promoting
> `0xC5` to `0x82` is a fold-and-reprise, not a migration script.

**[W]** **The domain string is the version.** No signed document carries a version
field — see [Keys](04-keys.md).

> That is why a downgrade attack fails cleanly. If a version lived *inside* the
> signed document, an attacker could try to make a v2 document parse as v1. With the
> version in the signing domain, the signature simply does not verify.

---

## 6. Refusal codes are protocol

**[S]** A code is shared vocabulary, pinned in the [code
list](reference/refusal-codes.md). A server MUST NOT narrow one locally, MUST NOT
merge two into one, and MUST NOT invent an unlisted code for a listed cause.

**[S]** The **one sanctioned exception** is signal close code `4403`, which merges
two causes the HTTP surface keeps apart — because a WebSocket close carries no body
to disambiguate with, and the client's response is identical either way.

**[C]** A client MUST surface a code it does not recognise **verbatim** — in its
error record, its alarm, its log line — and MUST NOT fold it into another code's
meaning.

> Folding is how a *new* server refusal becomes indistinguishable from any other
> error of the same status. The client then treats a permanent, named, actionable
> condition as a generic transport blip, and retries it for ever.

### Deterministic versus transient

**[S]** A refusal that a retry cannot change MUST be **stable**. The [code
list](reference/refusal-codes.md) marks every code.

**[C]** A client MUST **terminalise** a deterministic refusal — record it, raise it
to someone, stop — rather than re-attempting on every sync for ever.

**[C]** A client MUST NOT have a **retry-by-default** fallback for codes it does not
recognise.

```
   WRONG                                RIGHT
   ─────                                ─────
   switch (code) {                      switch (code) {
     case A: retry                        case A: retry        ← positive
     case B: give up                      case B: retry        ← positive
     default: retry     ◄── the bug       case C: give up
   }                                      default: bounded budget, then alarm
                                        }
```

> Transient conditions are matched **positively**. Anything unmatched gets a
> bounded budget, never an unbounded one. Otherwise a future server code silently
> rejoins the retry-forever path, which is precisely the defect this rule exists to
> prevent.

---

## 7. Discovery: the health endpoints

**[S]** Unversioned, unauthenticated, and the entry point for everything above.

### `GET /health`

```json
{"status": "ok",
 "version": "…",
 "contract_versions": ["v1"],
 "protocol_namespace": "acme",
 "profile": "acme/p1",
 "limits": {"max_ops_per_batch": 1000,
            "max_page_size": 1000,
            "default_page_size": 500,
            "signal_keepalive_seconds": 25}}
```

| Field | What a client does with it |
|---|---|
| `version` | **opaque deploy label.** Nothing parses it semantically. |
| `contract_versions` | pick a path prefix, or refuse and say why |
| `protocol_namespace` | confirm it is talking to the right protocol at all |
| `profile` | confirm it is talking to the right *deployment* |
| `limits` | size batches and pages; set the socket idle deadline |

**[S]** MUST remain reachable while the backing store is unavailable — that is its
purpose.

**[S]** `limits` MUST carry those four keys and MAY carry more.

> `contract_versions` exists because otherwise a client discovers an unsupported
> contract only by getting a `404` on a real request. `protocol_namespace` exists
> for the same reason with more force: without it, a namespace mismatch surfaces as
> a wall of `bad_root_signature` — a code that is supposed to mean *forged*, not
> *you are pointed at the wrong deployment.*

### `GET /health/db`

```json
{"status": "ok"}
```

**[S]** Confirms the backing store answers a trivial query.

**[S]** When it does not: `503 store_unavailable`.

> This is the **one** route whose failure is a state rather than a bug, which is
> what lets every other layer say "a `500` is a bug" without qualification.

### What is discoverable, and what is not

```
   DISCOVERABLE at runtime          FROZEN by the profile — never negotiated
   ──────────────────────          ────────────────────────────────────────
   contract versions               protocol namespace  (advertised, not agreed)
   batch and page ceilings         Workspace topology
   keepalive interval              role table
   deploy label                    member kinds
   profile name                    body size classes

   NEITHER — the client's own business, invisible to the server
   ───────────────────────────────────────────────────────────
   how a vault locator and wrapping secret are derived  → [Keys](04-keys.md)
```

**[S]** That third column is not an omission. The server cannot observe a client's
derivation, cannot validate it, and MUST NOT offer any field through which a client
could describe it.

> A self-reported property the server cannot verify and must not branch on is worse
> than no property at all: it invites exactly one bug, which is a server that starts
> trusting it.

**[P]** Everything in the right-hand column is part of protocol identity. Changing
one after a deployment has peers is a **fork**, not a configuration change — see
[profile obligations](reference/profile-obligations.md).

> One of them has a *retroactive* effect and deserves particular care: changing the
> body size classes invalidates every op already signed, because each of them padded
> to the old ladder.

---

## 8. Version-related constants

**[S]** The deployment-tunable settings, and the defaults a profile inherits unless
it says otherwise:

| Setting | Default | Advertised |
|---|---|---|
| ops per batch | 1000 | ✓ |
| page maximum | 1000 | ✓ |
| page default | 500 | ✓ |
| signal keepalive | 25 s | ✓ |
| signal auth deadline | 10 s | |
| device challenge lifetime | 120 s | |
| device challenges per window | 120 | |
| challenge window | 86 400 s | |
| vault fetches per window | 20 | |
| vault fetch window | 86 400 s | |
| access-token lifetime | 15 min | |
| refresh-token lifetime | 365 days | |

**[S]** The keepalive MUST be advertised, because a client's idle deadline derives
from it.

**[S]** The keepalive MUST sit **below** the idle-read timeout of every intermediary
in the deployment's path, or a live subscription is reaped as idle.

By contrast, these are **frozen by the wire format** and identical in every
deployment:

| | |
|---|---|
| header 158 B · signature 64 B · overhead 222 B | authentication tag 16 B |
| key id 8 B · content key 32 B · challenge nonce 32 B | member wrap 104 B · escrow wrap 72 B |
| digest 32 B · Root key 32 B · Root signature 64 B | prune targets ≤ 1000 |

> The prune-target cap is wire-frozen while the batch cap is not, and the
> distinction is worth understanding. The batch cap is server resource policy that a
> client discovers and adapts to. The prune cap is a **shape rule other clients
> enforce** on an op this server already accepted — so a server that raised it would
> mint ops its peers refuse.

---

## Next

You have read all five layers. What remains is reference material:

- [Refusal codes](reference/refusal-codes.md) — all 110
- [Glossary](reference/glossary.md)
- [Retained state](reference/retained-state.md)
- [Profile obligations](reference/profile-obligations.md)
- [Conformance](../conformance/checklist.yaml)
