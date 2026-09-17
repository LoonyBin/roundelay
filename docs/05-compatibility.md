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

### `v1` is unfrozen until it is deployed

**[S]** Everything above binds a version **that some device speaks**. Until the first
deployment exists, `v1` may be **rewritten in place**, without deprecation and without
a compatibility shim, because the set of devices speaking the old shape is empty and
breaking none of them is not a compromise.

**[S]** That licence ends at the first deployment, permanently and for every later
version. From that moment an in-place rewrite of a served version is a **fork**, not a
decision available to a maintainer.

Taken so far, while the set was empty:

```
   the identity provider removed, a Root keypair became the identity
        routes and a whole credential kind deleted outright
   holder_root_pk became holder_ref, 32 opaque bytes
   reprise moved 0x04 → 0x02, and reserved class 0x03 was dropped
   0x81 gained a payload type, and hard_prune with it
```

> Recorded because an undocumented exception is indistinguishable from a precedent,
> and a list of four is more honest than a claim of one. Someone will find that `v1`
> changed shape and reason that it may again — under deadline, which is exactly when
> this rule is worth the most and defended the least.
>
> So the test is not *how many times has this happened*. It is the single question
> **is the set of devices speaking the old shape empty**, which is answerable, and
> which becomes permanently and irreversibly "no" on the day something ships.

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

### A route is never added to a version already served

**[S]** A **functional route** is never added to a contract version already served, and
a server MUST NOT expose one there. A new route ships under a **new** contract version,
with the old one still served beside it on the rule above.

> Otherwise the ambiguity above walks straight back in, one level down. Add `GET
> /v1/w/{w}/thing` to the contract after `/v1` shipped, and a client meeting `404
> not_found` on it cannot tell *this server predates the route* from *I built the wrong
> URL* — and this time there is no code that could split them, because a bare
> `not_found` is the **correct** answer to both. A server that predates a route does
> not know the route exists to have an opinion about it.
>
> With the rule, "does this server have the route" is always answered by
> `contract_versions`, before a request is built. The cost is real — a whole version
> bump for one route — and it is what buys that answer being computable at all.
> Discovering the route's absence is not the same as guessing it.

**[S]** The health endpoints are outside the prefix and outside this rule: `GET
/health` and `GET /health/db` are not functional routes, and what they report grows
additively (§7).

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

### Responses run the other way

**[C]** A client MUST **ignore** an unrecognised member of a **response** body, at any
nesting depth, and MUST NOT refuse a response for carrying it. That includes a
refusal: a client MUST NOT reject one for carrying fields beyond the set its code is
documented with.

> The asymmetry is the whole point, and it is about who acts. A request is a set of
> instructions the **server** carries out, so a field it does not recognise is an
> instruction nobody will perform, and accepting it silently is the `200` that lost a
> column (§1). A response is the server **speaking**. A field a client does not
> recognise is a sentence it did not need — ignoring it loses nothing, and refusing it
> loses the whole answer.
>
> Additive response fields are the one evolution channel that must stay free for ever.
> Without this rule the *first* field ever added to a response breaks whichever strict
> client shipped first, permanently — the fleet never re-ships, so the field can never
> be added, and every response shape in the protocol is frozen by its earliest reader.
>
> `limits` has said this all along in miniature: MUST carry four keys and **MAY carry
> more** (§7). That was never a quirk of one field. It is this rule, stated once and
> generally.

**[C]** Ignoring is not honouring. A client MUST NOT infer meaning from an unknown
member, MUST NOT branch on its presence, and MUST NOT echo it back into a later
request — where it would be refused `unknown_request_field` by the rule above.

---

## 5. In-band versioning: the served sets

**[W]** Five sets define what an implementation understands. Anything outside
fails closed.

| Set | v1 |
|---|---|
| suites | `0x00` plaintext, `0x01` encrypted |
| op classes | `0x01` content, `0x02` reprise, `0x80` control, `0x81` prune, `0xBF` ext_binding |
| control types | `workspace_genesis`, `member_register`, `member_amend`, `grant`, `revoke`, `role_table`, `delegate`, `revoke_delegation`, `root_handover`, `rotate` |
| prune types | `prune`, `prune_ext`, `hard_prune` |
| ext_binding types | `bind`, `unbind` |

**[W]** *Fails closed* is unconditional for the **server** and holds for a reader on
every **load-bearing** value. The single reservation is the `note_*` control types
([Authority](03-authority.md#the-criticality-reservation)) — advisory for ever,
hash-chained past rather than interpreted, and still refused at a server's door like
any other type it does not serve. v1 defines none: it is a place kept, not a member.

**[W]** Two ranges of the class byte are **not** core-assigned and so are not part
of this table — see [The Log](01-the-log.md#3-the-class-byte):

| Range | Owner | Advertised |
|---|---|---|
| `0x40–0x7F` opaque | the profile declares them | ✓ `served_sets.op_classes` (§7), and with the profile |
| `0xC0–0xFF` server-read | the implementation defines them, the profile enables them | ✓ `extension_classes` **and** `served_sets.op_classes` (§7) |

**[S]** Those advertisements are fields, not aspirations. `GET /health` carries
`extension_classes`, mapping each enabled class to its NAME, `{}` when none (§7); and
it carries `served_sets`, in which `op_classes` is **every** class byte this server
serves, all three ranges alike. The opaque range needs no NAME map and has none —
nothing on the wire distinguishes a profile-declared opaque class from `0x01` — but its
members appear in `served_sets.op_classes` like every other byte the server will accept.

**[S]** `served_sets` advertises **four** of the five sets above — suites, op classes,
control types, prune types — each exactly as this server serves it (§7).

> Four, not five, and the omission is deliberate. `ext_binding` types are the one set
> nothing batches on: a deployment posts a binding per class, by hand, and reads the
> answer immediately. The field exists to spare a client an all-or-nothing batch (§7),
> and there is no such batch here.

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
        ├─► new suite byte              a new envelope construction —
        │                               sealing, signature, geometry
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
> reprise and prune already replace old encodings with new ones, and `prune_ext`
> ([The Log §7](01-the-log.md#prune_ext-folding-an-extension-class)) reaches the
> extension range itself, naming the class and the NAME its ops were written under.
> Promoting `0xC5` to `0x82` is a fold, a `prune_ext` and, if the bytes are wanted
> back, a `hard_prune`: not a migration script, and not a class that can never be
> retired.

**[W]** **The domain string is the version.** No signed document carries a version
field — see [Keys](04-keys.md).

> That is why a downgrade attack fails cleanly. If a version lived *inside* the
> signed document, an attacker could try to make a v2 document parse as v1. With the
> version in the signing domain, the signature simply does not verify.

### Which hashes can succeed, and how

The served sets say a construction may be replaced. They say nothing about the
**hashes**, and the answer differs by where a hash sits. Worth settling before there is
a second answer, because a successor to SHA-256 arrives on the same horizon a successor
to Ed25519 does.

**A per-op hash follows the referencing op's suite.** An envelope hash ([The Log
§2](01-the-log.md#2-the-envelope)) and the attestations a prune carries are computed by
one op and checked on behalf of one op. A successor function therefore rides a new
suite value and reaches **new** ops only: ops written before it verify under the old
function for ever, nothing stored is rehashed, and there is no migration step to get
wrong.

**[W]** **A hash that names another op is computed with the function of the op carrying
the name**, never with the named op's own. The chains therefore span suites:
`prev_author_hash` and `prev_control_hash` point at an earlier envelope that may have
been written under a different suite, and the link's algorithm is the **linking** op's.

> Stated now, while both answers are still free and neither has shipped, because this
> is exactly the question two implementations would answer differently with both
> looking right. The other reading — the named op's own function — is defensible and
> unworkable: a verifier would have to establish the target's suite before it could
> check the link, on a chain whose whole job is to be checkable from the bytes in hand.
> A linking op knows its own suite by definition. One reading is arithmetic; the other
> is a lookup.

**And a tombstone's hash can never succeed at all.** A `hard_prune` drops the envelope
bytes and keeps their hash ([The Log
§7](01-the-log.md#7-replacing-old-ops-reprise-and-prune)), so that hash can never be
recomputed under a later function — the input is gone. It stays whatever was in force
when the bytes were destroyed, and an implementation that has moved on keeps the old
function in order to check a later `hard_prune` against it.

> Accepted with eyes open rather than overlooked. Retaining the bytes so they stay
> rehashable is the one thing `hard_prune` exists to stop doing, and the alternative to
> a permanent hash is an attestation nobody can check — on precisely the targets nobody
> can re-derive. Thirty-two permanent bytes under a permanent function is the cheaper
> end of that trade, and it is a trade rather than a defect.

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
 "extension_classes": {"197": "retention-sweep"},
 "served_sets": {"suites": [0, 1],
                 "op_classes": [1, 2, 128, 129, 191, 197],
                 "control_types": ["delegate", "grant", "…"],
                 "prune_types": ["hard_prune", "prune", "prune_ext"]},
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
| `extension_classes` | confirm the deployment's extension vocabulary before binding |
| `served_sets` | know which in-band values this server understands, before batching them |
| `limits` | size batches and pages; set the socket idle deadline |

**[S]** MUST remain reachable while the backing store is unavailable — that is its
purpose.

**[S]** `extension_classes` maps each **enabled** extension class to its NAME, and
MUST be present — `{}` when none are enabled, never absent. It reports row 10 of the
[profile obligations](reference/profile-obligations.md) verbatim: the same set, the
same names, nothing added and nothing withheld.

**[S]** Its keys are the class number in **decimal, as a JSON string** — JSON has no
other kind of key — and carry the same values `ext_binding` carries as integers ([The
Log §3](01-the-log.md#3-the-class-byte)). `"197"` is `0xC5`. No leading zeros, no hex
spelling.

> This is where [The Log §3](01-the-log.md#3-the-class-byte)'s "a server MUST
> advertise the extension classes it implements in its served sets" is actually
> served. Without the field, a client discovers the vocabulary by binding and being
> refused — and neither refusal it can meet says the right thing.
> `ext_class_not_enabled` says *this deployment does not permit that class*;
> `ext_name_mismatch` says *your software and this server disagree about what it
> means*. Both are sharper than the truth, which was only *you were never told*.
>
> `{}` rather than an absent field, for the reason the whole layer runs on: absent is
> indistinguishable from a server too old to carry it, and a client that cannot tell
> those apart guesses. An empty object is an answer.

**[S]** `served_sets` MUST be present, MUST carry all four keys, and every array MUST be
**truthful** — exactly the set this server serves, nothing aspirational and nothing
withheld. A server that later widens a set widens it here in the same deploy.

> The name is `served_sets` and not `served` because `served` is taken: an
> `unsupported_contract_version` detail carries one, and it is a list of **versions**
> (§3). Two fields of one name, on one surface, meaning two things a client must not
> confuse — the defect this specification refuses everywhere else it appears.

**[S]** Values are spelled as the served-set table spells them (§5): a suite or class
**byte** as a JSON **integer**, in decimal, and a control or prune **type** as its
string. Both numeric arrays are ascending; both string arrays are sorted
lexicographically.

> Integers rather than `extension_classes`' decimal strings, and the difference is not
> an inconsistency. Those are JSON object **keys**, which have no other kind. These are
> array elements, and a class byte is an integer everywhere else it appears on this
> surface ([The Log §3](01-the-log.md#3-the-class-byte)).

**[S]** `op_classes` is **every** class byte this server accepts — core assignments,
the profile's opaque classes and the enabled extension classes alike. A byte absent
from it is refused `unsupported_op_class`. The `197` above is the same `0xC5` that
`extension_classes` names; the two fields never disagree.

**[C]** `served_sets` is **informational**. A client uses it to decide what to send and
how to group a batch, and MUST NOT read it as permission. Every fail-closed rule still runs
on both sides: a value listed here can still be refused by any later check, and a value
the client itself does not understand is still refused by the client, however
confidently the server advertises it.

> Which is what keeps this from becoming negotiation. Nothing is agreed here and
> nothing is promised — the field turns *find out by being refused* into *ask*, and
> stops there. A client that starts trusting the list instead of its own rules has
> rebuilt version negotiation inside a discovery endpoint, and the first server that
> advertises a class it then refuses for some other reason will find it.
>
> The all-or-nothing batch is what makes the ask worth a field. One op of an unserved
> class fails the batch around it ([The
> Log](01-the-log.md#the-batch-is-all-or-nothing)), so a post-widening client
> talking to an older server otherwise learns the vocabulary by bisecting its own
> queue — repeatedly, on every sync, against a server that could have answered in one
> unauthenticated request.

**[S]** `limits` MUST carry those four keys and MAY carry more.

**[S]** `max_page_size` and `default_page_size` govern **every** paged route — `GET
…/ops`, `GET …/members`, `GET …/keywraps/me` and `GET …/epoch-keys` alike. One
advertised pair, not one per route.

> Otherwise a client would have to discover a ceiling per route, and the first route
> added after a deployment shipped would have no way to advertise its own.

**[S]** A deployment's request-body bound ([the conventions](README.md)) is refused
`413 request_too_large`, on any route.

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

> Store unavailability is the **one** condition in this specification that is a
> *state* rather than a bug, which is what lets every other layer say "a `500` is a
> bug" without qualification. This is the route that exists to be **asked** about it.

### The one state that is not a bug

**[S]** That code is not confined to `GET /health/db`. **Any** route MAY answer
`503 store_unavailable` while the backing store is unavailable — **except `GET
/health`**, which MUST stay reachable and answer normally, because that is what it
is for. The refusal carries no other field, names no cause and says nothing about
the request: there is nothing it could say, because nothing judged it.

**[C]** A client treats it as **transient**, matched **positively** on §6's rule —
never as the unmatched default. `GET /health/db` is what it probes to decide whether
to keep waiting.

> Without this, an outage has no legal answer on a functional route. `POST …/ops`
> cannot append; it cannot refuse under any code in the [code
> list](reference/refusal-codes.md), because every one of them is a verdict on the
> request; and "a `500` is a bug" forbids what is left. The route is left with
> nothing it may say — a specification mandating an impossibility, rather than a
> server behaving badly.
>
> Carrying nothing is the point, and it is what keeps this from becoming a second
> `500`. `store_unavailable` is a statement about the **server**, and it is the only
> refusal in the vocabulary that is. Every other code answers *what was wrong with
> what you sent*; a client that met one of those and a client that meets this one
> have learned opposite things, and the empty body is what says so.

### What is discoverable, and what is not

```
   DISCOVERABLE at runtime          FROZEN by the profile — never negotiated
   ──────────────────────          ────────────────────────────────────────
   contract versions               protocol namespace  (advertised, not agreed)
   batch and page ceilings         Workspace topology
   keepalive interval              initial role table
   deploy label                    member kinds
   profile name                    body size classes
   served sets, extension names
     (advertised, not agreed)

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

By contrast, these are **fixed for the v1 constructions** and identical in every
deployment — no deployment tunes one, and no request negotiates one:

| | |
|---|---|
| header 158 B · signature 64 B · overhead 222 B | authentication tag 16 B |
| key id 8 B · content key 32 B · challenge nonce 32 B | member wrap 104 B · escrow wrap 72 B |
| digest 32 B · Root key 32 B · Root signature 64 B | prune targets ≤ 1000 |

**[W]** Fixed *for the v1 constructions* is not frozen for ever, and the distinction is
load-bearing on the first row: those are the envelope geometry of suites `0x00` and
`0x01`, and **a new suite value carries its own** — its own signature algorithm, its own
signature length, and so its own overhead ([Keys
§3](04-keys.md#3-suites-sealing-a-body)). The wraps, digests and key sizes below it are
versioned by their signing domains the same way (§5). What no deployment may do is vary
any of them for a construction that already exists.

> The line the first row was being read across. "Frozen by the wire format" is exactly
> true of a deployment — nobody tunes 158 — and was being carried into a claim about
> *time*, which it never made. A signature length that can never change is a fork
> waiting for a cryptographic deadline, and the machinery to avoid it has been here all
> along: an open enum and a per-suite length floor.

> The prune-target cap is wire-frozen while the batch cap is not, and the
> distinction is worth understanding. The batch cap is server resource policy that a
> client discovers and adapts to. The prune cap is a **shape rule other clients
> enforce** on an op this server already accepted — so a server that raised it would
> mint ops its peers refuse.

---

## Next

You have read all five layers. What remains is reference material:

- [Refusal codes](reference/refusal-codes.md) — all 125
- [Glossary](reference/glossary.md)
- [Retained state](reference/retained-state.md)
- [Profile obligations](reference/profile-obligations.md)
- [Conformance](../conformance/checklist.yaml)
