# Identity

*Which key is speaking.*

[The Log](01-the-log.md) described ops as "authored by a device". This layer says
what a device is, what the identity behind it is, and how each proves itself.

It answers **authentication** only — *who are you*. What you are then allowed to
write is [Authority](03-authority.md).

---

## 1. One identity, many devices

```
        ┌──────────────────────────────────────────────┐
        │  ROOT KEYPAIR                                │
        │  the identity itself. 32 random bytes.       │
        │  holds no session, authors no op, appears    │
        │  in no header. Signs certificates.           │
        │  At rest it exists only wrapped — [Keys]     │
        └───────────────────┬──────────────────────────┘
                            │  certifies
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  MEMBER    │  │  MEMBER    │  │  MEMBER    │
     │  "laptop"  │  │  "phone"   │  │  "tablet"  │
     │            │  │            │  │            │
     │ signing key│  │ signing key│  │ signing key│
     │ sealing key│  │ sealing key│  │ sealing key│
     └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
           │               │               │
           └── authors ops ┴── authors ops ┘
```

**Root is the identity.** There is no account record, no user id, and no third
party that says who you are. A Workspace's id is bound at genesis to the Root that
founded it ([Authority](03-authority.md)), so the identity and the data it owns are
tied at creation rather than by a lookup.

**Root is not a credential.** It authenticates nothing and appears in no
`Authorization` header. It signs certificates, and those certificates are what the
log carries.

**A Member is a device.** It holds a signing keypair and a sealing keypair, and it
is the only thing that ever authors an op. Every op names its author in the header.

> The separation is not bookkeeping. Holding Root must not be the everyday state:
> it appears on a device during a ceremony and is dropped when the ceremony ends,
> while the device's own keys work for years.
>
> It also decides what a compromised Root can do. Root can certify a **new** device,
> and that certificate lands in the log where every other device replays it. It
> cannot author ops as an **existing** device, because that needs a key that never
> left that device. So a stolen Root shows up as a new member nobody recognises,
> rather than as forged history on a device that was already trusted.

---

## 2. What authenticates, and what does not

There is one kind of session credential — a device token — and three things that
are not sessions at all.

| Route | What proves the claim |
|---|---|
| `GET /v1/vault/{locator}` | **nothing.** Knowing the locator is the claim |
| `PUT /v1/vault/{locator}` | a **Root signature** inside the body |
| `POST /v1/members` | a **Root-signed certificate** inside the body |
| `POST /v1/members/{m}/challenge` | nothing |
| `POST /v1/members/{m}/token` | a **device signature** over the challenge |
| `POST /v1/members/{m}/token/refresh` | the refresh token |
| everything else | a **device access token** |

**[S]** A device token authorises nothing outside the Workspace plane. It cannot
reach a vault slot, and there is no route on which it could: a slot is addressed by
a locator derived from a secret the device never holds, so the question the token
would answer is never asked.

> Worth stating rather than leaving structural. The vault holds Root; a device that
> could walk from its own token to the vault would be a device that could promote
> itself to the identity. It cannot, because it does not know where to look.

### Token properties

**[S]** Access tokens are **opaque bearer strings**, sent as `Authorization: Bearer
…`. Their internal format is the server's own business — it mints and consumes them
— but they MUST name the device they speak for, and they MUST expire.

**[S]** Refresh tokens are **opaque, high-entropy, returned exactly once**, and:

- **single-use** — every successful refresh revokes the presented token and issues a
  new pair;
- **revocable** — losing your last permission in a Workspace kills every refresh
  token scoped to that device ([Authority](03-authority.md));
- **stored irreversibly** — a server MUST NOT be able to reconstruct a live refresh
  token from its own storage.

**[S]** A credential failure is `401 invalid_credential`, carrying
`WWW-Authenticate: Bearer`.

---

## 3. Admission

The core does not decide who may bring a new identity into being. Anyone can mint a
Root keypair — it is 32 random bytes and no server is involved — so without some
gate, anyone can found Workspaces without limit.

### One gate, at the first thing that ever happens

**[S]** **Registering an identity's founding device is the only admitted operation.**
A server MUST decide, at `POST /v1/members`, whether this caller may bring a new
identity into being at all, and MUST refuse `403 admission_refused` when it may not.

**[S]** The **certificate type** in the request decides which branch applies, and
nothing else does:

```
   workspace_genesis certificate   →  founding.  Admission is required.
   member_register  certificate    →  joining.   The Workspace it names MUST
                                      already exist with that Root as its
                                      current Root — and then no admission
                                      credential is needed.
```

> A device joining an account it already owns proves that by construction: it holds
> Root because it just opened the vault, and the Workspace is already in the log.
> Making it ask an operator for permission to add a laptop would put a human in the
> middle of the one flow this design exists to make automatic.
>
> The discriminator is free because the founder was always going to present its
> genesis certificate here — [Authority](03-authority.md) embeds the founder's key
> block inside genesis precisely because nothing earlier in the log can introduce
> it. The route needs a certificate; the founder has exactly one; its type is the
> answer.

**[S]** A `workspace_genesis` certificate takes the founding branch **whether or not
the Workspace already exists**. The server does not look, and a pointless genesis
fails later under `genesis_not_first`.

> Keeping the founding branch purely syntactic is what stops this route needing a
> Workspace lookup on the path that runs before any Workspace exists.

**[S]** **How it decides is the implementation's own business.** The core defines no
mechanism and no format. Two conforming servers may answer the question in
completely different ways.

**[S]** What the core does define is the **carrier**, because most mechanisms need
one:

```
   Roundelay-Admission: <opaque>
```

**[S]** The value is an opaque string the server minted or recognises — a capability
token, a signed grant, an invite code, a proof of work, whatever the deployment
chose. The server parses it; nothing else does. A client treats it as bytes it was
handed and echoes it unmodified.

**[S]** It is **optional to send and optional to require**. A deployment that gates
on network position, a client certificate or nothing at all ignores the header
entirely. One that requires it answers `403 admission_refused` when it is absent,
malformed or spent — the same code, because the caller learns the same thing and
does the same thing.

> The shape is deliberately the one [§2](#2-what-authenticates-and-what-does-not)
> already uses for access tokens: a named place to put an opaque string whose
> internal format is the issuer's own business. Standardising the carrier and not
> the contents is what lets one client work against two deployments that gate
> completely differently — and without it every implementation invents its own
> header, which is the same fragmentation with none of the freedom.

**[S]** The header is meaningful **only where admission is evaluated**. A server MUST
ignore it everywhere else and MUST NOT accept it in place of a device credential on
any route.

> Otherwise it becomes a second session mechanism by accretion — first it admits a
> founding device, then it is convenient for one more route, and the account
> relationship this design removed grows back through the gap.

**[P]** A profile MUST declare **where** admission is enforced — including `open`,
meaning nothing is enforced — so that a deployment cannot ship without having
answered it. It declares nothing about *how*.

> The split is the point, and it took a wrong turn to find. Admission looks like
> protocol because the core has to say *something*, but everything anyone would
> actually write down — invites, payment, proof of work, an allow-list, a token —
> is deployment policy that needs none of the log, the certificates or Root. A
> specification that picked one would force the wrong one on most adopters and buy
> a refusal vocabulary, a profile row and a conformance surface to do a job a
> front door already does.
>
> What could *not* be pushed to a front door is the **boundary**: which operation is
> the one being gated, and which requests are exempt. A reverse proxy cannot tell a
> founding registration from a joining one without parsing the certificate, and
> cannot tell a Workspace that exists from one that does not without asking the
> store. So the core names the operation, names the discriminator, and stops.

**[S]** Admission is **never consulted again**. It MUST NOT participate in identity,
MUST NOT be recorded against the log, and MUST NOT gate any other route.

> It answers *may this caller consume storage*; it never answers *who is this*. The
> moment it answers the second question it has become an identity provider, and the
> server has an account relationship again — with a table to keep, a recovery story
> to own, and a second secret that can be stolen.

**[S]** Admission is consulted **once per identity**, however many Workspaces that
identity founds and however many devices it later enrols.

> It falls out of where the gate sits rather than being a rule anyone has to
> remember. The founding device is registered once; every Workspace it goes on to
> found, and every device that joins afterwards, rides on that one decision.

### Everything else follows

**[S]** Nothing after `POST /v1/members` is admission-checked. Posting a genesis
needs a device access token, which needs a member record, which was the admitted
act; every later op is judged by the log.

**[S]** A **first** write to a vault slot requires that at least one Workspace whose
current Root is the record's `root_pk` already exists. Otherwise `403
vault_requires_genesis`. Later writes are gated by the pinned Root signature.

> Not a second gate — a precondition. It costs nothing to check and it removes a
> state that never meant anything: a vault holding an identity that owns nothing.

**[C]** Founding is therefore **register, then genesis, then vault**.

**[S]** `open` is a legitimate declaration. A self-hosted deployment serving one
person has no abuse boundary worth defending, and saying so explicitly is better
than a policy nobody enforces.

---

## 4. How a device gets a credential

A device cannot present a password — it has a keypair. So it proves possession of
its signing key.

```
   device                                          server
     │                                               │
     │  ── 1. POST /v1/members ──────────────────►   │   a Root-signed
     │      { keys, registration certificate }       │   certificate
     │  ◄─── 201 { …, chained: false } ──────────    │   a shell. no authority.
     │                                               │
     │  ── 2. POST /v1/members/{m}/challenge ────►   │   no credential at all
     │  ◄─── 200 { nonce } ─────────────────────     │   32 random bytes
     │                                               │
     │      sign the nonce with the device key       │
     │                                               │
     │  ── 3. POST /v1/members/{m}/token ────────►   │   the signature IS
     │      { nonce, signature }                     │   the credential
     │  ◄─── 200 { access_token, refresh_token } ─   │
     │                                               │
     │      now it can write ops ── The Log          │
```

Step 1 needs Root. Steps 2 and 3 need only the device's own key.

> Which is why a device keeps working for years after the ceremony that created it.
> Root is required to *introduce* a device and never to operate one.

### `POST /v1/members` — register the device's public keys

**Credential:** the Root-signed registration certificate in the body. There is no
session to present.

```json
→ {"member_id": "<uuid>",
   "control_pk": "<b64 32B>",    // Ed25519 — server-read classes, and the challenge
   "content_pk": "<b64 32B>",    // Ed25519 — opaque classes
   "kex_pk":     "<b64 32B>",    // X25519  — receives sealed keys
   "key_ids":    { … },          // optional; must equal the derivations if sent
   "cert_b64":  "<b64>",         // member_register OR workspace_genesis
   "cert_sig_b64": "<b64 64B>",  // Root's signature over it
   "root_pk_b64":  "<b64 32B>"}  // the Root that signed

← {"member_id": "…", "control_pk": "…", "content_pk": "…", "kex_pk": "…",
   "key_ids": { … }, "chained": false}
```

**[S]** `201` on create; **`200` on an identical repeat**, with the same body.

**[S]** Checks, in order:

```
   1. the request's own shape: three 32-byte keys, a 32-byte root_pk,
        and each claimed key id 8 bytes, derived from the key beside it
   2. the certificate parses, with the closed key set for its type
   3. by certificate type:                                      ◄── creation
        workspace_genesis  →  creatable(root_pk, workspace_id)
        member_register    →  nothing; reachability is step 6
   4. the signature verifies under root_pk
   5. the certificate's contents: it names this member_id, it names
        these three keys, and its member_kind is one the profile serves
   6. by certificate type:                                      ◄── the gate, §3
        workspace_genesis  →  admission
        member_register    →  that Workspace exists, with root_pk as current Root
```

> Steps 1 and 2 are **shape**, and step 5 is **values** — which is why the
> certificate's own claims wait below the signature, exactly as they do in
> [Authority §10](03-authority.md#10-stage-4--verifying-control-ops). Whether this
> document names your device is a question about what it says, and asking it of
> bytes that have not verified decides something on a forgery's word. Step 1 is not
> that: it reads the request, not the certificate.

**[S]** Step 3 is the **creation** question of [Authority
§3.1](03-authority.md#31-creation), evaluated directly and on the founding branch
only. A `root_pk` the profile's predicate will not let create the id its certificate
names is `403 workspace_not_reachable`.

**[S]** Under `derived` that predicate is arithmetic and nothing else — the id the
certificate names is **one of** the ids the profile's ordered frozen namespaces
compute from `root_pk`. Under `explicit` it is the profile's own predicate, and may
consult the profile's own assignment state.

> Step 3 runs before step 4, so an unverified certificate can ask the question. Under
> `derived` that discloses nothing anyone could not compute offline. Under `explicit`
> it is a probe: `workspace_not_reachable` and `bad_root_signature` are distinct
> codes, so an unadmitted caller can walk ids past a `root_pk` it does not hold and
> learn which ones the profile has assigned. Verifying first would close it. The
> order stays because it is not this route's to choose — [Authority
> §10](03-authority.md#10-stage-4--verifying-control-ops) checks reachability before
> the signature on a genesis op, and one certificate must answer the same way at both
> doors. A deployment that minds the probe refuses the caller at its front door,
> which is where [§3](#3-admission) already puts the mechanism.

**[S]** A `member_register` certificate faces **no derivation check**. Its
reachability is what step 6 already asks — the Workspace exists, with this `root_pk`
as its **current** Root — refused `409 workspace_not_created` or
`422 cert_root_pk_mismatch`.

> Which is the only form of the question that survives a handover. After a
> `root_handover` the current Root is not the one the Workspace id was bound to at
> genesis, and never will be — that binding names only the founding Root ([Authority
> §2](03-authority.md#2-root-the-trust-anchor)) — so a Workspace that has used the
> escape hatch answers reachability from materialised state rather than from the
> founding binding. Asking step 3's question here would leave it unable to enrol
> another device.

**[S]** Steps 1, 2, 4 and 5 consult **no stored state at all**, and under `derived`
neither does step 3. No step on the founding branch reads the **Workspace** store
under either policy, which is what lets that branch run before any Workspace exists —
as it must, since a device registers its keys before it can author the genesis that
creates one. Step 6's joining branch reads the store, and only in the case where
the Workspace is already there to read; an `explicit` creation predicate reads
whatever the profile's own assignment state requires, which is the profile's business
and not this route's.

> There is no pinning step and no trust-on-first-use window on either branch. Under
> `derived` a Root either derives the Workspace it claims or it does not, and the
> answer is the same on every server, at every moment. On the joining branch the
> Workspace is already in the log, and the log says which key is its Root now.

**[S]** **This confers no authority whatsoever.** The record is a **shell** until
the same registration is accepted into the log as a control op
([Authority](03-authority.md)). The certificate proves Root asked for this key; only
the log makes it true.

> Worth pausing on. The certificate at this route and the certificate in the log are
> the same bytes checked twice, and that is deliberate: the server needs the key
> material before it can validate an envelope's author, and the envelope must be
> signed by the very key being registered. Presenting it here buys the ordering, not
> the authority.

**[S]** The server retains **no Root beside the device record**. Which Workspaces a
device may address is answered by its accepted registrations
([Authority](03-authority.md)), one per Workspace.

> A device does not have *a* certifying Root. In a shared Workspace it is registered
> by that Workspace's Root, so a device joining two Workspaces owned by two identities
> is certified by two different keys. Anything stored per device would be wrong for
> one of them.

**[S]** Every key id is **derived by the server** — the first 8 bytes of the key's
SHA-256. A client's claim is cross-checked, never stored.

> A key id indexes into a device's keys. Letting the client choose it would let one
> key occupy another's slot.

**[S]** `chained` reports whether an accepted registration exists for this device in
the log **anywhere**. It is a bootstrap hint that no verification reads. This is the
one place it is informative — it separates a shell from a registered device.

| Refusal | Cause |
|---|---|
| `422 malformed_sign_pk` | `control_pk` or `content_pk` is not 32 bytes |
| `422 malformed_kex_pk` | not 32 bytes |
| `422 malformed_key_id` | not base64, or not 8 bytes |
| `422 key_id_not_derived_from_sign_pk` | the claim disagrees with the derivation |
| `422 malformed_root_pk` | not 32 bytes |
| `422 malformed_control_payload` | the certificate does not parse, or carries an unknown key |
| `403 workspace_not_reachable` | `root_pk` may not create the id a `workspace_genesis` names |
| `422 bad_root_signature` | the claimed Root did not sign these certificate bytes |
| `422 cert_member_mismatch` | the certificate names another device |
| `422 cert_key_mismatch` | the certificate names another key |
| `422 unknown_member_kind` | the certificate's kind is not in the profile's set |
| `403 admission_refused` | a `workspace_genesis` certificate this caller may not present |
| `409 workspace_not_created` | a `member_register` certificate for a Workspace that does not exist |
| `422 cert_root_pk_mismatch` | that Workspace exists, but this is not its current Root |
| `409 member_id_already_registered` | see below |

**[S]** The certificate refusals are the codes [Authority](03-authority.md) already
defines for the same certificate arriving as an op. They are not narrowed or renamed
here, and the five governed by the shape-and-values discipline ([Authority
§5](03-authority.md#5-the-certificates)) fall on the same side of the signature
check at both doors:

```
   above:  malformed_control_payload, workspace_not_reachable
   below:  cert_member_mismatch, cert_key_mismatch, unknown_member_kind
```

**[S]** The claim covers those five and nothing else. `admission_refused` and
`workspace_not_created` are step 6's **branch** refusals rather than certificate
refusals, and `workspace_not_created` sits above the signature on the append path
(first in [stage 4](03-authority.md#10-stage-4--verifying-control-ops)'s
`member_register` sequence — stage 2 covers every class but control) and below it
here. The joining branch's `cert_root_pk_mismatch` has no counterpart on the append
path at all: a `member_register` op verifies under root authority directly, so the
same disagreement answers `bad_root_signature` there.

> One certificate, one vocabulary. A device that meets `cert_key_mismatch` at this
> route has learned exactly what it would have learned meeting it on the append
> path, and the remedy is identical.

**[S]** `member_id_already_registered` covers: the id exists with either signing key
different; with a stored `kex_pk` that differs from the one supplied; **and** with no
stored `kex_pk` while one is supplied. A stored sealing key is never upgraded in
place. Omitting `kex_pk` when one is stored is an identical repeat and answers `200`.

> The id is a client-chosen UUID, so this is an existence oracle over a namespace
> the caller already controls. Two identities that pick the same UUID collide, and
> the second one is told so rather than silently taking over the first one's record.

**[S]** A request repeating this `member_id` and these keys under a **different** valid
certificate — a `member_register` for a second Workspace, say — is not a refusal: it
answers `200` with the stored record. The certificate faces every check above and is
then discarded. Only a key that disagrees with the stored one refuses.

> The record holds keys, never certificates, so a second certificate has nothing to
> conflict with. Where a registration is *recorded* is the log, and that is where the
> second one goes ([Authority](03-authority.md)); this route only ever bought the
> ordering. Refusing here would mean a device could enrol in exactly one Workspace.

### `POST /v1/members/{member_id}/challenge` — get a nonce

**Credential:** none.

```json
← {"nonce": "<b64 32B>"}
```

**[S]** Single-use, short-lived.

> Unauthenticated **on purpose**: possession of the device's signing key *is* the
> credential being proved, and a random nonce discloses nothing. Requiring a
> credential to get one would defeat the point.

**[S]** Because it is unauthenticated it MUST be rate-limited per member id. **The
existence check runs first**, so sweeping through invented ids creates no counters.

| Refusal | Cause |
|---|---|
| `404 unknown_member` | no such device registered |
| `429 member_challenge_rate_limited` | too many; carries `retry_after_seconds` |

### `POST /v1/members/{member_id}/token` — exchange it

**Credential:** the signature.

```json
→ {"nonce": "<b64>", "signature": "<b64>"}
← {"access_token": "…", "refresh_token": "…", "token_type": "bearer"}
```

**[W]** The signature is by the device's **control key** ([Authority](03-authority.md)),
and covers the member id **and** the nonce, under a dedicated signing domain — see
[Keys](04-keys.md) for the exact construction.

```
        signed:   [ member id ] [ nonce ]
                        ▲
                        └── binds the signature to THIS device's challenge slot,
                            so a captured signature cannot be replayed into
                            another device's pending challenge
```

**[S]** **The challenge is spent by the attempt, win or lose** — and spent *before*
either field is decoded.

> So a signature-guessing loop needs a fresh round trip per guess. And a request the
> server cannot even parse must not be the one shape that leaves the nonce alive to
> try again.

| Refusal | Cause |
|---|---|
| `401 bad_member_challenge` | unknown device, nonce unknown/expired/wrong device, wrong nonce length, bad signature |
| `422 bad_member_challenge` | the nonce or signature was not valid base64 |

> Same code for both statuses, deliberately: the distinction leaks nothing about the
> device or its key, only that the bytes were not base64.

### `POST /v1/members/{member_id}/token/refresh`

```json
→ {"refresh_token": "…"}
← {"access_token": "…", "refresh_token": "…", "token_type": "bearer"}
```

**[S]** Rotation: revoke the presented token, issue a fresh pair.

**[S]** `401 invalid_refresh_token` — unknown, revoked, expired, scoped to a
different device, or naming a device that does not exist.

**[C]** Logging out is **client-side**: the device deletes its token pair. There is no
route that asks the server to, and the server-side cut is revocation — losing the last
permission in a Workspace already kills every refresh token scoped to that device
(§2, [Authority](03-authority.md)).

> The omission is deliberate. A device that wants its own session gone deletes it; a
> device that must be *cut off* is revoked, by whoever holds the authority to do it. A
> half-measure between the two is a second revocation mechanism to keep in step with
> the first, and they would disagree the first time either was extended.

---

## 5. Listing the devices in a Workspace

### `GET /v1/w/{workspace_id}/members`

**Credential:** a device token, unrevoked.

```
  ?after=<member_id>     exclusive; default: from the start
  &limit=500             1 … the advertised maximum
```

```json
← {"members": [{"member_id": "…", "member_kind": "<token>", "holder_ref": "…",
                "control_pk": "…", "content_pk": "…", "kex_pk": "…",
                "key_ids": { … }}],
   "has_more": true}
```

**[S]** **Scoped to the Workspace in the path**, in both senses — the path selects it
and the result reflects it. A device appears **iff a Root-signed registration naming
*this* Workspace has been accepted for it**, whatever identity holds it.

```
   Workspace W1
   ├── alice's laptop   registered in W1 and W2   → appears in both lists
   ├── alice's phone    registered in W1 only     → appears in W1's list only
   ├── bob's laptop     registered in W1 only     → appears, held by another Root
   └── alice's tablet   shell, never accepted     → appears in neither
```

**[S]** Entries carry the `holder_ref` from the registration, so a caller can group a
Workspace's devices by the identity holding them without asking anyone. Grouping is by
**equality within this Workspace** and nothing more ([Authority](03-authority.md)).

**[S]** Entries carry the registration's own `member_kind`, served as stored — the
profile's token, neither interpreted nor re-checked here
([Authority](03-authority.md#member-kinds)).

**[S]** Ordered by raw `member_id` bytes ascending, so two implementations return the
same page for the same state.

**[S]** `after` is **exclusive**, and the comparison is on the **raw 16 bytes** of the
member id, **as unsigned bytes**. The page begins at the first member whose id is
strictly greater; omitted, it begins at the start. On the wire it is the canonical
UUID of [the conventions](README.md).

> The text is not the hazard: canonical lowercase UUID sorts exactly as the bytes do,
> so a comparison on the served string agrees by construction. What diverges is a
> **structured** comparison — a platform UUID type that compares as two signed 64-bit
> halves reorders every id whose top bit is set, and one built from field-wise
> integers reorders on each field boundary. Both are ordinary library behaviour and
> neither is the ordering this route serves. Compare the bytes.

**[S]** `after` is a **position, not a lookup.** A value naming no member of this
Workspace is legal, and the page begins strictly above those bytes. It is refused only
for being misshapen.

> The cursor is the ordering, not the list. Every 16-byte value names a place in that
> ordering whether a member sits there or not, so resolving one would be a check with
> nothing behind it — and a route that refused an unrecognised cursor would owe a
> client somewhere to go next.

**[S]** `limit` runs 1 … `limits.max_page_size` and defaults to
`limits.default_page_size`. Those are the **same two ceilings that govern
`GET …/ops`** — [Compatibility §7](05-compatibility.md#7-discovery-the-health-endpoints)
advertises one pair for every paged route, not one pair per route.

**[S]** `has_more` is **exact**: true iff at least one further member exists after this
page.

**[S]** Exact **as of the page**, and no further: a walk holds no snapshot across
pages. A member registered at bytes below a walk's cursor is in none of that walk's
remaining pages, and nothing marks the walk stale — a caller that needs the list as of
now starts a fresh walk.

> The ordering is id bytes, and id bytes place a new member anywhere in it.
> `GET …/ops` never meets this: a new op lands above every cursor ([The Log
> §9](01-the-log.md#9-reading-get-v1wworkspace_idops)). No loss-proof walk is owed
> here, and it would cost the server-side cursor this transport refuses to keep —
> while the loss-proof feed already exists, because every registration is a control op
> in the log, which is where anything that verifies learns the members anyway (below).

**[S]** A `limit` outside range, or an `after` that is not a canonical UUID, is
`422 malformed_request` — **never clamped**, on the same rule as [the log's own
page](01-the-log.md#9-reading-get-v1wworkspace_idops).

> Clamping would let a device built against a larger deployment silently receive short
> pages and mistake one for the end of the list.

**[S]** `after` and `limit` are the **only** parameters this route accepts. Any other
is `422 unknown_request_field`, like an unrecognised parameter anywhere on the
versioned surface ([Compatibility §4](05-compatibility.md#4-unknown-fields-are-refused)).

**[S]** Entries carry **no `chained` flag** — presence in this list *is* the
chaining.

**[S]** A request against a Workspace that does not exist yet returns an **empty
list** with `has_more` false, never an error.

> An enrolling device does not see itself until its own registration lands. That is
> correct and consistent: a shell is a member of nothing.

**[S]** This is a **bootstrap hint that no verification reads.** A device's key is
learned from its own Root-signed registration in the log, so poisoning this list
achieves nothing. The route exists because the server's own permission checks need
the underlying index, and because device management is the obvious consumer.

| Refusal | Cause |
|---|---|
| `403 no_registration` | this device holds no accepted registration here |
| `403 no_live_grant` | this device is revoked here |

---

## 6. Rate limits

**[S]** Rate limits in this specification are **fixed-window**: the window opens at
the first counted request and is not extended by later ones. That holds wherever one
is stated — the vault fetch limit of [Keys](04-keys.md) included.

**[S]** A refused request still counts, except where an existence check runs first —
the challenge route above, and that same vault fetch.

**[S]** `retry_after_seconds` is the remaining lifetime of the current window,
rounded up; with no window open, the full window length.

> Stated because the alternative — a sliding window — produces `retry_after_seconds`
> values an order of magnitude apart for the same nominal limit, and clients back off
> against the wrong one.

---

## Next

[Authority](03-authority.md): now that we know which key is speaking, what is it
allowed to write?
