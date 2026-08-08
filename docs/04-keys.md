# Keys

*How content stays private, what every signature covers, and which party holds
which key.*

[The Log](01-the-log.md), [Identity](02-identity.md) and [Authority](03-authority.md)
built a log that devices can write to and read from, with permissions recorded
inside it. This layer is why the server holding all of that learns almost nothing.

---

## 1. The key inventory

Start here. Almost every question in this layer is answered by "who holds this?"

```
 ╔══════════════════════════════════════════════════════════════════════╗
 ║  ROOT KEYPAIR                    Ed25519, random, never derived      ║
 ║  ───────────────                                                     ║
 ║  is: the identity. Its public key names the Workspaces it founded    ║
 ║  signs: genesis, registrations, owner grants/revokes, handovers,     ║
 ║         vault records                                                ║
 ║  at rest: ONLY inside a vault record, sealed under a secret the      ║
 ║           client derives on the device                               ║
 ║  held by: a device, briefly, during a ceremony — then dropped        ║
 ║  server: NEVER, in any form                                          ║
 ╚══════════════════════════════════════════════════════════════════════╝

 ╔══════════════════════════════════════════════════════════════════════╗
 ║  DEVICE SIGNING KEYPAIR          Ed25519, one per device             ║
 ║  ──────────────────────                                              ║
 ║  signs: every envelope this device writes, and its auth challenge    ║
 ║  at rest: the device's own secure storage                            ║
 ║  server: holds the PUBLIC half only (registered in Identity)         ║
 ╚══════════════════════════════════════════════════════════════════════╝

 ╔══════════════════════════════════════════════════════════════════════╗
 ║  DEVICE SEALING KEYPAIR          X25519, one per device              ║
 ║  ──────────────────────                                              ║
 ║  receives: this device's copy of each Workspace content key          ║
 ║  at rest: the device's own secure storage                            ║
 ║  server: holds the PUBLIC half only                                  ║
 ╚══════════════════════════════════════════════════════════════════════╝

 ╔══════════════════════════════════════════════════════════════════════╗
 ║  WORKSPACE CONTENT KEY  K(w, epoch)     32 random bytes              ║
 ║  ──────────────────────────────────                                  ║
 ║  encrypts: every opaque body in that Workspace,                      ║
 ║            at that epoch                                             ║
 ║  distributed: sealed once per device (a "wrap"), and once under      ║
 ║            the master wrap key (the "escrow wrap")                   ║
 ║  server: holds the WRAPS. Cannot open any of them.                   ║
 ╚══════════════════════════════════════════════════════════════════════╝

 ╔══════════════════════════════════════════════════════════════════════╗
 ║  MASTER WRAP KEY                  32 bytes, one per identity         ║
 ║  ───────────────                                                     ║
 ║  opens: every epoch's escrow wrap, past and present                  ║
 ║  at rest: ONLY inside the vault record, beside Root                  ║
 ║  server: NEVER                                                       ║
 ╚══════════════════════════════════════════════════════════════════════╝

 ╔══════════════════════════════════════════════════════════════════════╗
 ║  THE WRAPPING SECRET              what opens the vault               ║
 ║  ──────────────────                                                  ║
 ║  derived: on the device, from whatever credential the user supplied  ║
 ║  by: a ladder this specification does not define — see §6            ║
 ║  at rest: nowhere. never transmitted, never stored, in any form      ║
 ╚══════════════════════════════════════════════════════════════════════╝
```

### The custody picture

```
              a credential the user supplies
                         │
                    client-side derivation
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
          locator              wrapping secret
      (where to look)          (what opens it)
              │                     │
              ▼                     │
   ┌────────────────────┐           │
   │  VAULT RECORD      │ ◄─────────┘
   │  ┌──────────────┐  │   stored on the server, opaque to it
   │  │ Root secret  │  │
   │  │ master wrap  │  │
   │  └──────────────┘  │
   └────────────────────┘
         │        │
   ┌─────┘        └─────────────┐
   ▼                            ▼
signs control ops       opens escrow wraps
(Authority)                     │
                                ▼
                    ┌────────────────────┐
                    │ K(w,1) K(w,2) …    │  every epoch key
                    └────────────────────┘
                                │
                                ▼
                        decrypts all content

   ────────────────────────────────────────────────────────────────
   MEANWHILE, the ordinary path, with no credential involved:

   device sealing key ──opens──► its own wrap ──► K(w, epoch) ──► content
```

**Two independent routes to the same content key.** The everyday one: each device
has its own sealed copy. The recovery one: the credential opens the vault, which
opens every epoch key ever minted. The second is what makes a fresh device work
**with no other device online** — which matters, because the alternative is a
ceremony that fails whenever the user's other phone is in a drawer.

---

## 2. Domain separation: what makes every signature unambiguous

Before any specific signature, one rule that governs all of them.

Every signature, key derivation and commitment in this protocol is
**domain-separated** — tagged with what kind of document it is — so that a signature
over one thing can never be replayed as a signature over another.

### The framing rule

**[W]** Every domain-separated construction — signature inputs, key-derivation info
strings, encryption associated data, hash prefixes alike — is framed:

```
   framed(domain, rest)  =  [1 byte: length of domain] [domain] [rest]
```

```
   ┌────┬──────────────────────┬─────────────────────────────────┐
   │ 13 │ "acme/grant/v1"      │ the certificate bytes           │
   └────┴──────────────────────┴─────────────────────────────────┘
     ▲
     └── one byte, and it is doing real work
```

> **This one byte is why the namespace can be a parameter at all.**
>
> Plain concatenation is not injective. `"a/op/v1" + "2foo"` and `"a/op/v12" +
> "foo"` are the same bytes. With a fixed namespace and a one-digit version that is
> safe by accident — but the moment the namespace varies, namespace `acme`
> with document `op` collides with namespace `acme/op` with document `v1`.
>
> And it is *reachable*, not theoretical: several inputs here begin with
> attacker-influenceable bytes. The vault input starts with a raw locator, any byte
> of which may happen to be an ASCII digit.
>
> The length prefix makes the construction injective unconditionally — no
> forbidden-character rule, no reasoning about what a payload might start with.
>
> It matters more here than in a closed system because **signing keys are shared
> across protocols by design**: a device key is the same key in every namespace it
> joins, and a key a user brings from elsewhere signs arbitrary messages for
> arbitrary protocols worldwide.

**[W]** The length is a single unsigned byte. Every domain below is well under 64
bytes; a domain of 256 bytes or more is illegal.

### The namespace

**[P]** The first component of every domain is `PROTOCOL_NAMESPACE`, a profile
constant.

**[P]** It MUST match `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, be 1–32 bytes, contain no
`/`, and be **globally unique** — a reverse-DNS-shaped label or a randomly minted
token, frozen once. *Locally* unique is not the property required, because these
keys are shared with unrelated protocols.

**[S]** The namespace is deployment-frozen. It MUST NOT appear in any request body,
MUST NOT be negotiated, and MUST NOT be echoed by a client.

> Anything that lets a peer *tell* you the namespace hands an attacker the domain
> separator, which is the whole defence.

**[S]** It MUST be advertised in `GET /health` as `protocol_namespace` — read-only,
informational, and never used to build a signature.

> Without the advertisement, a namespace mismatch surfaces as a wall of
> `bad_root_signature` — the code that is supposed to mean "forged, unrecoverable"
> rather than "you're pointed at the wrong deployment". Advertising it is mandatory.

### The eleven domains

**[W]** A domain is `<namespace>/<document>/v<n>`:

| Document | Frames |
|---|---|
| `op` | `header ‖ body` — every envelope |
| `member-register` | a registration certificate |
| `workspace-genesis` | a genesis certificate |
| `grant` | a grant certificate |
| `revoke` | a revoke certificate |
| `root-handover` | a handover certificate |
| `auth-challenge` | `member_id ‖ nonce` — the device login of [Identity](02-identity.md) |
| `vault` | `locator ‖ version ‖ blob` — the vault record |
| `keywrap` | the member-wrap key derivation and its associated data |
| `epoch-key-escrow` | the escrow-wrap associated data |
| `keywrap-digest` | the wrap-set commitment |

**[W]** **The domain string is the version.** No signed document carries a version
field. A field addition or a semantic change ships under a new `v<n>`, so a
downgrade attempt is a signature failure rather than a parsing ambiguity. This is
in-band versioning — see [Compatibility](05-compatibility.md).

**[W]** There is **no domain for the wrapping secret's derivation**, because the
core does not define one. A client that derives its secret by signing something
MUST use a domain of its own, disjoint from every row above.

> The rule survives even though the construction does not. A key that will sign a
> protocol message for this specification must never be induced to produce the
> *secret* under a domain this specification also uses — and the guarantee has to
> hold in both directions, which it only does if the sets are disjoint by
> construction.

---

## 3. Sealing a body

**[W]** The `suite` byte at header offset 1 names the **sealing construction** a
body was written under. It is an open enum, not a flag:

```
   0x00   none           body is the framed payload, in the clear
   0x01   encrypted      body is that same framed payload, sealed
```

**[W]** `0x00` is a member of that enum — *no sealing* — not the absence of a
value, and a future construction ships as `0x02`
([Compatibility](05-compatibility.md)).

> Worth insisting on, because the byte currently has two values and reads like a
> boolean. It is the mechanism by which encryption itself is allowed to change, so
> it stays a byte of its own. Folding it into a spare bit of the class byte — the
> obvious-looking economy — would cap sealing constructions at two for ever, and
> the loss is irreversible.

**[S]** **Which values are legal depends on the class**, and the rule is stated on
capability rather than on cleartext: a class with bit 7 set MUST use a construction
**this server can open**. In v1 that set is exactly `{0x00}`, so `suite` is pinned
there and carries no information. Below bit 7 both values are live and the choice
is the writer's, within the downgrade rule below.

> Worth writing this way now, because the obvious future is a construction sealed to
> a key the *server* holds — hiding control and prune payloads from a network
> observer or a stolen backup, adversaries this design does not currently address.
> That widens the legal set for server-read classes without changing the principle.
>
> **But it would cost something specific, and the cost is easy to miss.** Grants,
> the current Root, and every epoch's digest are rebuildable from the log *because
> control ops are readable* ([retained state](reference/retained-state.md)). Seal
> them to a server key and log replay depends on a key that is neither in the log
> nor on the list of things an operator is told to back up. A migration to another
> implementation would carry the ciphertext and not the meaning. Anyone adding such
> a suite must answer that first.

**[W]** Suite `0x01` is a **body wrapper and nothing else** — no offset moves, no
field is added:

```
   ┌─────────────────────────── the envelope ───────────────────────────┐
   │                                                                    │
   │  HEADER  158 bytes, always in the clear                            │
   │     ├── used as the associated data, exactly as it appears         │
   │     └── contains the nonce at offset 134                           │
   │                                                                    │
   │  BODY    XChaCha20-Poly1305(                                       │
   │              key   = K(workspace, key_epoch)                       │
   │              nonce = the header's own nonce field                  │
   │              aad   = those exact 158 header bytes                  │
   │              text  = the SAME framed body 0x00 would carry )       │
   │                                                                    │
   │  SIGNATURE  64 bytes, over header ‖ body                           │
   └────────────────────────────────────────────────────────────────────┘
```

**[W]** Exactly one rule differs by suite: a sealed body is 16 bytes longer than the
size class it padded to — the authentication tag.

> Using the literal header as associated data means the suite, the epoch and the
> nonce are all bound with no second binding to keep in step. Change any header byte
> and the body no longer opens.
>
> Note the order: **sign over the sealed bytes**. So a tampered ciphertext fails the
> *signature* check. A body that fails to open despite a valid signature means
> something else — bytes the author really signed that still will not decrypt.

**[S]** The server never decrypts and never parses a sealed body. From suite `0x01`
onward its content-blindness is cryptographic rather than merely policy.

### The forbidden combinations

**[W]** Sealing a server-read class is **forbidden for ever**. Three refusal codes
cover it — two named cases and everything else:

| Pair | Code |
|---|---|
| sealed **control** op | `encrypted_control_op` |
| sealed **prune** op | `encrypted_prune_op` |
| sealed op of **any other server-read class** | `encrypted_server_read_op` |

> All for one reason: the server must *act* on those payloads and holds no key. A
> sealed one would be an op nobody could act on — not a stricter op, a useless one.
>
> **[S]** The rule is on the bit, not the list: **every class with bit 7 set is
> plaintext-only**, `0xBF` and the whole extension range included. The first two
> get their own codes because a client that met one has learned something different
> about its server than one that met the other, and the remedy differs. Everything
> else shares one code, because the remedy is identical — stop sealing it.

### And the rule runs the other way for content

**[C]** An **opaque** op — any class with bit 7 clear — at suite `0x00`, at an epoch
the reader **holds a key for**, is a downgrade and MUST be refused
`plaintext_at_encrypted_epoch`.

> The upgrade is one-way. Once a Workspace is encrypted at some epoch, cleartext at
> that epoch is either an attack or a broken writer. This verdict is *reader state* —
> it depends on which keys you hold — so the server never raises it.

---

## 4. Epochs: key generations

A Workspace's content key is not permanent. Each generation is an **epoch**,
numbered in the header of every op sealed under it.

```
   epoch 0 ──────────► epoch 1 ──────────► epoch 2 ──────────► epoch 3
      │                   │                   │                   │
   unkeyed, or         K(w,1)              K(w,2)              K(w,3)
   keyed at genesis
      │                   │                   │                   │
   ops 1..12           ops 13..40          ops 41..77          ops 78..
      │                   │                   │                   │
      └───────────────────┴───────────────────┴───────────────────┘
              every epoch key is kept FOR EVER by every device
              that held it — old ops must stay readable
```

**[S]** A rotation is created by a `rotate` control op ([layer
3](03-authority.md)), and it is **single-step**: `to_epoch` must be `from_epoch + 1`.

> A jump would leave a gap that no wrap set is ever minted for, and the epoch floor
> below would then refuse content at an epoch the Workspace never keyed.

**[S]** `from_epoch` must be the Workspace's **current** epoch — the highest one
materialised — or 0 when unkeyed. Otherwise `409 rotate_epoch_conflict`, carrying
`expected_from_epoch`.

> So two owners racing a rotation cannot both land and leave the log claiming two
> different keys for one epoch. The loser re-reads and rotates again.

### The epoch floor on writes

This is stage 2's fourth check in the [append pipeline](01-the-log.md#the-pipeline).

```
   current epoch = 3

   an op arriving at epoch:   1     2     3     4
                              ✗     ✓     ✓     ✗
                         too old         │      no such epoch
                                         │
      key_epoch_stale ◄──────────────────┴──────────► key_epoch_unknown
```

**[S]** `409 key_epoch_stale` when more than one epoch behind. `409
key_epoch_unknown` when above the current epoch. Both carry `key_epoch` and
`current_epoch`.

> **The one-epoch slack is deliberate.** A device that was offline across a rotation
> holds already-signed ops at the previous epoch. It cannot re-sign them without
> forging its own chain, so without slack its queue could never drain. One epoch of
> slack lets an honest device catch up; two would make the floor meaningless.
>
> The ceiling exists because no wrap set is minted for an epoch nothing rotated to.
> Such an op could never be opened by anyone, so admitting it would park permanently
> unreadable bytes in the log.

**[S]** An **unkeyed** Workspace refuses neither. There is no epoch to be stale
against.

> A deployment that ships plaintext and enables encryption later never has an epoch 0
> key: its first rotation is `0 → 1`, and its pre-encryption history stays readable
> under suite `0x00` for ever. A Workspace keyed from genesis does have an epoch 0.
> Both shapes are legitimate; which one you have is a fact about your history, not a
> choice.

---

## 5. Wraps: getting the key to the people who may read

An epoch key is minted once, on one device. Everyone else needs a copy, and the
server must not be able to make one.

```
                          K(w, 3)   minted on the owner's device
                             │
          ┌──────────────────┼──────────────────┬───────────────┐
          │                  │                  │               │
     sealed to           sealed to          sealed to      sealed under
     laptop's            phone's            tablet's       master wrap key
     sealing key         sealing key        sealing key         │
          │                  │                  │               │
          ▼                  ▼                  ▼               ▼
     ┌─────────┐        ┌─────────┐        ┌─────────┐    ┌──────────┐
     │ wrap 1  │        │ wrap 2  │        │ wrap 3  │    │ escrow   │
     │ 104 B   │        │ 104 B   │        │ 104 B   │    │ wrap 72B │
     └─────────┘        └─────────┘        └─────────┘    └──────────┘
          └──────────────────┴──────────────────┴───────────────┘
                                     │
                                     ▼
                    all uploaded to the server, which
                    can open exactly none of them
```

### Member wrap — 104 bytes

**[W]**

```
  info = framed("<ns>/keywrap/v1",
                epk 32B ‖ workspace_id 16B ‖ epoch u32
                ‖ member_id 16B ‖ kex_key_id 8B)

  wrap = epk 32B ‖ nonce 24B ‖ XChaCha20-Poly1305(
             key  = HKDF-SHA256(ikm = X25519(ephemeral, device_kex_pk),
                                salt, info, 32 bytes)
             nonce, aad = info, text = K 32B)
```

**[W]** HKDF is RFC 5869, HMAC-SHA-256, 32 bytes out. **The salt is RFC 5869's
default: 32 zero bytes**, not a zero-length key.

> A real fork point, stated explicitly. HMAC pads a short key with zeros, so an empty
> salt and 32 zero bytes happen to produce the same result — but a library that
> rejects an empty salt, or substitutes a different default, produces a different
> one, and nothing in the ciphertext says which happened.

**[W]** `info` is both the derivation info **and** the associated data. Every field
in it binds the wrap to one slot:

| In `info` | So a wrap cannot be |
|---|---|
| `epk` | re-pointed at a different ephemeral share |
| `workspace_id`, `epoch` | replayed into another Workspace or another epoch |
| `member_id`, `kex_key_id` | handed to a different device, or a different key of the same device |

> Because the same bytes are both info and associated data, a mismatch on any of them
> is an **authentication failure** — not a silent decryption to garbage.

### Escrow wrap — 72 bytes

**[W]**

```
  info = framed("<ns>/epoch-key-escrow/v1", workspace_id 16B ‖ epoch u32)

  escrow_wrap = nonce 24B ‖ XChaCha20-Poly1305(
                    master_wrap_key, nonce, aad = info, text = K 32B)
```

One per `(Workspace, epoch)`. This is the recovery route from §1.

### The digest: what stops the server curating the set

If the server could decide *which* wraps exist, it could quietly omit one device
(locking it out) or add one (letting an attacker in). It cannot, because the set is
committed to in the signed log **before any wrap is uploaded**.

```
   TIME ──────────────────────────────────────────────────────────────►

   1. device mints K(w,3), builds every wrap, computes the digest
   2. device authors  rotate(2 → 3, keywrap_digest = D)   ← SIGNED, in the log
   3. rotate lands. The server now knows: epoch 3's wrap set must hash to D
   4. device uploads the wrap set
   5. server hashes what it received. Not D?  →  refused
                                        │
                  ┌─────────────────────┴─────────────────────┐
                  │  the server is holding ITSELF to somebody │
                  │  else's signed word — not enforcing a     │
                  │  policy of its own                        │
                  └───────────────────────────────────────────┘
```

**[W]**

```
  keywrap_digest = SHA-256(framed("<ns>/keywrap-digest/v1",
        epoch u32 ‖ member_wrap_count u32
     ‖  for each (member_id, kex_key_id, wrap), SORTED:
            member_id 16B ‖ kex_key_id 8B ‖ SHA-256(wrap) 32B
     ‖  SHA-256(escrow_wrap) 32B))
```

**[W]** The sort key is the **raw 16-byte member id, then the raw 8-byte key id,
compared as unsigned bytes.** Not the UUID text, and emphatically not the base64
spelling.

> Base64's alphabet is not monotonic in byte value, so sorting the wire form gives a
> different digest for the same set. The failure mode is maximally unhelpful:
> `keywrap_digest_mismatch` is deterministic, so a well-behaved client terminalises
> it — and the Workspace becomes permanently unrotatable.

Sorted at all so the digest describes the **set**, not the upload order the server
could shuffle.

---

## 6. The vault: recovery from a credential alone

A device that has just been set up holds nothing. The vault is what turns *something
the user can supply* into Root.

### Two pieces of information

**[C]** A bootstrapping client computes two values on the device:

```
   a LOCATOR      32 bytes — where the record is. It travels.
   a WRAPPING     32 bytes — what opens the blob. It never travels,
     SECRET                  in any form, ever.
```

**[S]** How they are computed is **not specified here**, and a conforming server
cannot tell. The core specifies the slot and stops.

> This is the deliberate line, and it is worth being explicit about what it costs.
> The server cannot distinguish a locator derived from a 256-bit key from one derived
> from `testpass`, and never will. Every rule below is therefore written for the weak
> case: there is no strong-secret exemption anywhere, because there is no way to know
> one is present.

### What the vault must yield

**[W]** Opening the blob MUST produce exactly:

```
   Root secret 32B  ‖  master wrap key 32B
```

**[W]** How those 64 bytes are sealed is the client's choice. The core fixes the
plaintext because other clients of the same deployment depend on it — the master
wrap key opens escrow wraps the *server* is holding — and fixes nothing else.

**[S]** The server stores the blob verbatim, never parses it, and **MUST NOT even
length-check it.**

> Contrast this with the wrap constructions of §5, which are specified to the byte.
> Those travel between clients through the server and must be interoperable. The
> vault blob is written and read by the same client, from the same secret, so the
> only thing that must agree is what falls out of it.

### The two halves are independent, and stay that way

The two keys sit side by side under one secret, which makes them look like one
thing. They are not, and two rules keep them apart.

**[W]** The master wrap key is **32 random bytes, independent of Root**. It MUST NOT
be derived from the Root secret, from Root's public key, or from anything else that
a `root_handover` changes.

> The derivation is tempting precisely because the two live and die together —
> anyone who opens the vault has both, so the independence buys no separation, and
> collapsing them would drop an entry from §1 and halve the blob.
>
> A handover is what forbids it. Change Root, and a derived master wrap key changes
> with it — while every escrow wrap ever minted is still sealed under the old one.
> Every epoch key before the handover becomes unrecoverable from the vault.
>
> And there is no repair. `PUT …/keywraps` is whole-set-per-epoch, and
> `keywrap_already_written` refuses a *different* set for an epoch already
> published — the rule that stops a stolen authority credential swapping the key set
> out from under devices that already read it. It blocks re-minting here too, and it
> should: the two cases are indistinguishable from the server's side.
>
> Deriving from the **founding** Root instead survives the handover and defeats its
> purpose. The founding secret is exactly what an attacker holds in the case that
> motivates handing over; they would keep deriving the master wrap key and keep
> opening every escrow wrap. The succession would move signing authority and leave
> all content readable.

**[C]** Every later write of a vault slot MUST carry the **same master wrap key** as
the record it replaces — after a credential change, after a handover, after any
re-wrap at all. Only the sealing changes; the 64 bytes inside do not, except for
Root on a handover.

> This is the sharpest silent-failure path in the layer. A client that mints a fresh
> master wrap key while re-wrapping produces a vault that opens correctly, verifies
> correctly, and answers every request — and orphans every escrow wrap in the
> account. Nothing refuses, because no server can see inside the blob. The loss
> surfaces the first time somebody enrols a device from the credential alone, which
> may be months later and is exactly the moment the vault existed for.

### Guidance — choosing a derivation

> **Non-normative.** None of this is checkable by a server, and a deployment may
> ignore all of it.

A second component in the derivation defends against exactly one thing: **an
attacker who already holds the blob** — a leaked backup, a hostile operator, a
stolen disk. Online guessing is already bounded, because the record cannot be
*found* without computing the locator, and each attempt costs a full derivation plus
a round trip.

Two shapes are worth suggesting:

**A — a minted key, alone.** A signature from a key the user already holds, a passkey
PRF output, or a secret key the client mints and the user keeps. 128 bits or more, so
a leaked store yields nothing.

**B — a memorable credential plus a minted phrase, combined.** Both feed one
derivation producing one locator and one secret. The typed part carries little; the
minted phrase carries the security. Six words from a 7776-word list is about 77 bits.

And four things not to do:

- **Do not treat a federated sign-in as contributing secret material.** It
  contributes none. It is sign-in UX in front of a real secret, and calling that
  arrangement two-factor invites the belief that two weak legs make a strong one.
- **Do not ship several independent wrappings of differing strength.** Any one of
  them opens the same Root, so the account is worth its *weakest* leg. Independent
  wrappings are an availability mechanism — a real one, §7 — never a second factor.
- **Do not read derivation parameters from the fetched blob.** Client-side constants
  only. Honouring parameters an untrusted party supplied is how a weakened-parameters
  attack works, and constants close it by construction.
- **Do not tell the server which model you chose.** A self-reported strength the
  server cannot verify and must not branch on is worse than none.

> What matters in a secret is whether it was **sampled from a known distribution**,
> not who sampled it. A person rolling dice against a word list produces exactly what
> a machine would. Four words a person merely thought of is nowhere near it, because
> human word choice is associative and attackers model that directly — same artifact,
> different entropy, and indistinguishable from the string itself.

### The signature the server does check

**[W]**

```
   root_sig = Ed25519(signing key,
                framed("<ns>/vault/v1",
                       locator 32B ‖ version u64 ‖ blob))
```

The locator is inside the signed bytes, so a record signed for one slot can never be
replayed into another.

**[W]** The **signing key is the slot's currently pinned Root** — on a first write,
the `root_pk` the record itself declares.

**[W]** `root_pk` is therefore *the Root this record installs*, not necessarily the
one that signed it. The two differ on exactly one kind of write: the one that follows
a `root_handover` ([Authority](03-authority.md)).

> Which is the same shape the handover certificate has, for the same reason. Only the
> outgoing key can attest that a succession is intended; a signature by the incoming
> key would prove nothing, because anyone can mint a keypair. Requiring the outgoing
> Root here is what stops a stolen slot being re-pinned to an attacker's key.

### `PUT /v1/vault/{locator}`

**Credential:** none. The Root signature is the authorisation.

**[W]** `locator` is 32 bytes, lowercase hex — the `^[0-9a-f]{64}$` shape of [the
conventions](README.md). Anything else is an unrouted path: `404 not_found`.

```json
→ {"version": 1, "blob_b64": "…", "root_sig_b64": "…", "root_pk_b64": "…"}
← {"version": 1, "blob_b64": "…", "root_sig_b64": "…", "root_pk_b64": "…"}
```

```
   FIRST write            establishes root_pk for this slot
                          must be version 1
                          signature checked against the key it CARRIES
                          ── trust on first use ──

   EVERY LATER write      version must be strictly greater
                          signature checked against the PINNED key
                          the pin moves to root_pk after it verifies
                          ── only the retiring Root can hand the slot on ──
```

**[S]** A **first** write requires that at least one Workspace whose current Root is
the record's `root_pk` already exists. Otherwise `403 vault_requires_genesis`. Later
writes are not checked: the slot exists and the pinned signature is the gate.

> Which is how the vault inherits a gate without having one. Registering the founding
> device is the admitted operation ([Identity](02-identity.md)); a caller who was not
> admitted never got a token, never posted a genesis, and so has no Workspace and no
> slot to open. It also removes a state that never meant anything — a vault holding
> an identity that owns nothing.

**[C]** Founding is therefore **register, then genesis, then vault**. A device that
mints Root MUST land its `workspace_genesis` before writing the slot that will
recover it.

**[S]** Concurrent writes resolve with exactly one winner; the loser learns what the
slot now holds rather than silently overwriting.

> The locator gets the request *to* the slot. The Root signature gets it *into* the
> slot. That is the whole design in one sentence.

| Refusal | Cause |
|---|---|
| `422 malformed_vault_blob` | not base64 — the blob is never length-checked |
| `422 malformed_vault_signature` | not 64 bytes |
| `422 malformed_root_pk` | not 32 bytes |
| `422 malformed_vault_version` | out of range |
| `403 vault_requires_genesis` | a first write by a Root that has founded nothing |
| `403 bad_vault_signature` | the slot's pinned Root did not sign this record |
| `409 vault_version_regression` | not greater than stored; carries `stored_version` |

**[S]** `bad_vault_signature` is `403`, not `422`, because the caller cannot prove
control of the slot at all — an authorisation failure of the whole request, not a
malformed field.

**[S]** `vault_version_regression` reports `stored_version: 0` when nothing is
stored, so "a create must be version 1" reads unambiguously off it. One version rule
for a client to handle, not two.

### `GET /v1/vault/{locator}`

**Credential:** none. **Takes no body and no parameters** — nothing derived from the
wrapping secret ever reaches the server, so there is nothing to accept. Returns the
record verbatim.

**[S]** **Every served read is recorded durably, before the bytes leave.**

> A silent read is exactly what an attack on this slot needs. Recording each one
> turns it into something that can be shown to whoever owns the identity.

**[S]** **Rate-limited per locator**, and **existence is checked before the quota is
spent**.

> The limit bounds bytes leaving the slot. A slot holding nothing must not be able to
> burn it — otherwise twenty pointless requests lock out the one fetch that actually
> matters.

**[S]** Neither the limit nor the audit is conditional on anything. There is no
signal available that would justify relaxing them, and the guidance above explains
why there never will be.

| Refusal | Cause |
|---|---|
| `404 no_vault_record` | nothing written here |
| `429 vault_fetch_rate_limited` | carries `retry_after_seconds` |

**[C]** A client MUST check that the `root_pk` it was served equals the Root it
recovered from the blob, and MUST treat a mismatch as a corrupt record rather than as
a key to adopt.

> The signature is the *server's* gate, and after a handover a fresh client cannot
> verify it — it has never seen the retired key. What it can always do is compare the
> declared Root against the one the AEAD just authenticated, which is the check that
> actually protects it.

---

## 7. One identity, one vault, several Workspaces

**[S]** The vault is **not Workspace-scoped**. One identity has one Root, one master
wrap key, and therefore one record — however many Workspaces that Root founded.

> Which removes a whole class of problem the Workspace-scoped design had: no
> designated slot to pick, no ordering rule about which slot to write first, and no
> half-written ceremony where one Workspace is recoverable and another is not.

**[C]** Several **independent** vault records — different locators, from different
secrets, holding the same Root — are permitted and sometimes wise. Each one is a
separate way in.

**[C]** They are an **availability** mechanism, not a security one. Any of them opens
the identity, so the identity is worth the *weakest* of them. A client that offers a
recovery record MUST derive it from a secret at least as strong as the primary.

> The failure this prevents is a strong primary quietly undermined by a memorable
> backup. If either one opens everything, adding the weaker one moved the whole
> account down to it.

**The server can tell sibling slots apart from strangers'**, and a client should not
assume otherwise. Every slot stores its pinned Root public key, so grouping by that
column returns every wrapping of one identity, with the times they were written. That
is a consequence of the pin, not a rule of its own — no requirement here creates it
and none can remove it.

> Stated plainly because the comfortable assumption is the opposite one. The locators
> are unlinkable — they come from independent secrets and nothing derives one from
> another — but the *records* are not, because the pin has to be there: it is what
> every later write is checked against. Dropping it would mean any caller who guessed
> a locator could overwrite the slot.
>
> So the cost of a second wrapping is not zero. Anyone holding the database learns
> how many ways into an identity exist and when each was added — not what they are,
> not what opens them, but the shape. A deployment that finds that unacceptable has
> one option, and it is a real one: **do not offer a second wrapping**, and accept
> that forgetting the only credential is terminal.

**[S]** That same grouping is what lets a deployment **bound slots per Root**, and it
SHOULD. An identity is admitted once ([Identity](02-identity.md)), but locators are
the caller's to choose, so one admitted identity can otherwise write slots without
limit into the one table worth stealing.

### Guidance — custody of a shared identity

> **Non-normative.** No server can see any of this, and a deployment that ignores all
> of it is conformant.

An identity that stands for an organisation has exactly the vault a person's does,
and one requirement a person's does not have: **no single individual should be able
to open it, and no single individual's departure should close it.**

The artifact needing a policy is the **wrapping secret**. It is not a password for a
manager belonging to whoever set the account up. It opens Root — and through the
master wrap key beside it, every epoch key ever escrowed, which is every content key
the organisation has used.

- **Split it.** A `k`-of-`n` reconstruction over the 32 bytes fits without any
  protocol support, because §6 specifies the slot and stops: nothing on the wire, and
  nothing in the server, can tell how the secret was assembled.
- **Record where it is.** The locator is not secret in the way the wrapping secret is,
  but it is what makes the record findable at all, and the bound on offline guessing
  in §6 assumes an attacker does not have it. Durable, not public.
- **Rehearse it.** A quorum that has never been convened is not known to work. The
  first attempt should not be the real one — that is the same failure §6 describes for
  a mis-minted master wrap key, arriving at the same moment and for the same reason.
- **A departure is a re-split, not a handover.** Cheap, as long as the quorum stays
  above the number of shares that could plausibly be combined. It becomes a
  `root_handover` only when a share leaves in hostile hands, which is expensive and is
  the thing the quorum size is chosen to avoid.

**Delegation is what keeps the ceremony rare.** With [Authority
§6](03-authority.md#6-delegation-keeping-root-cold), the quorum is needed for three
things only — founding, handing over, and rewriting the vault. Every registration,
grant and revoke goes through a delegate. A deployment convening its quorum weekly has
something delegable that it has not delegated.

### Guidance — the custodian

> **Non-normative**, and about client deployment rather than about this server. The
> name belongs to this section, for talking about the arrangement. It is not a
> protocol role, and nothing in the core knows it exists.

Nothing requires the party that keeps Root to be online, co-located with anything, or
continuously reachable. An organisation may keep it on a small machine inside its own
network — a **custodian** — that comes up to sign and goes back down. It is how a
quorum-held Root stays cold in practice, and what
[delegation](03-authority.md#6-delegation-keeping-root-cold) keeps it cold *for*.

**A custodian is a client.** It speaks the same routes every other client speaks, and
the server gives it nothing — no mode, no registration, no awareness that it exists.
Worth saying plainly because the arrangement looks like infrastructure: there is no
server-side half to build, and a deployment that sets out to add one has misread where
the trust sits.

It is not a **holder** ([Authority](03-authority.md)), which is the identity a device
belongs to. English makes the two words near-synonyms; here one is a machine looking
after key material and the other is 32 bytes in a certificate.

What it buys is that the store can be hosted at any scale, anywhere, while the machine
that looks after the identity stays small, local, and switched off between uses.
Content is sealed against the host either way — what moves is who can be
**compelled**, not what the server can read.

What it does not buy is anything on §9's list. Metadata is what the server sees by
doing its job, and moving Root behind a firewall does not change which ops arrive,
from which device, or when.

---

## 8. The key-plane endpoints

Three routes. In all three the server's job is **storage and arithmetic**: it holds
wraps it cannot open, and checks one hash it was told to check. Every cryptographic
decision was made on a device before the bytes arrived.

### `PUT /v1/w/{workspace_id}/keywraps` — publish an epoch's wrap set

**Credential:** a device holding the **authority role**.

```json
→ {"epoch": 3,
   "wraps": [{"member_id": "…", "kex_key_id_b64": "…", "wrap_b64": "…"}, …],
   "escrow_wrap_b64": "…",
   "keywrap_digest_b64": "…"}
← {"wraps": [ …the caller's own wraps, every epoch… ]}
```

**[S]** **Whole set, never incremental.**

> The digest commits to the whole set, so a partial upload could not be checked
> against it — and accepting one would restore exactly the curation power the digest
> exists to remove.

**[S]** For `epoch > 0` the matching `rotate` must **already** be in the log, and the
set must hash to *its* digest.

> Ordering is the client's to get right: author the rotate, let it land, then upload.
> A set arriving first is refused rather than trusted, because a digest the log has
> not committed to is just a number the uploader chose.

**[S]** Epoch 0 is the one case with no rotate behind it. With no epoch-0 record
stored, `keywrap_digest_b64` is **required** and becomes the commitment. Once a
record exists — including on a replay — it is **optional and ignored**, because the
stored commitment is authoritative.

> That "optional and ignored" is a deliberate exception to the usual unknown-field
> strictness. The field is *known*, and the retry loops depend on a re-upload of the
> same bytes succeeding.

**[S]** **Byte-identical replay is idempotent** and answers `200`. A *different* set
for an epoch already published is refused.

> The wraps an epoch was published with are not a later caller's to replace. Allowing
> it would let a stolen authority credential swap the key set out from under devices
> that already read it.

**[S]** Refusals, in order:

```
   no_registration ─► malformed_key_epoch ─► no_live_grant
     ─► keywrap_requires_owner ─► malformed_escrow_wrap
     ─► per entry: malformed_keywrap · malformed_kex_key_id
                   unknown_keywrap_member · kex_key_id_not_registered
                   duplicate_keywrap_member
     ─► missing_keywrap_digest ─► malformed_keywrap_digest
     ─► rotate_not_materialised ─► keywrap_digest_mismatch
     ─► keywrap_already_written
```

**[S]** `kex_key_id_not_registered` fires when the id is not the one derived from the
device's **registered** sealing key.

> Never a claim. A wrap sealed to some other key would be undeliverable, and the
> device would look orphaned for a reason nothing in the log explained.

**[S]** `duplicate_keywrap_member` fires on two wraps for one device in one set.

> The digest sorts by `(member_id, kex_key_id)`, so a duplicate would make the
> commitment depend on which copy the server happened to keep.

**[C]** `keywrap_digest_mismatch` is **deterministic**. A client MUST terminalise it
rather than retry — see [Compatibility](05-compatibility.md).

### `GET /v1/w/{workspace_id}/keywraps/me` — my own wraps

**Credential:** a device token, unrevoked.

```json
← {"wraps": [{"epoch": 1, "member_id": "…", "kex_key_id_b64": "…",
              "wrap_b64": "…"}, …]}
```

**[S]** **Scoped to the calling device and not parameterised** — there is no id to
get wrong, because the route has nowhere to put one. Ordered by epoch ascending.

> They would be unopenable by anyone else anyway, which makes the scoping a tidiness
> rather than the defence.

**[S]** **Every epoch, kept for ever.** Reprised ops are retained, so content
sealed at any past epoch may still need opening.

### `GET /v1/w/{workspace_id}/epoch-keys` — the escrow wraps

**Credential:** a device with **any** live grant.

```json
← {"epochs": [{"epoch": 1, "escrow_wrap_b64": "…",
               "keywrap_digest_b64": "…"}, …]}
```

**[S]** Ordered by epoch ascending.

**[S]** **Useless without the wrapping secret.** An escrow wrap opens only under the
master wrap key, which exists only inside the vault record.

**[S]** In a **shared** Workspace the escrow wraps open only under the *founding*
identity's master wrap key. A member holding a device registered by that Workspace's
Root, but held by their own ([Authority](03-authority.md)), has member wraps and
nothing else.

> Which means a member of somebody else's Workspace cannot recover a fresh device
> into it from their own credential: their vault holds their Root, not this
> Workspace's master wrap key. An owner has to mint them wraps, exactly as at first
> enrolment. That is the right answer for a Workspace a company owns — losing a laptop
> is an IT ticket, not a self-service reset — but it is a fact about shared Workspaces
> worth knowing before it is discovered.

> Anyone who can already open these can already open Root — which is why the bar is
> deliberately low, and why this route is **not** rate-limited or audited the way the
> vault fetch is. The vault route serves the material a guess is tested against, so
> each fetch is a guess handed out. These wraps are not guessable against anything.

This is the route that makes a fresh device work with **no second device online**:

```
   credential ─► locator ─► vault record ─► Root + master wrap key
                                                     │
                                                     ▼
                                        GET /epoch-keys  →  every escrow wrap
                                                     │
                                                     ▼
                                         K(w,1) K(w,2) K(w,3) …
                                                     │
                                                     ▼
                                         decrypt the entire history
                                                     │
                                                     ▼
                                  and then, holding the authority role,
                                  mint and upload its OWN member wraps
```

**[S]** **Epochs whose escrow wrap has not been uploaded yet are omitted.**

> That is the window between a rotate landing and its wraps arriving. Serving an empty
> blob would look like a wrap that fails to open — an alarm — instead of one that has
> not arrived.

| Refusal | Cause |
|---|---|
| `403 no_registration` | this device is not registered in this Workspace |
| `403 no_live_grant` | no live permission here |

---

## 9. What the server can and cannot learn

Worth stating plainly, because it is the thing being bought — and because the list
grew when Workspaces became shareable, in the direction that matters most.

**It can see:**

- how many ops exist, when each one arrived, and which device wrote it
- how ops group into Workspaces
- roughly how large each payload is, to the nearest size class
- which devices are registered in which Workspace — and **which of them one identity
  holds**, because `holder_ref` groups them ([Authority](03-authority.md))
- who holds which permissions, and every change: grants, revokes, delegations
- when keys were rotated
- which vault slots share a pinned Root, and so belong to one identity (§7)

**And one thing more, once reprising starts:** a prune op names the ops it reprises,
so the server learns that those ops belong together — without learning what they are.
If a client folds one record at a time, that is a partition of the history into
per-record groups. It is a client design choice rather than a protocol property, and
the trade-offs are set out under
[a prune discloses a grouping](01-the-log.md#guidance--a-prune-discloses-a-grouping).

**It cannot see:** anything any content op says, any reprise op's contents, any epoch
key, Root, the master wrap key, the wrapping secret, or anything the client derived
on the way to it.

**It cannot know who anybody is.** Every identity it handles is 32 bytes. Nothing in
this protocol maps a public key to a name, an address or a person, and no certificate
may carry one ([Authority](03-authority.md)). It also cannot tell how strong the
secret behind a locator is.

**It cannot do:** forge a signature, grant a permission, add or remove a device from a
wrap set, or read a body — even holding the entire database.

### What it adds up to

For one identity with three devices the metadata is thin. Across two hundred
identities sharing Workspaces, the same fields compose into something else, and it is
better to say so than to let somebody discover it:

```
   registrations over time            joiners
   revocations, and when              leavers, and how abruptly
   co-membership across Workspaces    who works with whom
   op timestamps per device           when people work, and when they stopped
   op volume per Workspace            which projects are alive
   who holds owner or a delegation    where authority actually sits
   a burst of both at once            a reorganisation, or an acquisition
```

None of that is content. All of it is an org chart with a clock attached.

**One join is worth naming on its own**, and it is the one thing on this list a
profile can take away. Under a profile whose `holder_ref` is the holder's Root — the
obvious choice — it is the same 32 bytes the vault slot pins, so the two tables join:
*the identity behind this vault slot is a member of those Workspaces.* That crosses
the key plane and the log plane, which nothing else in this design does.

A profile whose `holder_ref` the server cannot reverse closes it
([Authority](03-authority.md)) — but only if devices also register under a **fresh
identity per Workspace**, because a device's three public keys are otherwise the same
bytes everywhere it joins and rebuild the join by themselves. Both halves or neither;
one alone changes nothing.

### Holding the keys does not withhold the metadata

None of the above depends on who holds a key. It is what the server sees by doing its
job: it cannot order ops without watching them arrive, refuse a write without knowing
who may write, or serve a page without knowing which Workspace it belongs to.
Metadata is not a leak in this design — it is the working material.

> Worth stating because the inference runs the other way so naturally. *We hold every
> key* is a claim about confidentiality and says nothing about the list above, and a
> deployment that reaches from one to "end to end encrypted" has described its content
> accurately and its exposure not at all.

### What can be reduced

> **Non-normative.** None of this is a requirement on anyone, and a deployment that
> ignores all of it is conformant.

Not much, honestly, and the short list is short for a reason:

- **size** is already blurred by the padding ladder, which is coarse on purpose
- **timing** blurs if a client batches rather than writing through
- **grouping** shrinks if reprises fold larger sets, or if the client never folds
- **cross-Workspace identity** is the one entry that can be removed rather than
  blurred — an unreversible `holder_ref` and a fresh device identity per Workspace,
  together — and it costs a profile row and a keypair per Workspace per device
- **everything else** goes away only by not sharing a server with an observer you
  care about

Availability and metadata are **not protected here**. Confidentiality and
authenticity are. A design claiming otherwise would be claiming something no server
that orders bytes can deliver.

---

## Next

[Compatibility](05-compatibility.md): how all of this is allowed to change without
breaking a device that has been in a drawer for two years.
