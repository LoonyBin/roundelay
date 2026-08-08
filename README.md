# Roundelay

A **content-blind, append-only, signed op-log sync server**.

Devices write to their own local store and keep working offline. Every change is
described as an **op** — small, signed, usually encrypted — and appended to a
shared log. Other devices pull the log and replay it. The server in the middle
stores the log and hands it back in order. It cannot read what most ops say, does
not know what the application is about, and is trusted with nothing except keeping
and ordering bytes.

Any application that needs multi-device convergence over data the server must not
read can run it unchanged.

---

## Start here

**→ [docs/README.md](docs/README.md)** tells the whole story in about ten minutes.

The specification is five layers, in dependency order. Each one only needs the
ones above it.

| Document | Answers |
|---|---|
| [The Log](docs/01-the-log.md) | What is an op? What is a Workspace? How do I write and read? |
| [Identity](docs/02-identity.md) | What is the identity? Who is a device? How does each prove it? |
| [Authority](docs/03-authority.md) | Who decides what a device may write, and how is that recorded? |
| [Keys](docs/04-keys.md) | What is signed, what is encrypted, and who holds which key? |
| [Compatibility](docs/05-compatibility.md) | What happens when a device is two years older than the server? |

Reference material, kept out of the narrative:

- [Refusal codes](docs/reference/refusal-codes.md) — all 117, with cause and whether a retry helps
- [Glossary](docs/reference/glossary.md)
- [Retained state](docs/reference/retained-state.md) — what a server must remember
- [Profile obligations](docs/reference/profile-obligations.md) — the eleven decisions a deployment makes
- [Conformance](conformance/checklist.yaml) — 194 machine-readable items

---

## Core plus profile

A running server is **core plus exactly one profile**. The core defines the
transport, the trust model and the refusal vocabulary. The profile supplies what is
genuinely a product decision: the protocol namespace, the Workspace topology, the
where admission is enforced, the role table, the member kinds, and a handful of tuned
constants.

There are **no defaults**. A server refuses to start with any profile decision
unset, because a silent default there is either a security hole or a convergence
bug.

> Two servers on different profiles are different protocols that happen to share a
> shape. By design, they cannot verify each other's signatures at all.

A profile is filled in row by row under [profile
obligations](docs/reference/profile-obligations.md). Profiles ship in their own
repositories; this one defines the core and nothing else.

---

## Seven things worth knowing before you read further

**The server verifies far less than it stores.** It never checks envelope
signatures or author chains — those belong to the device that pulls, because only
that device knows which keys it has decided to trust. A server that "helpfully"
verified would reject ops every conforming server accepts.

**One bit decides what the server may read.** Bit 7 of the class byte: set, and the
server unpacks the body — permissions and housekeeping, never application data.
Clear, and the body is bytes it has no key for, for ever, by construction rather
than by a table it might misread.

**The server is authoritative for nobody.** Its index exists to refuse writes
cheaply. The signed log is the truth, and every device works out permissions for
itself by replaying it. Tampering with server state cannot elevate anyone.

**The identity is a keypair, not an account.** There is no identity provider and no
user record. A Workspace's id derives from the public key of the Root that founded
it, and Root itself lives wrapped in a vault slot the server cannot open. Every
identity it handles is 32 bytes; nothing here maps one to a person.

**Metadata is not protected, and at scale it is an org chart.** The server sees when
each op arrived, which device wrote it, which identity holds that device, who was
granted what and when it was taken away. None of it is content; all of it composes.
Holding every key yourself moves confidentiality and moves none of this — [Keys
§9](docs/04-keys.md) says exactly what is and is not bought.

**Refusal codes are protocol.** A code may not be narrowed, merged, or invented
locally, and a client that meets an unfamiliar one surfaces it verbatim.

**Skew is permanent, not a deploy window.** Contract versions on the path, unknown
fields refused rather than dropped, deterministic refusals terminalised rather than
retried for ever.

---

## Conformance

Two lints hold over the checklist, and a conforming release runs both:

- **coverage** — every code in the [code list](docs/reference/refusal-codes.md)
  appears in some item's `codes`
- **observability** — every `black-box` item is decidable from HTTP and WebSocket
  traffic alone

Both currently pass. Cite item ids in review: *"this loosens `CONF-LOG-014`"*.
