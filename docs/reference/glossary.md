# Reference — Glossary

Capitalised when naming the concept; lowercase inside identifiers, wire values and
code names.

**admission** — the server's decision, taken once per identity at the registration of
its founding device, that this caller may exist here at all. Which branch a
`POST /v1/members` takes is decided by its certificate type: `workspace_genesis`
means founding and is gated, `member_register` means joining and is not. The core
fixes only the carrier — a
`Roundelay-Admission` header holding an opaque string — never the mechanism or the
format; the profile declares only where the gate lives.
[Identity](../02-identity.md)

**advisory control type** — a control type whose name begins `note_`, reserved for ever. It
bears no authority and alters no derived state, so a reader that does not serve one
hash-chains past it without interpreting it and keeps answering for later positions.
Every other type is **load-bearing**; v1 defines no advisory type, and no load-bearing
type may ever be named `note_*`. [Authority](../03-authority.md)

**author position** — `author_seq`. An op's 1-based, gap-free position within its own
author's chain, per Workspace. Not the transport position.
[The Log](../01-the-log.md)

**authority role** — the role named `owner`: the only role that may author
non-Root-signed control ops, and the only one whose grants require root authority
(Authority §6) to create or revoke. [Authority](../03-authority.md)

**bar** — one of the two authorisation tiers: member-GET, or member plus a live
grant. [Authority](../03-authority.md)

**chained** — of a device: having a registration signed under root authority accepted
into the log. A shell that has none confers no authority. [Identity](../02-identity.md)

**class byte** — the byte at header offset 0. Bit 7 says whether the server reads the
body; bit 6 says whether the value is defined outside the core; the low six select
within the resulting quadrant. [The Log](../01-the-log.md)

**content signing key** — `content_pk`. The device key that signs opaque-class
envelopes, used constantly. [Authority](../03-authority.md)

**control signing key** — `control_pk`. The device key that signs server-read
envelopes and the auth challenge, used occasionally.
[Authority](../03-authority.md)

**content key** — `K(w, epoch)`. 32 random bytes that seal one Workspace's opaque
bodies at one epoch, where they are sealed at all. An unkeyed Workspace has none.
[Keys](../04-keys.md)

**control op** — class `0x80`. Server-read, and the permission record. Ten types in v1,
every one of them load-bearing; a type named `note_*` is *advisory* instead, and v1
names none. [Authority](../03-authority.md)

**control chain** — the one chain of control payloads a Workspace has, enforced by the
server. Every non-genesis payload links the previous by a hash of its bytes —
SHA-256 under the v1 suites; the function is the linking op's suite's
([Compatibility](../05-compatibility.md)) —
(`prev_control_hash`); only the genesis has none. The **control tip** is the latest
accepted payload's hash — derived when asked, never stored. A reader verifies the
chain unbroken from genesis; a break is a truncated or tampered history, not a gap to
skip. [Authority](../03-authority.md)

**current Root** — the Root a Workspace's certificates are verified against now.
Equal to the founding Root until a root handover moves it.
[Authority](../03-authority.md)

**delegation** — a Root-signed statement that some other key may exercise **root
authority** — registrations, grants, revokes — from that op's position. Never
genesis, handover or the vault. Disposable: it has no recovery path, because Root
mints another. [Authority](../03-authority.md)

**digest** — `keywrap_digest`. The commitment a rotate op makes to a whole wrap set
before any wrap is uploaded. [Keys](../04-keys.md)

**envelope** — the complete signed byte string: header, body, signature.
[The Log](../01-the-log.md)

**envelope hash** — bare SHA-256 (under the v1 suites; the function follows the
referencing op's suite) over the complete envelope bytes,
`header || body || signature`, nothing prefixed or re-serialised. What
`prev_author_hash` and a prune target's attestation carry.
[The Log](../01-the-log.md)

**epoch** — `key_epoch`. The generation of a Workspace's content key. Monotonic,
single-step, never reused. [Keys](../04-keys.md)

**ext_binding** — class `0xBF`. A member's signed assertion of what an extension
class means to it, refused if it disagrees with the server. Not a permission — a
semantic handshake, scoped to `(Workspace, member, class)`.
[The Log](../01-the-log.md)

**extension class** — a server-read class in `0xC0–0xFF`, defined by an
implementation, enabled by the profile, bound per member by an `ext_binding`.
Disabled by default, and foldable by `prune_ext` and by nothing else.
[The Log](../01-the-log.md)

**founding Root** — the Root that authored a Workspace's genesis. Its public key is
what a Workspace id is bound to at genesis, so it never changes.
[Authority](../03-authority.md)

**grant** — a signed statement that a device holds a role in a Workspace.
Grant-granular: a device may hold several, and a revoke names exactly one.
[Authority](../03-authority.md)

**HLC** — the logical clock inside signed documents: `[wall_ms, counter,
member_id_hex]`. The server stores it and never orders by it.

**locator** — 32 bytes naming a vault slot. Derived on the device from the user's
credential, by a construction the core does not define. Knowing it is the only claim
a read requires. [Keys](../04-keys.md)

**master wrap key** — 32 bytes, one per identity. At rest on the server it exists
only inside the vault record; whether a client keeps it warm between ceremonies is
custody policy. Opens every epoch's escrow wrap. [Keys](../04-keys.md)

**Member** — a device, identified by a signing keypair, introduced by a Root-signed
registration. The only thing that authors ops. [Identity](../02-identity.md)

**member kind** — a profile-declared token on every registration, saying what sort of
member this is. The core knows only that the tokens exist.
[Authority](../03-authority.md)

**member_amend** — the control type that replaces the keys a device holds — any subset
of `control`, `content`, `kex`, at least one. Signed under root authority, so a live
delegate may issue one, and **per Workspace** like the registration it amends. A
replaced key stops signing from that op's position and keeps verifying its own older
ops for ever. [Authority](../03-authority.md)

**op** — one record of change, authored by one device: signed, usually sealed,
immutable. [The Log](../01-the-log.md)

**op class** — a value of the *class byte*. Bit 7 decides how the server handles the
op; within a quadrant the value decides only who may author one.
[The Log](../01-the-log.md)

**opaque class** — any class with bit 7 clear: `0x00–0x7F`. Never unpacked by the
server, sealed under the content key where the Workspace is keyed, eligible as a
prune target.
[The Log](../01-the-log.md)

**poke** — the empty text frame on the signal socket, meaning "sync from your cursor
now". [The Log](../01-the-log.md)

**profile** — the per-deployment policy layer the core requires.
[Profile obligations](profile-obligations.md)

**prune op** — class `0x81`. Server-read, and self-identifying by a mandatory `type`.
Three in v1: `prune` attests which ops a reprise stands in for, `prune_ext` folds one
extension class, and `hard_prune` reclaims the bytes of whatever either mark reached.
[The Log](../01-the-log.md)

**prune_ext** — the `0x81` payload type that folds an **extension class**, naming the
class and the NAME its targets were written under. One class and one name per op; it
reaches that class and nothing else, the name is checked per target against the NAME in
force for that target's author *there*, and no reprise stands behind it.
[The Log](../01-the-log.md)

**access gate** — the check, on every Workspace-scoped device route, that this device
holds an accepted registration in this Workspace. A fact in the log, never a profile
decision. [Authority](../03-authority.md)

**creation policy** — the profile predicate deciding which Workspace ids a given Root
may bring into being. Asked at genesis and nowhere else.
[Authority](../03-authority.md)

**holder** — `holder_ref`. The identity that holds a device, named in its registration
beside the Workspace Root that signed it, as 32 opaque bytes whose derivation is a
profile row. Attribution only: it grants nothing, the server never interprets it, and
the core promises only that equal bytes mean one identity *within one Workspace*.
[Authority](../03-authority.md)

**reprise op** — class `0x02`. Holds the combined effect of the ops folded into it,
stated again. Opaque: the server treats it exactly as content and never reads it. Its
two variants — reclaiming storage, and restating in a newer payload encoding — are
one operation here; which was meant lives in the payload.
[The Log](../01-the-log.md)

**reprised** — the state of an op named by an accepted `prune` or `prune_ext`: hidden
from ordinary reads, still served by `include_reprised=true`. Nothing distinguishes the
two marks. Reversible, and the only state from which a `hard prune` may destroy the
bytes.

**hard prune** — the `0x81` payload type that destroys a reprised op's envelope bytes,
leaving a tombstone. The one irreversible operation in the protocol, conferred only by
a role entry that names it. [The Log](../01-the-log.md)

**role table** — the role tokens a Workspace recognises and, for each, which op classes
and which `0x81` payload types they permit. The profile supplies the initial one; from
the first `role_table` op onward the log supplies it instead. **Positional**: the table
in force at a position is the one carried by the latest `role_table` op strictly below
it. [Authority](../03-authority.md)

**role_table** — the control type that installs one. A **complete replacement**, never a
patch; signed by the current Root itself and never by a delegate, so it needs no grant;
and it re-judges nothing already in the log. [Authority](../03-authority.md)

**Root** — the identity: an Ed25519 keypair whose public key names the Workspaces it
founded. Signs certificates; never authenticates; never appears in a header. Not a
credential. [Authority](../03-authority.md)

**root authority** — the signing authority a Workspace's control documents verify
under: its current Root, or a delegation live at the relevant point — positional at
that op's position on the append path, live as the route evaluates the request at
`POST /v1/members`. What "Root-signed" means, said of a control payload, and the
permission bypass carries with it. Genesis, handover, the role table and the vault are
never delegable, so there root authority is the current Root alone.
[Authority §6](../03-authority.md#6-delegation-keeping-root-cold)

**root handover** — the control op that moves a Workspace's current Root to a new
key, signed by the key it retires. [Authority](../03-authority.md)

**served set** — one of the five sets that say what an implementation understands:
suites, op classes, control types, prune types, `ext_binding` types. Anything outside
fails closed. `GET /health` advertises four of them under `served_sets` — every set but
`ext_binding` types — and names the enabled extension classes under
`extension_classes`. [Compatibility](../05-compatibility.md)

**shell** — a device record created by `POST /v1/members` whose registration has not
yet been accepted into the log. Confers nothing.
[Identity](../02-identity.md)

**size class** — a legal padded body length. [The Log](../01-the-log.md)

**tombstone** — what survives an accepted hard prune: every per-op fact, the envelope
hash included, and none of the bytes. Uniqueness still refuses a resurrection,
positions stay stable, the gap stays auditable, and a later attestation stays
checkable. [The Log](../01-the-log.md)

**transport position** — `seq`. An op's position in its Workspace's log. A cursor
only: never causality, never a merge input, never evidence.
[The Log](../01-the-log.md)

**vault** — the slot holding Root and the master wrap key, sealed under the wrapping
secret. Addressed by locator, not by Workspace: one identity has one vault, however
many Workspaces it founded. [Keys](../04-keys.md)

**Workspace** — the partition unit: one log, one grant set, one epoch sequence.
[The Log](../01-the-log.md)


**wrap** — a content key sealed either to a device's sealing key (*member wrap*) or
under the master wrap key (*escrow wrap*). [Keys](../04-keys.md)

**wrapping secret** — 32 bytes derived on the device from the user's credential, and
the only thing that opens a vault blob. Never transmitted, never stored, in any form.
[Keys](../04-keys.md)
