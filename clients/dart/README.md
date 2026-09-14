# roundelay — Dart reference client

The client-side counterpart to the reference server, in pure Dart.

## Why this exists

The protocol's central security property is enforced on the client and nowhere
else, **by design**:

> `CONF-CLI-001` — a client verifies every pulled envelope's Ed25519 signature
> and refuses on failure.

The server deliberately does not verify envelope signatures or author chains.
That is a stated commitment in [`docs/01-the-log.md`](../../docs/01-the-log.md),
not an omission — verification belongs to the pulling device, because only it
knows which keys it trusts. The consequence is that until there was a client,
the property was tested by nothing on either side of the wire, and the 30
`subject: client` items in [`conformance/checklist.yaml`](../../conformance/checklist.yaml)
had nothing to bind to.

## What is implemented

This is the first slice — the wire layer and verification:

| Construction | Vector |
|---|---|
| `framed(domain, rest)`, including the collision pair the length prefix exists for | `framing.json` |
| `key_id` derivation | `keyid.json` |
| `uuid8(NS, root_pk)` — derived Workspace ids | `uuid8.json` |
| the padding ladder, legal body lengths, the envelope length floor | `body.json` |
| which domain each class byte signs under | `domains.json` |
| the 158-byte header, the signing input, the envelope hash, the control-chain link | `envelope.json` |
| Ed25519 verification and refusal — `CONF-CLI-001` | `envelope.json` |

**Not yet implemented:** the key plane (member and escrow wraps, `keywrap_digest`,
XChaCha20-Poly1305 sealing), the author chain (`CONF-CLI-002`), authority and
certificate validation, and the HTTP client. `keyplane.json` and `auth.json`
are unbound.

## A third implementation, not a port

Written from `docs/`, not ported from `wire/` and not from
[`tests/conformance/roundelay/`](../../tests/conformance/). That is the same
choice `crypto.py` documents and for the same reason: an implementation that
shared a codec with the others could not catch a framing bug, because the error
would cancel out everywhere and every test would still pass. What proves
something is independent implementations agreeing on the frozen corpus.

Ed25519 and SHA-256 come from packages, as they do in the Python suite. The
constructions *above* the primitives — framing, the header layout, the ladder,
the domain rules — are written here.

## Running the tests

The tests read `vectors/` from the repository root, so they must run with this
directory as the working directory:

```
cd clients/dart
dart pub get
dart test
```

**No machine in this fleet can run them.** The aarch64 hosts have no Dart
release; the x86_64 macOS host's SDK refuses to start on macOS 12, a floor
compiled into the binary. Note that `dart --version` *succeeds* there — it
answers before the VM initialises — so it is not a check that the toolchain
works. `.github/workflows/dart-ci.yml` is the verification path.
