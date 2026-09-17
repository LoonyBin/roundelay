# Roundelay — implementation

A **content-blind, append-only, signed op-log sync server**.

Devices write to their own local store and keep working offline. Every change is
described as an **op** — small, signed, usually encrypted — and appended to a
shared log. Other devices pull the log and replay it. The server in the middle
stores the log and hands it back in order. It cannot read what most ops say, does
not know what the application is about, and is trusted with nothing except keeping
and ordering bytes.

This branch is the Go server, the Dart reference client, the frozen vectors and
the conformance suite. **The specification is not here.** It is on
[`main`](https://github.com/LoonyBin/roundelay/tree/main), and this branch reads
it rather than keeping a copy.

---

## The spec lives on `main`

Both branches used to carry the document, and they drifted. `main` described 194
conformance items and 117 refusal codes while everything here was checked against
a private copy describing 250 and 125 — so every green result on this branch was
a fact about a document the canonical branch did not contain.

So: one copy, on `main`, and [`spec.lock`](spec.lock) says where to get it.

```
make spec
```

fetches the eleven files into this tree at the paths they have on `main` —
`docs/…` and `conformance/checklist.yaml`. They are listed in
[`.gitignore`](.gitignore) and are never committed here. Same paths deliberately:
the checklist cites `docs/…` in every one of its items, and those citations have
to resolve on both branches.

Run it once after cloning. `make check` will tell you if you have not:

```
spec-sync: the specification is not in this tree (11 of 11 files missing).
spec-sync: it lives on 'main' and is not committed here. Run: make spec
```

`spec.lock` names a branch rather than a commit, so CI here is always deciding
this implementation against the current spec. A change on `main` that this
branch does not satisfy turns it red. That is the point: a pin nobody advances
is a fork with extra steps.

**Changing the spec means opening a PR against `main`.** Changing it here is not
possible any more, which is the other half of the point.

---

## Reading the spec

After `make spec`, **→ [docs/README.md](docs/README.md)** tells the whole story
in about ten minutes. The five layers are in dependency order; each only needs
the ones above it.

| Document | Answers |
|---|---|
| [The Log](docs/01-the-log.md) | What is an op? What is a Workspace? How do I write and read? |
| [Identity](docs/02-identity.md) | What is the identity? Who is a device? How does each prove it? |
| [Authority](docs/03-authority.md) | Who decides what a device may write, and how is that recorded? |
| [Keys](docs/04-keys.md) | What is signed, what is encrypted, and who holds which key? |
| [Compatibility](docs/05-compatibility.md) | What happens when a device is two years older than the server? |

Reference material: [refusal codes](docs/reference/refusal-codes.md),
[glossary](docs/reference/glossary.md), [retained
state](docs/reference/retained-state.md), [profile
obligations](docs/reference/profile-obligations.md), and the
[checklist](conformance/checklist.yaml) — 250 machine-readable items.

Those links resolve once you have run `make spec`. On the web, read them
[on `main`](https://github.com/LoonyBin/roundelay/tree/main/docs).

---

## Layout

| Path | What it is |
|---|---|
| `cmd/`, `httpapi/`, `wire/` | The server: entry point, routes, envelope encoding |
| `oplog/`, `authority/`, `keyplane/`, `identity/`, `signal/` | The layers, one package per spec document |
| `profile/` | The eleven decisions a deployment makes. No defaults |
| `codes/` | The refusal vocabulary, generated from `docs/reference/refusal-codes.md` |
| `pgstore/`, `internal/memstore/` | The two stores |
| `vectors/` | The frozen cross-implementation corpus |
| `clients/dart/` | The reference client — a second implementation, deliberately not a port |
| `tests/conformance/` | The black-box suite, in Python, against a server it starts itself |
| `internal/conformance/` | The lints, and the checklist ↔ test bindings |

---

## Building and checking

```
make spec        # fetch the specification from main — do this first
make check       # what CI runs: gofmt, vet, tests, lints, generated-artefact drift
make test        # go test ./...
make pg-up       # a Postgres for the store's tests, on 55432
make pg-test     # the store's tests, which skip silently without a DSN
make generate    # regenerate vectors/ and codes/ from their sources
```

The conformance suite needs Python and a running server; CI runs it
Postgres-backed. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for
the exact invocation — it is the command a developer runs, not a variant of it.

Five lints hold over the checklist and `make check` runs all of them:
**structure**, **coverage**, **vocabulary**, **observability** and **bindings**.
Cite item ids in review: *"this loosens `CONF-LOG-014`"*.

---

## Licence

Copyright © 2026 LoonyBin. Two licences, because a specification and a program
are not the same kind of thing.

**Everything on this branch is [AGPL-3.0-only](LICENSE)** — the Go server, the
Dart client, the conformance suite and its bindings, and the frozen vectors in
[`vectors/`](vectors/). Run it, read it, change it, pass it on; if you pass on a
changed version, or run one where other people can reach it over a network, your
changes go back out under the same licence. For a sync server the network clause
is the one that bites: hosting a modified roundelay for others counts, even if
you never ship a binary. Vendoring the checklist or the vectors into your own
implementation carries that obligation into it.

**The specification is [CC BY-ND 4.0](LICENSE-DOCS)** and lives on `main`. The
files `make spec` writes into this tree are under that licence, not this
branch's — which is one more reason they are not committed here. Read them,
quote them, mirror them, for any purpose including a commercial one, as long as
you credit them; what you may not publish is a *changed* version.

Implementing the spec is not changing it. Build whatever you like from those
documents — any language, any product, closed source or open — and the ND term
never reaches your code.

So: the spec is free to implement, and the code and test material are copyleft.
If you want the checklist or the vectors under other terms — because you are
shipping an independent implementation under a licence of your own — ask. That
is a conversation, not a refusal.
