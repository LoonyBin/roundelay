package keyplane

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
)

// Slot is one vault record.
//
// A slot is keyed by locator alone: it has no owner and no Workspace. It is not
// thereby unlinkable — two slots holding the same Root under different secrets
// carry the same pinned Root public key, so grouping on that column returns
// every wrapping of one identity. That is a consequence of the pin, not of the
// key, and it cannot be removed without removing the pin.
type Slot struct {
	Locator [32]byte
	Version int64
	Blob    []byte
	Sig     [64]byte
	// PinnedRoot is what every later write is verified against. It is not
	// write-once: it moves when a write carries a different root_pk and is
	// signed by the key currently pinned — the vault's half of a root handover.
	PinnedRoot [32]byte
}

// VaultStore is the vault's own state. None of it is in the log.
type VaultStore interface {
	Slot(ctx context.Context, locator [32]byte) (*Slot, bool, error)
	// PutSlot writes a slot. expectedVersion is what the caller read; a store
	// must refuse the write if it has moved, so that concurrent writes resolve
	// with exactly one winner.
	PutSlot(ctx context.Context, s Slot, expectedVersion int64) (bool, error)

	// RootHasWorkspace reports whether at least one Workspace has this key as its
	// current Root.
	RootHasWorkspace(ctx context.Context, root [32]byte) (bool, error)

	// RecordFetch appends to the fetch audit. It is called before the bytes
	// leave: a silent read is exactly what an attack on this slot needs, and a
	// slot with no record is a slot whose reads nobody can ever account for.
	RecordFetch(ctx context.Context, locator [32]byte, at time.Time) error

	// CountFetch is the fixed-window limit, per locator.
	CountFetch(ctx context.Context, locator [32]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error)
}

// VaultWrite is the decoded PUT body.
type VaultWrite struct {
	Version int64
	Blob    []byte
	Sig     [64]byte
	RootPK  [32]byte
}

// Vault serves the two unauthenticated vault routes.
type Vault struct {
	Profile *profile.Profile
	Store   VaultStore
	Now     func() time.Time
}

func (v *Vault) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Write stores a record.
//
// The locator gets the request to the slot. The Root signature gets it into the
// slot. That is the whole design in one sentence.
func (v *Vault) Write(ctx context.Context, locator [32]byte, w *VaultWrite) (*Slot, *oplog.Refusal) {
	existing, found, err := v.Store.Slot(ctx, locator)
	if err != nil {
		return nil, storeDown()
	}

	stored := int64(0)
	if found {
		stored = existing.Version
	}
	// A first write must be version 1, not merely above the zero that stands for
	// "nothing stored". The looser reading — one rule, strictly greater than
	// stored — admits a slot created at version 17, and every client that later
	// reasons about how many times a slot has been written is then reasoning
	// about a number the first writer chose.
	//
	// stored_version is 0 in that case, so the two rules still report through one
	// field: a client sees what is there and writes one above it.
	if w.Version <= stored || (!found && w.Version != 1) {
		return nil, refuse(http.StatusConflict, codes.VaultVersionRegression,
			map[string]any{"stored_version": stored})
	}

	// A first write establishes root_pk for the slot and is checked against the
	// key it carries — trust on first use. Every later write is checked against
	// the pinned key, and only the retiring Root can hand the slot on.
	against := w.RootPK
	if found {
		against = existing.PinnedRoot
	}
	if !found {
		// A precondition rather than a second gate: it costs nothing to check and
		// removes a state that never meant anything — a vault holding an identity
		// that owns nothing. A caller who was not admitted never got a token,
		// never posted a genesis, and so has no Workspace and no slot to open.
		ok, err := v.Store.RootHasWorkspace(ctx, w.RootPK)
		if err != nil {
			return nil, storeDown()
		}
		if !ok {
			return nil, refuse(http.StatusForbidden, codes.VaultRequiresGenesis, nil)
		}
	}

	input := v.Profile.Namespace.VaultInput(locator, uint64(w.Version), w.Blob)
	if !ed25519.Verify(ed25519.PublicKey(against[:]), input, w.Sig[:]) {
		// 403 rather than 422: the caller cannot prove control of the slot at
		// all, which is an authorisation failure of the whole request rather than
		// a malformed field.
		return nil, refuse(http.StatusForbidden, codes.BadVaultSignature, nil)
	}

	slot := Slot{Locator: locator, Version: w.Version, Blob: w.Blob, Sig: w.Sig, PinnedRoot: w.RootPK}
	won, err := v.Store.PutSlot(ctx, slot, stored)
	if err != nil {
		return nil, storeDown()
	}
	if !won {
		// Concurrent writes resolve with exactly one winner; the loser learns
		// what the slot now holds rather than silently overwriting.
		current, _, err := v.Store.Slot(ctx, locator)
		if err != nil || current == nil {
			return nil, storeDown()
		}
		return nil, refuse(http.StatusConflict, codes.VaultVersionRegression,
			map[string]any{"stored_version": current.Version})
	}
	return &slot, nil
}

// Read serves a record verbatim.
//
// It takes no body and no parameters: nothing derived from the wrapping secret
// ever reaches the server, so there is nothing to accept.
func (v *Vault) Read(ctx context.Context, locator [32]byte) (*Slot, *oplog.Refusal) {
	now := v.now()

	// Existence is checked before the quota is spent. The limit bounds bytes
	// leaving the slot, and a slot holding nothing must not be able to burn it —
	// otherwise twenty pointless requests lock out the one fetch that matters.
	slot, found, err := v.Store.Slot(ctx, locator)
	if err != nil {
		return nil, storeDown()
	}
	if !found {
		return nil, refuse(http.StatusNotFound, codes.NoVaultRecord, nil)
	}

	ok, retry, err := v.Store.CountFetch(ctx, locator, now,
		v.Profile.Limits.VaultFetchWindow, v.Profile.Limits.VaultFetchesPerWindow)
	if err != nil {
		return nil, storeDown()
	}
	if !ok {
		return nil, refuse(http.StatusTooManyRequests, codes.VaultFetchRateLimited,
			map[string]any{"retry_after_seconds": int(retry.Round(time.Second).Seconds())})
	}

	// Durably, before the bytes leave. Neither the limit nor the audit is
	// conditional on anything: there is no signal available that would justify
	// relaxing them.
	if err := v.Store.RecordFetch(ctx, locator, now); err != nil {
		return nil, storeDown()
	}
	return slot, nil
}
