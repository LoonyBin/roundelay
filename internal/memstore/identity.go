package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/keyplane"
)

// Identity is the in-memory half of the store that authentication needs.
//
// It is deliberately a separate type from Store: none of this is in the log,
// none of it is authoritative for anything, and a replacement rebuilt from the
// log is complete without it.
type Identity struct {
	mu sync.Mutex

	devices    map[[16]byte]identity.Device
	challenges map[[16]byte]pendingChallenge
	windows    map[[16]byte]rateWindow
	refresh    map[[32]byte]refreshRow

	// log is consulted for the two questions that cross into the Workspace
	// plane: whether a registration has been accepted anywhere, and which
	// control keys are in force.
	log *Store
}

type pendingChallenge struct {
	nonce   [32]byte
	expires time.Time
}

type rateWindow struct {
	opened time.Time
	count  int
}

type refreshRow struct {
	member  [16]byte
	expires time.Time
}

// NewIdentity returns an empty identity store over a log store.
func NewIdentity(log *Store) *Identity {
	return &Identity{
		devices:    map[[16]byte]identity.Device{},
		challenges: map[[16]byte]pendingChallenge{},
		windows:    map[[16]byte]rateWindow{},
		refresh:    map[[32]byte]refreshRow{},
		log:        log,
	}
}

var _ identity.Store = (*Identity)(nil)

func (i *Identity) Device(_ context.Context, id [16]byte) (*identity.Device, bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d, ok := i.devices[id]
	if !ok {
		return nil, false, nil
	}
	return &d, true, nil
}

func (i *Identity) PutDevice(_ context.Context, d identity.Device) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.devices[d.MemberID] = d
	return nil
}

// ChainedAnywhere scans every Workspace, because a registration is per Workspace
// and this question is not.
func (i *Identity) ChainedAnywhere(_ context.Context, id [16]byte) (bool, error) {
	i.log.mu.Lock()
	defer i.log.mu.Unlock()
	for _, w := range i.log.ws {
		w.mu.Lock()
		_, ok := w.st.members[id]
		w.mu.Unlock()
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ControlKeysInForce is a union over every Workspace this device is registered
// in, materialised as the route evaluates and authoritative for nobody.
//
// The per-device row and the per-Workspace rows are not alternatives: the
// registered key is what a shell has and where every interval starts, and the
// per-Workspace intervals are what an envelope at a position resolves against.
// So a device registered nowhere falls back to its shell — which it must, or the
// founding ceremony could not begin: posting a genesis needs a token, a token
// needs a member record, and the member record is all a founder has before its
// own genesis lands.
func (i *Identity) ControlKeysInForce(ctx context.Context, id [16]byte) ([][32]byte, error) {
	i.log.mu.Lock()
	var out [][32]byte
	seen := map[[32]byte]bool{}
	registered := false
	for _, w := range i.log.ws {
		w.mu.Lock()
		if _, ok := w.st.members[id]; ok {
			registered = true
		}
		for _, iv := range w.st.controlKeys[id] {
			if iv.end == 0 && !seen[iv.pk] {
				seen[iv.pk] = true
				out = append(out, iv.pk)
			}
		}
		w.mu.Unlock()
	}
	i.log.mu.Unlock()

	if registered {
		// A key amended away in every Workspace stops obtaining tokens.
		return out, nil
	}
	d, ok, err := i.Device(ctx, id)
	if err != nil || !ok {
		return out, err
	}
	return append(out, d.ControlPK), nil
}

func (i *Identity) PutChallenge(_ context.Context, member [16]byte, nonce [32]byte, expires time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	// Single-use and short-lived. One pending challenge per device, so a second
	// request replaces the first rather than widening the guessing surface.
	i.challenges[member] = pendingChallenge{nonce: nonce, expires: expires}
	return nil
}

func (i *Identity) TakeChallenge(_ context.Context, member [16]byte, now time.Time) ([32]byte, bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	c, ok := i.challenges[member]
	delete(i.challenges, member)
	if !ok || !now.Before(c.expires) {
		return [32]byte{}, false, nil
	}
	return c.nonce, true, nil
}

// CountChallenge is fixed-window: the window opens at the first counted request
// and is not extended by later ones.
//
// Stated because the alternative — a sliding window — produces
// retry_after_seconds values an order of magnitude apart for the same nominal
// limit, and clients back off against the wrong one.
func (i *Identity) CountChallenge(_ context.Context, member [16]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	w, ok := i.windows[member]
	if !ok || !now.Before(w.opened.Add(window)) {
		i.windows[member] = rateWindow{opened: now, count: 1}
		return true, 0, nil
	}
	if w.count >= limit {
		// The remaining lifetime of the current window, rounded up.
		remaining := w.opened.Add(window).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		return false, remaining, nil
	}
	w.count++
	i.windows[member] = w
	return true, 0, nil
}

func (i *Identity) PutRefresh(_ context.Context, hash [32]byte, member [16]byte, expires time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.refresh[hash] = refreshRow{member: member, expires: expires}
	return nil
}

// TakeRefresh is single-use, and consumes only on success.
//
// The check and the delete are one atomic step: two concurrent refreshes of one
// token must not both succeed, and a failed attempt must leave the token where
// it was.
func (i *Identity) TakeRefresh(_ context.Context, hash [32]byte, member [16]byte, now time.Time) (bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	row, ok := i.refresh[hash]
	if !ok || row.member != member || !now.Before(row.expires) {
		return false, nil
	}
	delete(i.refresh, hash)
	return true, nil
}

func (i *Identity) RevokeRefreshFor(_ context.Context, member [16]byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	for h, row := range i.refresh {
		if row.member == member {
			delete(i.refresh, h)
		}
	}
	return nil
}

// LiveRefreshCount reports how many refresh tokens a device holds, for
// assertions.
func (i *Identity) LiveRefreshCount(member [16]byte) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	n := 0
	for _, row := range i.refresh {
		if row.member == member {
			n++
		}
	}
	return n
}

// ── the joining branch's lookup ─────────────────────────────────────────────

// Lookup answers POST /v1/members' joining branch from the Workspace plane.
type Lookup struct{ Log *Store }

// CurrentRoot reports the Workspace's current Root, and whether it exists.
func (l Lookup) CurrentRoot(_ context.Context, id [16]byte) ([32]byte, bool, error) {
	w := l.Log.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.st.exists {
		return [32]byte{}, false, nil
	}
	return w.st.root, w.st.hasRoot, nil
}

// LiveDelegations materialises the Workspace's live delegations as the route
// evaluates. The route occupies no position in the log, so this is the only
// question it can ask — and the append path re-asks it positionally when the
// certificate lands.
func (l Lookup) LiveDelegations(_ context.Context, id [16]byte) ([][32]byte, error) {
	w := l.Log.workspace(id)
	w.mu.Lock()
	defer w.mu.Unlock()
	var out [][32]byte
	for _, did := range w.st.delegationOrder {
		if d := w.st.delegations[did]; d.End == 0 {
			out = append(out, d.PK)
		}
	}
	return out, nil
}

// ── the vault ───────────────────────────────────────────────────────────────

// Vault is the in-memory vault store. Keyed by locator alone: a slot has no
// owner and no Workspace.
type Vault struct {
	mu     sync.Mutex
	slots  map[[32]byte]keyplane.Slot
	audit  []FetchRecord
	window map[[32]byte]rateWindow
	log    *Store
}

// FetchRecord is one row of the append-only fetch audit.
type FetchRecord struct {
	Locator [32]byte
	At      time.Time
}

// NewVault returns an empty vault over a log store, which it consults only to
// answer whether a Root has founded anything.
func NewVault(log *Store) *Vault {
	return &Vault{slots: map[[32]byte]keyplane.Slot{}, window: map[[32]byte]rateWindow{}, log: log}
}

var _ keyplane.VaultStore = (*Vault)(nil)

func (v *Vault) Slot(_ context.Context, locator [32]byte) (*keyplane.Slot, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.slots[locator]
	if !ok {
		return nil, false, nil
	}
	return &s, true, nil
}

// PutSlot writes iff the slot has not moved since the caller read it.
func (v *Vault) PutSlot(_ context.Context, s keyplane.Slot, expected int64) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	current := int64(0)
	if existing, ok := v.slots[s.Locator]; ok {
		current = existing.Version
	}
	if current != expected {
		return false, nil
	}
	v.slots[s.Locator] = s
	return true, nil
}

func (v *Vault) RootHasWorkspace(_ context.Context, root [32]byte) (bool, error) {
	v.log.mu.Lock()
	defer v.log.mu.Unlock()
	for _, w := range v.log.ws {
		w.mu.Lock()
		match := w.st.exists && w.st.hasRoot && w.st.root == root
		w.mu.Unlock()
		if match {
			return true, nil
		}
	}
	return false, nil
}

func (v *Vault) RecordFetch(_ context.Context, locator [32]byte, at time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.audit = append(v.audit, FetchRecord{Locator: locator, At: at})
	return nil
}

func (v *Vault) CountFetch(_ context.Context, locator [32]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	w, ok := v.window[locator]
	if !ok || !now.Before(w.opened.Add(window)) {
		v.window[locator] = rateWindow{opened: now, count: 1}
		return true, 0, nil
	}
	if w.count >= limit {
		remaining := w.opened.Add(window).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		return false, remaining, nil
	}
	w.count++
	v.window[locator] = w
	return true, 0, nil
}

// Audit returns the fetch trail, for assertions.
func (v *Vault) Audit() []FetchRecord {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]FetchRecord, len(v.audit))
	copy(out, v.audit)
	return out
}
