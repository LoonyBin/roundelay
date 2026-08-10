package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/keyplane"
)

// Identity is the Postgres half of the state authentication needs.
//
// None of it is in the log, nothing derives from it, and a replacement rebuilt
// from the log is complete without it — which is why it is a separate type over
// the same pool rather than more methods on the append transaction.
type Identity struct{ pool *pgxpool.Pool }

// NewIdentity returns an identity store over the same pool.
func NewIdentity(s *Store) *Identity { return &Identity{pool: s.pool} }

var _ identity.Store = (*Identity)(nil)

func (i *Identity) Device(ctx context.Context, id [16]byte) (*identity.Device, bool, error) {
	var (
		d            identity.Device
		mid, c, n, k []byte
	)
	err := i.pool.QueryRow(ctx,
		`select member_id, control_pk, content_pk, kex_pk from device where member_id = $1`,
		id[:]).Scan(&mid, &c, &n, &k)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d.MemberID = to16(mid)
	d.ControlPK = to32(c)
	d.ContentPK = to32(n)
	d.KexPK = to32(k)
	return &d, true, nil
}

// PutDevice only ever creates: a stored key is never replaced in place.
func (i *Identity) PutDevice(ctx context.Context, d identity.Device) error {
	_, err := i.pool.Exec(ctx,
		`insert into device (member_id, control_pk, content_pk, kex_pk) values ($1,$2,$3,$4)
		 on conflict (member_id) do nothing`,
		d.MemberID[:], d.ControlPK[:], d.ContentPK[:], d.KexPK[:])
	return err
}

// ChainedAnywhere asks the Workspace plane, because a registration is per
// Workspace and this question is not.
func (i *Identity) ChainedAnywhere(ctx context.Context, id [16]byte) (bool, error) {
	var n int
	err := i.pool.QueryRow(ctx, `select count(*) from member where member_id = $1`, id[:]).Scan(&n)
	return n > 0, err
}

// ControlKeysInForce is the union over every Workspace this device is registered
// in, materialised as the route evaluates and authoritative for nobody.
//
// A device registered nowhere falls back to its shell. It must: posting a
// genesis needs a token, a token needs a member record, and the member record is
// all a founder has before its own genesis lands. The per-device row is what a
// shell has and where every interval starts.
func (i *Identity) ControlKeysInForce(ctx context.Context, id [16]byte) ([][32]byte, error) {
	rows, err := i.pool.Query(ctx,
		`select distinct pk from key_interval
		 where member_id = $1 and key_name = 'control' and end_seq is null`, id[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][32]byte
	for rows.Next() {
		var pk []byte
		if err := rows.Scan(&pk); err != nil {
			return nil, err
		}
		out = append(out, to32(pk))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 {
		// A key amended away in every Workspace stops obtaining tokens.
		return out, nil
	}
	var registered int
	if err := i.pool.QueryRow(ctx, `select count(*) from member where member_id = $1`, id[:]).
		Scan(&registered); err != nil {
		return nil, err
	}
	if registered > 0 {
		return out, nil
	}
	d, ok, err := i.Device(ctx, id)
	if err != nil || !ok {
		return out, err
	}
	return append(out, d.ControlPK), nil
}

// PutChallenge replaces any pending one: single-use and short-lived, and one per
// device so a second request does not widen the guessing surface.
func (i *Identity) PutChallenge(ctx context.Context, member [16]byte, nonce [32]byte, expires time.Time) error {
	_, err := i.pool.Exec(ctx,
		`insert into challenge (member_id, nonce, expires) values ($1,$2,$3)
		 on conflict (member_id) do update set nonce = excluded.nonce, expires = excluded.expires`,
		member[:], nonce[:], expires)
	return err
}

// TakeChallenge consumes the pending challenge whatever follows. Deleting and
// returning in one statement is what makes "spent by the attempt, win or lose"
// atomic rather than a read followed by a hopeful delete.
func (i *Identity) TakeChallenge(ctx context.Context, member [16]byte, now time.Time) ([32]byte, bool, error) {
	var (
		nonce   []byte
		expires time.Time
	)
	err := i.pool.QueryRow(ctx,
		`delete from challenge where member_id = $1 returning nonce, expires`, member[:]).
		Scan(&nonce, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, false, nil
	}
	if err != nil {
		return [32]byte{}, false, err
	}
	if !now.Before(expires) {
		return [32]byte{}, false, nil
	}
	return to32(nonce), true, nil
}

func (i *Identity) CountChallenge(ctx context.Context, member [16]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error) {
	return countWindow(ctx, i.pool, "challenge", member[:], now, window, limit)
}

func (i *Identity) PutRefresh(ctx context.Context, hash [32]byte, member [16]byte, expires time.Time) error {
	_, err := i.pool.Exec(ctx,
		`insert into refresh_token (token_hash, member_id, expires) values ($1,$2,$3)`,
		hash[:], member[:], expires)
	return err
}

// TakeRefresh consumes a token iff it is live and scoped to this device.
//
// The check and the delete are one statement: two concurrent refreshes of one
// token must not both succeed, and a failed attempt must leave the token where
// it was. Only a successful refresh revokes the presented token — the opposite
// of the challenge rule, and deliberately so.
func (i *Identity) TakeRefresh(ctx context.Context, hash [32]byte, member [16]byte, now time.Time) (bool, error) {
	var got []byte
	err := i.pool.QueryRow(ctx,
		`delete from refresh_token
		 where token_hash = $1 and member_id = $2 and expires > $3 returning token_hash`,
		hash[:], member[:], now).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (i *Identity) RevokeRefreshFor(ctx context.Context, member [16]byte) error {
	_, err := i.pool.Exec(ctx, `delete from refresh_token where member_id = $1`, member[:])
	return err
}

// ── the vault ───────────────────────────────────────────────────────────────

// Vault is the Postgres vault store.
type Vault struct{ pool *pgxpool.Pool }

// NewVault returns a vault store over the same pool.
func NewVault(s *Store) *Vault { return &Vault{pool: s.pool} }

var _ keyplane.VaultStore = (*Vault)(nil)

func (v *Vault) Slot(ctx context.Context, locator [32]byte) (*keyplane.Slot, bool, error) {
	var (
		s              keyplane.Slot
		loc, sig, root []byte
	)
	err := v.pool.QueryRow(ctx,
		`select locator, version, blob, sig, pinned_root from vault_slot where locator = $1`,
		locator[:]).Scan(&loc, &s.Version, &s.Blob, &sig, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s.Locator = to32(loc)
	s.Sig = to64(sig)
	s.PinnedRoot = to32(root)
	return &s, true, nil
}

// PutSlot writes iff the slot has not moved since the caller read it, so
// concurrent writes resolve with exactly one winner.
func (v *Vault) PutSlot(ctx context.Context, s keyplane.Slot, expected int64) (bool, error) {
	if expected == 0 {
		tag, err := v.pool.Exec(ctx,
			`insert into vault_slot (locator, version, blob, sig, pinned_root)
			 values ($1,$2,$3,$4,$5) on conflict (locator) do nothing`,
			s.Locator[:], s.Version, s.Blob, s.Sig[:], s.PinnedRoot[:])
		if err != nil {
			return false, err
		}
		return tag.RowsAffected() == 1, nil
	}
	tag, err := v.pool.Exec(ctx,
		`update vault_slot set version = $2, blob = $3, sig = $4, pinned_root = $5
		 where locator = $1 and version = $6`,
		s.Locator[:], s.Version, s.Blob, s.Sig[:], s.PinnedRoot[:], expected)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (v *Vault) RootHasWorkspace(ctx context.Context, root [32]byte) (bool, error) {
	var n int
	err := v.pool.QueryRow(ctx,
		`select count(*) from workspace where genesis_seq is not null and root_pk = $1`,
		root[:]).Scan(&n)
	return n > 0, err
}

// RecordFetch appends to the audit before the bytes leave. A slot with no record
// is a slot whose reads nobody can ever account for.
func (v *Vault) RecordFetch(ctx context.Context, locator [32]byte, at time.Time) error {
	_, err := v.pool.Exec(ctx,
		`insert into vault_fetch (locator, fetched) values ($1,$2)`, locator[:], at)
	return err
}

func (v *Vault) CountFetch(ctx context.Context, locator [32]byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error) {
	return countWindow(ctx, v.pool, "vault", locator[:], now, window, limit)
}

// countWindow is the fixed-window limiter both planes share.
//
// Fixed rather than sliding, because a sliding window produces
// retry_after_seconds values an order of magnitude apart for the same nominal
// limit, and clients back off against the wrong one.
func countWindow(ctx context.Context, pool *pgxpool.Pool, scope string, key []byte, now time.Time, window time.Duration, limit int) (bool, time.Duration, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback(ctx)

	var (
		opened time.Time
		count  int
	)
	err = tx.QueryRow(ctx,
		`select opened, count from rate_window where scope = $1 and key = $2 for update`,
		scope, key).Scan(&opened, &count)
	fresh := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !fresh {
		return false, 0, err
	}
	// The window opens at the first counted request and is not extended by later
	// ones.
	if fresh || !now.Before(opened.Add(window)) {
		if _, err := tx.Exec(ctx,
			`insert into rate_window (scope, key, opened, count) values ($1,$2,$3,1)
			 on conflict (scope, key) do update set opened = excluded.opened, count = 1`,
			scope, key, now); err != nil {
			return false, 0, err
		}
		return true, 0, tx.Commit(ctx)
	}
	if count >= limit {
		remaining := opened.Add(window).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		return false, remaining, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx,
		`update rate_window set count = count + 1 where scope = $1 and key = $2`, scope, key); err != nil {
		return false, 0, err
	}
	return true, 0, tx.Commit(ctx)
}

// AuditRows reports how many reads have been served for a locator, for a
// deployment's own tooling and for tests.
func (v *Vault) AuditRows(ctx context.Context, locator [32]byte) (int, error) {
	var n int
	err := v.pool.QueryRow(ctx, `select count(*) from vault_fetch where locator = $1`, locator[:]).Scan(&n)
	return n, err
}

func to64(b []byte) [64]byte { var o [64]byte; copy(o[:], b); return o }
