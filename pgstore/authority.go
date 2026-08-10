package pgstore

import (
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
)

// ── Root and registrations ──────────────────────────────────────────────────

func (t *tx) CurrentRoot() ([32]byte, bool, error) {
	if len(t.rootPK) == 0 {
		return [32]byte{}, false, nil
	}
	return to32(t.rootPK), true, nil
}

func (t *tx) SetRoot(pk [32]byte) error {
	t.rootPK = pk[:]
	_, err := t.tx.Exec(t.ctx, `update workspace set root_pk = $2 where workspace_id = $1`, t.ws, pk[:])
	return err
}

func (t *tx) MemberRecord(member [16]byte) (*oplog.MemberRecord, bool, error) {
	var (
		rec                    oplog.MemberRecord
		id, ref, ctl, cnt, kex []byte
	)
	err := t.tx.QueryRow(t.ctx,
		`select member_id, kind, holder_ref, control_pk, content_pk, kex_pk, registered_at
		 from member where workspace_id = $1 and member_id = $2`, t.ws, member[:]).
		Scan(&id, &rec.Kind, &ref, &ctl, &cnt, &kex, &rec.RegisteredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec.MemberID = to16(id)
	rec.HolderRef = to32(ref)
	rec.ControlPK = to32(ctl)
	rec.ContentPK = to32(cnt)
	rec.KexPK = to32(kex)
	return &rec, true, nil
}

// PutRegistration records the member and opens interval zero for each of its
// three keys. The per-device row is where every interval starts.
func (t *tx) PutRegistration(rec oplog.MemberRecord) error {
	if _, err := t.tx.Exec(t.ctx,
		`insert into member (workspace_id, member_id, kind, holder_ref,
		                     control_pk, content_pk, kex_pk, registered_at)
		 values ($1,$2,$3,$4,$5,$6,$7,$8)
		 on conflict (workspace_id, member_id) do nothing`,
		t.ws, rec.MemberID[:], rec.Kind, rec.HolderRef[:],
		rec.ControlPK[:], rec.ContentPK[:], rec.KexPK[:], rec.RegisteredAt); err != nil {
		return err
	}
	for _, k := range []struct {
		name string
		pk   [32]byte
	}{{"control", rec.ControlPK}, {"content", rec.ContentPK}, {"kex", rec.KexPK}} {
		id := keyIDOf(k.pk)
		if _, err := t.tx.Exec(t.ctx,
			`insert into key_interval (workspace_id, member_id, key_name, pk, key_id, start_seq)
			 values ($1,$2,$3,$4,$5,$6) on conflict do nothing`,
			t.ws, rec.MemberID[:], k.name, k.pk[:], id[:], rec.RegisteredAt); err != nil {
			return err
		}
	}
	return nil
}

// ControlKeyAt resolves the interval whose span contains a position.
func (t *tx) ControlKeyAt(member [16]byte, at int64) ([32]byte, bool, error) {
	var pk []byte
	err := t.tx.QueryRow(t.ctx,
		`select pk from key_interval
		 where workspace_id = $1 and member_id = $2 and key_name = 'control'
		   and start_seq <= $3 and (end_seq is null or $3 < end_seq)
		 order by start_seq desc limit 1`, t.ws, member[:], at).Scan(&pk)
	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, false, nil
	}
	if err != nil {
		return [32]byte{}, false, err
	}
	return to32(pk), true, nil
}

func (t *tx) KexKeyIDInForce(member [16]byte) ([8]byte, bool, error) {
	var id []byte
	err := t.tx.QueryRow(t.ctx,
		`select key_id from key_interval
		 where workspace_id = $1 and member_id = $2 and key_name = 'kex' and end_seq is null
		 order by start_seq desc limit 1`, t.ws, member[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return [8]byte{}, false, nil
	}
	if err != nil {
		return [8]byte{}, false, err
	}
	return to8(id), true, nil
}

func (t *tx) AmendIDUsed(id [16]byte) (bool, error) {
	var n int
	err := t.tx.QueryRow(t.ctx,
		`select count(*) from amend where workspace_id = $1 and amend_id = $2`, t.ws, id[:]).Scan(&n)
	return n > 0, err
}

// PutAmend closes the interval each named key was in and opens the next at this
// op's position. Every op below keeps verifying under the keys it was signed
// with, for ever.
func (t *tx) PutAmend(member, amendID [16]byte, control, content, kex *oplog.KeyChange, at int64) error {
	if _, err := t.tx.Exec(t.ctx,
		`insert into amend (workspace_id, amend_id, member_id, at_seq) values ($1,$2,$3,$4)`,
		t.ws, amendID[:], member[:], at); err != nil {
		return err
	}
	for _, k := range []struct {
		name   string
		change *oplog.KeyChange
	}{{"control", control}, {"content", content}, {"kex", kex}} {
		if k.change == nil {
			continue
		}
		// end_seq is write-once, and the partial unique index refuses a second
		// open interval if this close is ever lost.
		if _, err := t.tx.Exec(t.ctx,
			`update key_interval set end_seq = $4
			 where workspace_id = $1 and member_id = $2 and key_name = $3 and end_seq is null`,
			t.ws, member[:], k.name, at); err != nil {
			return err
		}
		if _, err := t.tx.Exec(t.ctx,
			`insert into key_interval (workspace_id, member_id, key_name, pk, key_id, start_seq)
			 values ($1,$2,$3,$4,$5,$6)`,
			t.ws, member[:], k.name, k.change.PK[:], k.change.KeyID[:], at); err != nil {
			return err
		}
	}
	// The member row carries the keys in force, which is the latest interval
	// materialised.
	if control != nil {
		if _, err := t.tx.Exec(t.ctx,
			`update member set control_pk = $3 where workspace_id = $1 and member_id = $2`,
			t.ws, member[:], control.PK[:]); err != nil {
			return err
		}
	}
	if content != nil {
		if _, err := t.tx.Exec(t.ctx,
			`update member set content_pk = $3 where workspace_id = $1 and member_id = $2`,
			t.ws, member[:], content.PK[:]); err != nil {
			return err
		}
	}
	if kex != nil {
		if _, err := t.tx.Exec(t.ctx,
			`update member set kex_pk = $3 where workspace_id = $1 and member_id = $2`,
			t.ws, member[:], kex.PK[:]); err != nil {
			return err
		}
	}
	return nil
}

// ── grants ──────────────────────────────────────────────────────────────────

func (t *tx) GrantByID(id [16]byte) (*oplog.Grant, bool, error) {
	return scanGrant(t.tx.QueryRow(t.ctx,
		`select grant_id, member_id, role, granter, granter_root, start_seq, coalesce(end_seq,0)
		 from grant_row where workspace_id = $1 and grant_id = $2`, t.ws, id[:]))
}

func (t *tx) LiveGrantsAt(member [16]byte, at int64) ([]oplog.Grant, error) {
	rows, err := t.tx.Query(t.ctx,
		`select grant_id, member_id, role, granter, granter_root, start_seq, coalesce(end_seq,0)
		 from grant_row
		 where workspace_id = $1 and member_id = $2
		   and start_seq < $3 and (end_seq is null or $3 < end_seq)
		 order by start_seq`, t.ws, member[:], at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oplog.Grant
	for rows.Next() {
		g, _, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (t *tx) HasAnyGrant(member [16]byte) (bool, error) {
	var n int
	err := t.tx.QueryRow(t.ctx,
		`select count(*) from grant_row where workspace_id = $1 and member_id = $2`,
		t.ws, member[:]).Scan(&n)
	return n > 0, err
}

func (t *tx) PutGrant(g oplog.Grant) error {
	var granter []byte
	if !g.GranterIsRoot {
		granter = g.Granter[:]
	}
	_, err := t.tx.Exec(t.ctx,
		`insert into grant_row (workspace_id, grant_id, member_id, role, granter,
		                        granter_root, start_seq)
		 values ($1,$2,$3,$4,$5,$6,$7)`,
		t.ws, g.GrantID[:], g.Member[:], g.Role, granter, g.GranterIsRoot, g.Start)
	return err
}

// CloseGrant writes the end position, which is immutable once written: moving
// the mark forward would widen the window an already-revoked grant covers.
func (t *tx) CloseGrant(id [16]byte, at int64) error {
	tag, err := t.tx.Exec(t.ctx,
		`update grant_row set end_seq = $3
		 where workspace_id = $1 and grant_id = $2 and end_seq is null`, t.ws, id[:], at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("pgstore: a grant's end position is write-once")
	}
	return nil
}

func scanGrant(row pgx.Row) (*oplog.Grant, bool, error) {
	var (
		g          oplog.Grant
		id, member []byte
		granter    []byte
	)
	err := row.Scan(&id, &member, &g.Role, &granter, &g.GranterIsRoot, &g.Start, &g.End)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	g.GrantID = to16(id)
	g.Member = to16(member)
	if granter != nil {
		g.Granter = to16(granter)
	}
	return &g, true, nil
}

// ── delegations ─────────────────────────────────────────────────────────────

func (t *tx) DelegationByID(id [16]byte) (*oplog.Delegation, bool, error) {
	var (
		d       oplog.Delegation
		did, pk []byte
	)
	err := t.tx.QueryRow(t.ctx,
		`select delegation_id, pk, start_seq, coalesce(end_seq,0)
		 from delegation where workspace_id = $1 and delegation_id = $2`, t.ws, id[:]).
		Scan(&did, &pk, &d.Start, &d.End)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	d.DelegationID = to16(did)
	d.PK = to32(pk)
	return &d, true, nil
}

func (t *tx) LiveDelegationsAt(at int64) ([]oplog.Delegation, error) {
	rows, err := t.tx.Query(t.ctx,
		`select delegation_id, pk, start_seq, coalesce(end_seq,0) from delegation
		 where workspace_id = $1 and start_seq < $2 and (end_seq is null or $2 < end_seq)
		 order by start_seq`, t.ws, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oplog.Delegation
	for rows.Next() {
		var (
			d       oplog.Delegation
			did, pk []byte
		)
		if err := rows.Scan(&did, &pk, &d.Start, &d.End); err != nil {
			return nil, err
		}
		d.DelegationID = to16(did)
		d.PK = to32(pk)
		out = append(out, d)
	}
	return out, rows.Err()
}

// IsRegisteredSigningKey answers delegate_pk_in_use: a delegation must not name
// a key that is any device's registered signing key here, because that would
// blur two authorities into one key.
func (t *tx) IsRegisteredSigningKey(pk [32]byte) (bool, error) {
	var n int
	err := t.tx.QueryRow(t.ctx,
		`select count(*) from key_interval
		 where workspace_id = $1 and key_name in ('control','content') and pk = $2`,
		t.ws, pk[:]).Scan(&n)
	return n > 0, err
}

func (t *tx) PutDelegation(d oplog.Delegation) error {
	_, err := t.tx.Exec(t.ctx,
		`insert into delegation (workspace_id, delegation_id, pk, start_seq) values ($1,$2,$3,$4)`,
		t.ws, d.DelegationID[:], d.PK[:], d.Start)
	return err
}

func (t *tx) CloseDelegation(id [16]byte, at int64) error {
	tag, err := t.tx.Exec(t.ctx,
		`update delegation set end_seq = $3
		 where workspace_id = $1 and delegation_id = $2 and end_seq is null`, t.ws, id[:], at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("pgstore: a delegation's end position is write-once")
	}
	return nil
}

// ── the role table ──────────────────────────────────────────────────────────

func (t *tx) RoleTableAt(at int64) (profile.RoleTable, bool, error) {
	var raw []byte
	err := t.tx.QueryRow(t.ctx,
		`select entries from role_table where workspace_id = $1 and at_seq < $2
		 order by at_seq desc limit 1`, t.ws, at).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var table profile.RoleTable
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, false, err
	}
	return table, true, nil
}

func (t *tx) PutRoleTable(table profile.RoleTable, at int64) error {
	raw, err := json.Marshal(table)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(t.ctx,
		`insert into role_table (workspace_id, at_seq, entries) values ($1,$2,$3)
		 on conflict (workspace_id, at_seq) do update set entries = excluded.entries`,
		t.ws, at, raw)
	return err
}

// ── epochs ──────────────────────────────────────────────────────────────────

// CurrentEpoch is the maximum materialised epoch, computed on demand. A stored
// value would be a cache of that maximum, free to disagree with the records that
// produced it.
func (t *tx) CurrentEpoch() (uint32, error) {
	var max *int64
	err := t.tx.QueryRow(t.ctx,
		`select max(epoch) from epoch where workspace_id = $1 and rotate_seq > 0`, t.ws).Scan(&max)
	if err != nil || max == nil {
		return 0, err
	}
	return uint32(*max), nil
}

func (t *tx) PutRotate(from, to uint32, digest [32]byte, at int64) error {
	_, err := t.tx.Exec(t.ctx,
		`insert into epoch (workspace_id, epoch, digest, rotate_seq) values ($1,$2,$3,$4)
		 on conflict (workspace_id, epoch) do update set digest = excluded.digest,
		                                                 rotate_seq = excluded.rotate_seq`,
		t.ws, int64(to), digest[:], at)
	return err
}

// ── the cascade ─────────────────────────────────────────────────────────────

// EndDeviceSessions buffers the target. It fires after the commit, because a
// rolled-back batch must kill no live session.
func (t *tx) EndDeviceSessions(member [16]byte) error {
	t.ended = append(t.ended, member)
	return nil
}

func keyIDOf(pk [32]byte) [8]byte { return wireKeyID(pk) }
