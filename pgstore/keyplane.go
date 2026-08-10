package pgstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/wire"
)

func wireKeyID(pk [32]byte) [8]byte { return wire.KeyID(pk[:]) }

// ── extension bindings ──────────────────────────────────────────────────────

func (t *tx) ExtBindingAt(member [16]byte, class byte, seq int64) (string, bool, error) {
	var name string
	err := t.tx.QueryRow(t.ctx,
		`select name from ext_binding
		 where workspace_id = $1 and member_id = $2 and op_class = $3
		   and start_seq <= $4 and (end_seq is null or $4 < end_seq)
		 order by start_seq desc limit 1`, t.ws, member[:], int16(class), seq).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return name, err == nil, err
}

func (t *tx) LiveExtBinding(member [16]byte, class byte) (string, bool, error) {
	var name string
	err := t.tx.QueryRow(t.ctx,
		`select name from ext_binding
		 where workspace_id = $1 and member_id = $2 and op_class = $3 and end_seq is null
		 order by start_seq desc limit 1`, t.ws, member[:], int16(class)).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return name, err == nil, err
}

func (t *tx) OpenExtBinding(member [16]byte, class byte, name string, at int64) error {
	_, err := t.tx.Exec(t.ctx,
		`insert into ext_binding (workspace_id, member_id, op_class, name, start_seq)
		 values ($1,$2,$3,$4,$5)`, t.ws, member[:], int16(class), name, at)
	return err
}

func (t *tx) CloseExtBinding(member [16]byte, class byte, at int64) error {
	tag, err := t.tx.Exec(t.ctx,
		`update ext_binding set end_seq = $4
		 where workspace_id = $1 and member_id = $2 and op_class = $3 and end_seq is null`,
		t.ws, member[:], int16(class), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("pgstore: no open binding interval to close")
	}
	return nil
}

// ── wrap sets ───────────────────────────────────────────────────────────────

func (t *tx) EpochRecord(epoch uint32) (*oplog.EpochRecord, bool, error) {
	return scanEpoch(t.tx.QueryRow(t.ctx,
		`select epoch, digest, escrow_wrap, rotate_seq, published
		 from epoch where workspace_id = $1 and epoch = $2`, t.ws, int64(epoch)))
}

func (t *tx) MemberWrapsAt(epoch uint32) ([]oplog.MemberWrap, error) {
	rows, err := t.tx.Query(t.ctx,
		`select epoch, member_id, kex_key_id, wrap from member_wrap
		 where workspace_id = $1 and epoch = $2 order by member_id`, t.ws, int64(epoch))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWraps(rows)
}

// PublishWraps stores an epoch's whole set. Never incremental: the digest
// commits to the whole set, so a partial upload could not be checked against it.
func (t *tx) PublishWraps(epoch uint32, digest [32]byte, escrow []byte, wraps []oplog.MemberWrap) error {
	if _, err := t.tx.Exec(t.ctx,
		`insert into epoch (workspace_id, epoch, digest, escrow_wrap, published)
		 values ($1,$2,$3,$4,true)
		 on conflict (workspace_id, epoch) do update
		   set digest = excluded.digest, escrow_wrap = excluded.escrow_wrap, published = true`,
		t.ws, int64(epoch), digest[:], escrow); err != nil {
		return err
	}
	for _, w := range wraps {
		if _, err := t.tx.Exec(t.ctx,
			`insert into member_wrap (workspace_id, epoch, member_id, kex_key_id, wrap)
			 values ($1,$2,$3,$4,$5)`,
			t.ws, int64(epoch), w.Member[:], w.KexKeyID[:], w.Wrap); err != nil {
			return err
		}
	}
	return nil
}

func scanEpoch(row pgx.Row) (*oplog.EpochRecord, bool, error) {
	var (
		rec            oplog.EpochRecord
		epoch          int64
		digest, escrow []byte
	)
	err := row.Scan(&epoch, &digest, &escrow, &rec.RotateAt, &rec.Published)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec.Epoch = uint32(epoch)
	rec.Digest = to32(digest)
	rec.EscrowWrap = escrow
	return &rec, true, nil
}

func scanWraps(rows pgx.Rows) ([]oplog.MemberWrap, error) {
	var out []oplog.MemberWrap
	for rows.Next() {
		var (
			w             oplog.MemberWrap
			epoch         int64
			member, keyID []byte
		)
		if err := rows.Scan(&epoch, &member, &keyID, &w.Wrap); err != nil {
			return nil, err
		}
		w.Epoch = uint32(epoch)
		w.Member = to16(member)
		w.KexKeyID = to8(keyID)
		out = append(out, w)
	}
	return out, rows.Err()
}

// ── reads ───────────────────────────────────────────────────────────────────

type readTx struct {
	ctx    context.Context
	tx     pgx.Tx
	ws     []byte
	closed bool
}

func (r *readTx) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.tx.Rollback(r.ctx)
}

func (r *readTx) WorkspaceExists() (bool, error) {
	var seq *int64
	err := r.tx.QueryRow(r.ctx, `select genesis_seq from workspace where workspace_id = $1`, r.ws).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return seq != nil, err
}

func (r *readTx) Registered(member [16]byte) (bool, error) {
	var n int
	err := r.tx.QueryRow(r.ctx,
		`select count(*) from member where workspace_id = $1 and member_id = $2`,
		r.ws, member[:]).Scan(&n)
	return n > 0, err
}

func (r *readTx) HasAnyGrant(member [16]byte) (bool, error) {
	var n int
	err := r.tx.QueryRow(r.ctx,
		`select count(*) from grant_row where workspace_id = $1 and member_id = $2`,
		r.ws, member[:]).Scan(&n)
	return n > 0, err
}

func (r *readTx) LiveGrantsAt(member [16]byte, at int64) ([]oplog.Grant, error) {
	rows, err := r.tx.Query(r.ctx,
		`select grant_id, member_id, role, granter, granter_root, start_seq, coalesce(end_seq,0)
		 from grant_row
		 where workspace_id = $1 and member_id = $2
		   and start_seq < $3 and (end_seq is null or $3 < end_seq)
		 order by start_seq`, r.ws, member[:], at)
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

func (r *readTx) NextSeq() (int64, error) {
	var seq int64
	err := r.tx.QueryRow(r.ctx, `select next_seq from workspace where workspace_id = $1`, r.ws).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 1, nil
	}
	return seq, err
}

// ReadOps fetches one past the limit, which answers has_more exactly without a
// second query and without counting the whole log.
//
// A hard-pruned position is absent under either filter: it is necessarily
// reprised, so the default filter already hides it, and this is what keeps the
// history view from serving a hole.
func (r *readTx) ReadOps(since int64, limit int, includeReprised bool) (oplog.Page, error) {
	q := opColumns + ` from op where workspace_id = $1 and seq > $2 and envelope is not null`
	if !includeReprised {
		q += ` and reprised_by = 0`
	}
	q += ` order by seq limit $3`

	rows, err := r.tx.Query(r.ctx, q, r.ws, since, limit+1)
	if err != nil {
		return oplog.Page{}, err
	}
	defer rows.Close()

	var page oplog.Page
	for rows.Next() {
		op, _, err := scanOp(rows)
		if err != nil {
			return oplog.Page{}, err
		}
		if len(page.Ops) == limit {
			page.HasMore = true
			break
		}
		page.Ops = append(page.Ops, *op)
	}
	return page, rows.Err()
}

// ReadMembers orders by the raw member id bytes, which is what Postgres's bytea
// comparison already is — unsigned, byte by byte. Not the UUID text, and
// emphatically not a signed 64-bit comparison of two halves.
func (r *readTx) ReadMembers(after *[16]byte, limit int) (oplog.MemberPage, error) {
	cursor := []byte{}
	if after != nil {
		cursor = after[:]
	}
	rows, err := r.tx.Query(r.ctx,
		`select member_id, kind, holder_ref, control_pk, content_pk, kex_pk, registered_at
		 from member where workspace_id = $1 and member_id > $2
		 order by member_id limit $3`, r.ws, cursor, limit+1)
	if err != nil {
		return oplog.MemberPage{}, err
	}
	defer rows.Close()

	var page oplog.MemberPage
	for rows.Next() {
		var (
			rec                    oplog.MemberRecord
			id, ref, ctl, cnt, kex []byte
		)
		if err := rows.Scan(&id, &rec.Kind, &ref, &ctl, &cnt, &kex, &rec.RegisteredAt); err != nil {
			return oplog.MemberPage{}, err
		}
		if len(page.Members) == limit {
			page.HasMore = true
			break
		}
		rec.MemberID = to16(id)
		rec.HolderRef = to32(ref)
		rec.ControlPK = to32(ctl)
		rec.ContentPK = to32(cnt)
		rec.KexPK = to32(kex)
		page.Members = append(page.Members, rec)
	}
	return page, rows.Err()
}

func (r *readTx) ReadMemberWraps(member [16]byte, afterEpoch *uint32, limit int) (oplog.WrapPage, error) {
	after := int64(-1)
	if afterEpoch != nil {
		after = int64(*afterEpoch)
	}
	rows, err := r.tx.Query(r.ctx,
		`select epoch, member_id, kex_key_id, wrap from member_wrap
		 where workspace_id = $1 and member_id = $2 and epoch > $3
		 order by epoch limit $4`, r.ws, member[:], after, limit+1)
	if err != nil {
		return oplog.WrapPage{}, err
	}
	defer rows.Close()

	all, err := scanWraps(rows)
	if err != nil {
		return oplog.WrapPage{}, err
	}
	page := oplog.WrapPage{Wraps: all}
	if len(all) > limit {
		page.Wraps, page.HasMore = all[:limit], true
	}
	return page, nil
}

// ReadEpochKeys omits an epoch whose escrow wrap has not arrived, and has_more
// counts servable entries only — so an omission is never observable as a short
// page or as a gap between two.
func (r *readTx) ReadEpochKeys(afterEpoch *uint32, limit int) (oplog.EpochPage, error) {
	after := int64(-1)
	if afterEpoch != nil {
		after = int64(*afterEpoch)
	}
	rows, err := r.tx.Query(r.ctx,
		`select epoch, digest, escrow_wrap, rotate_seq, published from epoch
		 where workspace_id = $1 and epoch > $2 and escrow_wrap is not null
		 order by epoch limit $3`, r.ws, after, limit+1)
	if err != nil {
		return oplog.EpochPage{}, err
	}
	defer rows.Close()

	var page oplog.EpochPage
	for rows.Next() {
		rec, _, err := scanEpoch(rows)
		if err != nil {
			return oplog.EpochPage{}, err
		}
		if len(page.Epochs) == limit {
			page.HasMore = true
			break
		}
		page.Epochs = append(page.Epochs, *rec)
	}
	return page, rows.Err()
}
