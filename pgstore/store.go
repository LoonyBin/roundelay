// Package pgstore is the Postgres implementation of the server's retained
// state.
//
// Two properties are the reason it exists rather than being a translation of
// the in-memory one.
//
// Positions are allocated by taking the Workspace's counter row FOR UPDATE at
// the start of an append, which puts the allocation under the same
// serialisation as the commit. A sequence would not: it hands out 100 and 101
// outside the transaction, 101 commits first, a reader advances its cursor past
// it, and 100 is never served again — silent, permanent loss that nothing
// detects and no application logic can close.
//
// And the two uniqueness rules are enforced by the storage layer rather than by
// application code, because the write path reads the author's head and then
// inserts: two concurrent batches can both read the same head and both believe
// they own the next slot, and a forked author chain is unrecoverable.
package pgstore

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
)

//go:embed schema.sql
var schema string

// Store is an oplog.Store over a Postgres pool.
type Store struct {
	pool *pgxpool.Pool

	// onSessionsEnded is the cascade's fan-out. A deployment points it at its
	// token table and its socket registry.
	onSessionsEnded func(member [16]byte)
}

// OnSessionsEnded registers the fan-out. It fires after the commit, because
// every effect a control op causes does.
func (s *Store) OnSessionsEnded(f func(member [16]byte)) { s.onSessionsEnded = f }

// Open connects and applies the schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstore: applying schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pool, for a deployment that shares it.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

var _ oplog.Store = (*Store)(nil)

// Refusal maps a storage error onto the vocabulary, by constraint name.
//
// Every unique constraint in the schema is named after the refusal it produces,
// which is what keeps this a lookup rather than a pile of pre-flight SELECTs
// that race anyway.
//
// The two on `op` are a backstop rather than a live path: an append holds the
// Workspace's counter row, so appends to one Workspace serialise and neither can
// be reached. Reaching one means the serialisation was lost, and the fieldless
// form of author_chain_conflict is exactly the verdict for that — a concurrent
// request for the same author committed in between, with no numbers guessed.
func Refusal(err error) (codes.Code, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23505" {
		return "", false
	}
	switch pg.ConstraintName {
	case "op_id_already_used", "author_chain_conflict":
		return codes.AuthorChainConflict, true
	case "grant_id_already_used":
		return codes.GrantIdAlreadyUsed, true
	case "delegation_id_already_used":
		return codes.DelegationIdAlreadyUsed, true
	case "amend_id_already_used":
		return codes.AmendIdAlreadyUsed, true
	case "duplicate_keywrap_member":
		return codes.DuplicateKeywrapMember, true
	case "key_interval_one_open", "ext_binding_one_open":
		// An end position is write-once, so a second open interval is a lost
		// close rather than a caller's mistake.
		return codes.StoreUnavailable, true
	}
	return "", false
}

// BeginAppend opens an append transaction and takes the Workspace's counter row.
func (s *Store) BeginAppend(ctx context.Context, workspace [16]byte) (oplog.Tx, error) {
	conn, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	t := &tx{store: s, ctx: ctx, tx: conn, ws: workspace[:], id: workspace}

	// Upsert-then-lock: a Workspace row exists before its genesis, because the
	// counter has to exist before the op that creates the Workspace can be given
	// a position.
	if _, err := conn.Exec(ctx,
		`insert into workspace (workspace_id) values ($1) on conflict do nothing`, t.ws); err != nil {
		_ = conn.Rollback(ctx)
		return nil, err
	}
	if err := conn.QueryRow(ctx,
		`select next_seq, genesis_seq, root_pk from workspace where workspace_id = $1 for update`,
		t.ws).Scan(&t.nextSeq, &t.genesisSeq, &t.rootPK); err != nil {
		_ = conn.Rollback(ctx)
		return nil, err
	}
	return t, nil
}

// BeginRead opens a read-only snapshot.
//
// REPEATABLE READ is what makes "a read must not observe a partially committed
// batch" true across the several queries a page needs: every statement sees the
// same snapshot, so a batch that commits between them is invisible to all of
// them rather than to some.
func (s *Store) BeginRead(ctx context.Context, workspace [16]byte) (oplog.ReadTx, error) {
	conn, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	return &readTx{ctx: ctx, tx: conn, ws: workspace[:]}, nil
}

type tx struct {
	store      *Store
	ctx        context.Context
	tx         pgx.Tx
	ws         []byte
	id         [16]byte
	nextSeq    int64
	genesisSeq *int64
	rootPK     []byte
	closed     bool

	// ended accumulates the cascade's targets. It fires after the commit,
	// because every effect a control op causes does.
	ended []([16]byte)
}

func (t *tx) Commit() error {
	if t.closed {
		return errors.New("pgstore: transaction is closed")
	}
	t.closed = true
	// The counter moved inside this transaction, so a rollback burns no
	// positions and a commit publishes exactly the ones it used.
	if _, err := t.tx.Exec(t.ctx,
		`update workspace set next_seq = $2 where workspace_id = $1`, t.ws, t.nextSeq); err != nil {
		_ = t.tx.Rollback(t.ctx)
		return err
	}
	if err := t.tx.Commit(t.ctx); err != nil {
		return err
	}
	if t.store != nil && t.store.onSessionsEnded != nil {
		for _, m := range t.ended {
			t.store.onSessionsEnded(m)
		}
	}
	return nil
}

func (t *tx) Rollback() error {
	if t.closed {
		return nil
	}
	t.closed = true
	return t.tx.Rollback(t.ctx)
}

// ── The Log ─────────────────────────────────────────────────────────────────

func (t *tx) NextSeq() (int64, error) { return t.nextSeq, nil }

func (t *tx) WorkspaceExists() (bool, error) { return t.genesisSeq != nil, nil }

func (t *tx) MarkGenesis(at int64) error {
	t.genesisSeq = &at
	_, err := t.tx.Exec(t.ctx, `update workspace set genesis_seq = $2 where workspace_id = $1`, t.ws, at)
	return err
}

func (t *tx) Registered(member [16]byte) (bool, error) {
	var n int
	err := t.tx.QueryRow(t.ctx,
		`select count(*) from member where workspace_id = $1 and member_id = $2`,
		t.ws, member[:]).Scan(&n)
	return n > 0, err
}

func (t *tx) KeyIDsHeldForClass(member [16]byte, class oplog.SigningClass) ([][8]byte, error) {
	name := "control"
	if class == oplog.ContentSigning {
		name = "content"
	}
	rows, err := t.tx.Query(t.ctx,
		`select key_id from key_interval
		 where workspace_id = $1 and member_id = $2 and key_name = $3
		 order by start_seq`, t.ws, member[:], name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][8]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, to8(raw))
	}
	return out, rows.Err()
}

func (t *tx) OpByOpID(author, opID [16]byte) (*oplog.StoredOp, bool, error) {
	return scanOp(t.tx.QueryRow(t.ctx, opColumns+
		` from op where workspace_id = $1 and author = $2 and op_id = $3`, t.ws, author[:], opID[:]))
}

func (t *tx) OpAt(seq int64) (*oplog.StoredOp, bool, error) {
	return scanOp(t.tx.QueryRow(t.ctx, opColumns+
		` from op where workspace_id = $1 and seq = $2`, t.ws, seq))
}

func (t *tx) AuthorHead(member [16]byte) (uint64, error) {
	var head *int64
	err := t.tx.QueryRow(t.ctx,
		`select max(author_seq) from op where workspace_id = $1 and author = $2`,
		t.ws, member[:]).Scan(&head)
	if err != nil || head == nil {
		return 0, err
	}
	return uint64(*head), nil
}

func (t *tx) LastControlOpBefore(seq int64) (*oplog.StoredOp, bool, error) {
	return scanOp(t.tx.QueryRow(t.ctx, opColumns+
		` from op where workspace_id = $1 and class = $2 and seq < $3 order by seq desc limit 1`,
		t.ws, int16(0x80), seq))
}

// Append stores an op verbatim at the next position.
func (t *tx) Append(op oplog.StoredOp) (int64, error) {
	seq := t.nextSeq
	_, err := t.tx.Exec(t.ctx,
		`insert into op (workspace_id, seq, class, key_epoch, op_id, author,
		                 author_key_id, author_seq, envelope_hash, envelope)
		 values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.ws, seq, int16(op.Class), int64(op.KeyEpoch), op.OpID[:], op.Author[:],
		op.AuthorKeyID[:], int64(op.AuthorSeq), op.EnvelopeHash[:], op.Envelope)
	if err != nil {
		return 0, err
	}
	t.nextSeq++
	return seq, nil
}

func (t *tx) MarkReprised(seq, byPos int64) error {
	_, err := t.tx.Exec(t.ctx,
		`update op set reprised_by = $3 where workspace_id = $1 and seq = $2`, t.ws, seq, byPos)
	return err
}

// DropEnvelope destroys the bytes and keeps the tombstone — every other column
// on the row, including the envelope hash, which was materialised from the bytes
// about to be dropped.
func (t *tx) DropEnvelope(seq int64) error {
	_, err := t.tx.Exec(t.ctx,
		`update op set envelope = null where workspace_id = $1 and seq = $2`, t.ws, seq)
	return err
}

const opColumns = `select seq, class, key_epoch, op_id, author, author_key_id,
                          author_seq, reprised_by, envelope_hash, envelope`

func scanOp(row pgx.Row) (*oplog.StoredOp, bool, error) {
	var (
		op                                  oplog.StoredOp
		class                               int16
		epoch                               int64
		opID, author, keyID, hash, envelope []byte
		authorSeq                           int64
	)
	err := row.Scan(&op.Seq, &class, &epoch, &opID, &author, &keyID,
		&authorSeq, &op.ReprisedBy, &hash, &envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	op.Class = byte(class)
	op.KeyEpoch = uint32(epoch)
	op.OpID = to16(opID)
	op.Author = to16(author)
	op.AuthorKeyID = to8(keyID)
	op.AuthorSeq = uint64(authorSeq)
	op.EnvelopeHash = to32(hash)
	op.Envelope = envelope
	return &op, true, nil
}

func to8(b []byte) [8]byte   { var o [8]byte; copy(o[:], b); return o }
func to16(b []byte) [16]byte { var o [16]byte; copy(o[:], b); return o }
func to32(b []byte) [32]byte { var o [32]byte; copy(o[:], b); return o }
