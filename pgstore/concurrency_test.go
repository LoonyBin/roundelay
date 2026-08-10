package pgstore_test

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/loonybin/roundelay/oplog"
)

// The property Postgres is here for.
//
// Many writers append to one Workspace at once. Every position from 1 to N must
// be occupied exactly once, with no hole and no repeat — because a hole is an op
// a reader's cursor skips past for ever, and `since` is exclusive with no
// server-side cursor to notice.
//
// A bigserial would fail this: it allocates outside the transaction, so 101 can
// commit while 100 is still in flight, a read returns 101, and 100 is never
// served again.
func TestConcurrentAppendsLoseNoPosition(t *testing.T) {
	store := openStore(t)
	ws := freshWorkspace(t)

	const writers = 8
	const each = 6

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			author := authorID(w)
			for i := 1; i <= each; i++ {
				tx, err := store.BeginAppend(t.Context(), ws)
				if err != nil {
					errs <- err
					return
				}
				op := oplog.StoredOp{
					Class: 0x01, OpID: opID(w, i), Author: author, AuthorSeq: uint64(i),
					EnvelopeHash: [32]byte{byte(w), byte(i)}, Envelope: []byte{byte(w), byte(i)},
				}
				if _, err := tx.Append(op); err != nil {
					_ = tx.Rollback()
					errs <- err
					return
				}
				if err := tx.Commit(); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("writer: %v", err)
	}

	rd, err := store.BeginRead(t.Context(), ws)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	total := writers * each
	page, err := rd.ReadOps(0, total+10, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Ops) != total {
		t.Fatalf("%d ops stored, want %d", len(page.Ops), total)
	}
	// Ascending, contiguous from 1, each position once.
	for i, op := range page.Ops {
		if op.Seq != int64(i+1) {
			t.Fatalf("position %d is occupied by seq %d; the log has a hole or a repeat", i+1, op.Seq)
		}
	}
	// And every author's chain is intact — the uniqueness rule the storage layer
	// owns, under real contention.
	seen := map[[16]byte]map[uint64]bool{}
	for _, op := range page.Ops {
		if seen[op.Author] == nil {
			seen[op.Author] = map[uint64]bool{}
		}
		if seen[op.Author][op.AuthorSeq] {
			t.Fatalf("author %x wrote author_seq %d twice", op.Author[:4], op.AuthorSeq)
		}
		seen[op.Author][op.AuthorSeq] = true
	}
	for author, chain := range seen {
		for i := 1; i <= each; i++ {
			if !chain[uint64(i)] {
				t.Errorf("author %x is missing author_seq %d", author[:4], i)
			}
		}
	}
}

// A reader must never see a position while a lower one is still uncommitted.
//
// With the counter row held for the length of the append, an in-flight batch
// blocks the next one from being allocated at all — so there is no window in
// which a higher position is visible and a lower one is not.
func TestNoHoleIsEverVisible(t *testing.T) {
	store := openStore(t)
	ws := freshWorkspace(t)
	author := authorID(0)

	// One writer holds a transaction open with a position allocated.
	slow, err := store.BeginAppend(t.Context(), ws)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slow.Append(oplog.StoredOp{
		Class: 0x01, OpID: opID(0, 1), Author: author, AuthorSeq: 1,
		EnvelopeHash: [32]byte{1}, Envelope: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}

	// A second writer cannot get past the counter row while the first holds it,
	// so it cannot be given position 2 and commit ahead.
	raced := make(chan struct{})
	go func() {
		defer close(raced)
		tx, err := store.BeginAppend(t.Context(), ws)
		if err != nil {
			return
		}
		_, _ = tx.Append(oplog.StoredOp{
			Class: 0x01, OpID: opID(1, 1), Author: authorID(1), AuthorSeq: 1,
			EnvelopeHash: [32]byte{2}, Envelope: []byte{2},
		})
		_ = tx.Commit()
	}()

	// While the first is open, a reader sees nothing.
	rd, err := store.BeginRead(t.Context(), ws)
	if err != nil {
		t.Fatal(err)
	}
	page, err := rd.ReadOps(0, 10, true)
	rd.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Ops) != 0 {
		t.Errorf("a reader saw %d uncommitted ops", len(page.Ops))
	}

	if err := slow.Commit(); err != nil {
		t.Fatal(err)
	}
	<-raced

	rd, err = store.BeginRead(t.Context(), ws)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	page, err = rd.ReadOps(0, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Ops) != 2 || page.Ops[0].Seq != 1 || page.Ops[1].Seq != 2 {
		t.Errorf("after both committed the log is %v", seqsOf(page))
	}
}

func seqsOf(p oplog.Page) []int64 {
	out := make([]int64, 0, len(p.Ops))
	for _, o := range p.Ops {
		out = append(out, o.Seq)
	}
	return out
}

func authorID(n int) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], uint64(0xA07))
	binary.BigEndian.PutUint64(id[8:], uint64(n))
	return id
}

func opID(w, i int) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], uint64(w))
	binary.BigEndian.PutUint64(id[8:], uint64(i))
	return id
}
