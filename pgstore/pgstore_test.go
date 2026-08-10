package pgstore_test

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/loonybin/roundelay/internal/storetest"
	"github.com/loonybin/roundelay/pgstore"
)

// The Postgres store must satisfy the same contract the in-memory one does.
//
// Skipped without a database, so `go test ./...` stays runnable anywhere — but a
// release that has not run this has not tested the store it ships.
// openStore connects, or skips.
//
// Skipped without a database, so `go test ./...` stays runnable anywhere — but a
// release that has not run this has not tested the store it ships.
func openStore(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("ROUNDELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("set ROUNDELAY_TEST_DSN to run the Postgres store tests")
	}
	store, err := pgstore.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// freshWorkspace returns an id nothing has touched. Postgres persists between
// runs, so the contract's assumption of a clean Workspace has to be bought.
func freshWorkspace(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStoreContract(t *testing.T) {
	store := openStore(t)
	var prefix [8]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		t.Fatal(err)
	}
	var n byte
	storetest.Run(t, storetest.Suite{
		Log:      store,
		Identity: pgstore.NewIdentity(store),
		Vault:    pgstore.NewVault(store),
		Fresh: func() [16]byte {
			n++
			var id [16]byte
			copy(id[:8], prefix[:])
			id[15] = n
			return id
		},
	})
}
