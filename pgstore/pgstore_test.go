package pgstore_test

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
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

// A search_path is interpolated into DDL, which no amount of care makes safe
// for an arbitrary string, so only a bare identifier is accepted.
//
// The guard is narrower in effect than it looks, and worth being honest about:
// a value carrying a quote never reaches it, because Postgres refuses the
// connection over an invalid search_path first. What the guard owns is the
// values Postgres is happy with and this code should not be — a quoted
// identifier that is not lower-case, or does not start with a letter, would be
// created and then never found again by an unquoted query. Keeping it is
// defence that does not depend on another system's validation staying where it
// is.
func TestSearchPathMustBeABareIdentifier(t *testing.T) {
	dsn := os.Getenv("ROUNDELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("set ROUNDELAY_TEST_DSN to run the Postgres store tests")
	}
	joiner := "&"
	if !strings.Contains(dsn, "?") {
		joiner = "?"
	}
	for _, bad := range []string{"Public", "1schema", "sch-ema"} {
		_, err := pgstore.Open(context.Background(), dsn+joiner+"search_path="+bad)
		if err == nil {
			t.Errorf("search_path %q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "bare identifier") {
			t.Errorf("search_path %q answered on something else: %v", bad, err)
		}
	}

	// And a legal one is created and used, which is what the whole check is in
	// the way of.
	store, err := pgstore.Open(context.Background(),
		dsn+joiner+"search_path=rc_probe_bare_identifier")
	if err != nil {
		t.Fatalf("a bare identifier should be created: %v", err)
	}
	store.Close()
}
