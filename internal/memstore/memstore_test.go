package memstore_test

import (
	"encoding/binary"
	"testing"

	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/storetest"
)

// The in-memory store must satisfy the same contract the Postgres one does.
// Without this, "storage-agnostic" is a claim about the specification and not
// about the code.
func TestStoreContract(t *testing.T) {
	log := memstore.New()
	var n uint64
	storetest.Run(t, storetest.Suite{
		Log:      log,
		Identity: memstore.NewIdentity(log),
		Vault:    memstore.NewVault(log),
		Fresh: func() [16]byte {
			n++
			var id [16]byte
			binary.BigEndian.PutUint64(id[:8], n)
			return id
		},
	})
}
