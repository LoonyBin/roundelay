package httpapi_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/keyplane"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

type kpWorld struct {
	t     *testing.T
	rt    http.Handler
	prof  *profile.Profile
	log   *memstore.Store
	vault *memstore.Vault
	ns    wire.Namespace
	ws    [16]byte
	owner [16]byte
	other [16]byte
	clock time.Time
}

// kpMember is a device with a sealing key the wraps are minted for.
type kpMember struct {
	id      [16]byte
	kexPriv *ecdh.PrivateKey
}

func newKPMember(label string) kpMember {
	return kpMember{id: vectors.Bytes16("kp/" + label), kexPriv: vectors.KexPriv("kp/" + label + "/kex")}
}

func (m kpMember) kexPub() [32]byte { return to32(m.kexPriv.PublicKey().Bytes()) }
func (m kpMember) kexKeyID() [8]byte {
	pk := m.kexPub()
	return wire.KeyID(pk[:])
}

func newKPWorld(t *testing.T, owner, other kpMember) *kpWorld {
	t.Helper()
	p := testprofile.Minimal()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	log := memstore.New()
	vault := memstore.NewVault(log)
	ns, _ := wire.NewNamespace(vectors.Namespace)
	w := &kpWorld{t: t, prof: p, log: log, vault: vault, ns: ns,
		ws: vectors.WorkspaceID, owner: owner.id, other: other.id, clock: time.Unix(1700000000, 0)}

	log.Seed(w.ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{MemberID: owner.id, Kind: "device", KexPK: owner.kexPub()})
		s.Member(oplog.MemberRecord{MemberID: other.id, Kind: "device", KexPK: other.kexPub()})
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("kp/g/owner"), Member: owner.id, Role: "owner", GranterIsRoot: true})
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("kp/g/other"), Member: other.id, Role: "participant"})
	})

	auth := authority.New(p)
	kp := &httpapi.KeyplaneHandler{
		Auth: fakeAuth{device: owner.id}, Store: log, Profile: p,
		Authority: auth, Bar2: auth,
		Publisher: &keyplane.Publisher{Profile: p, Owner: auth},
	}
	vh := &httpapi.VaultHandler{Vault: &keyplane.Vault{
		Profile: p, Store: vault, Now: func() time.Time { return w.clock },
	}}

	router := httpapi.NewRouter(httpapi.NewHealth(p, okProbe))
	v1 := http.NewServeMux()
	v1.HandleFunc("PUT /w/{workspace_id}/keywraps", kp.ServePublish)
	v1.HandleFunc("GET /w/{workspace_id}/keywraps/me", kp.ServeMyWraps)
	v1.HandleFunc("GET /w/{workspace_id}/epoch-keys", kp.ServeEpochKeys)
	v1.HandleFunc("PUT /vault/{locator}", vh.ServeWrite)
	v1.HandleFunc("GET /vault/{locator}", vh.ServeRead)
	v1.HandleFunc("/", httpapi.NotFound)
	router.Contract("v1", v1)
	w.rt = router
	return w
}

// asDevice rebuilds the handler chain speaking for another device.
func (w *kpWorld) asDevice(id [16]byte) http.Handler {
	auth := authority.New(w.prof)
	kp := &httpapi.KeyplaneHandler{
		Auth: fakeAuth{device: id}, Store: w.log, Profile: w.prof,
		Authority: auth, Bar2: auth,
		Publisher: &keyplane.Publisher{Profile: w.prof, Owner: auth},
	}
	router := httpapi.NewRouter(httpapi.NewHealth(w.prof, okProbe))
	v1 := http.NewServeMux()
	v1.HandleFunc("PUT /w/{workspace_id}/keywraps", kp.ServePublish)
	v1.HandleFunc("GET /w/{workspace_id}/keywraps/me", kp.ServeMyWraps)
	v1.HandleFunc("GET /w/{workspace_id}/epoch-keys", kp.ServeEpochKeys)
	v1.HandleFunc("/", httpapi.NotFound)
	router.Contract("v1", v1)
	return router
}

func (w *kpWorld) do(h http.Handler, method, path, body string) (int, map[string]any) {
	w.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			w.t.Fatalf("%s %s: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func (w *kpWorld) call(method, path, body string) (int, map[string]any) {
	return w.do(w.rt, method, path, body)
}

// wrapSet mints a real set for an epoch, using the wire constructions.
type wrapSet struct {
	Epoch  uint32
	Wraps  []wire.WrapEntry
	Escrow []byte
	Digest [32]byte
}

func (w *kpWorld) mintSet(epoch uint32, key [32]byte, members ...kpMember) wrapSet {
	w.t.Helper()
	set := wrapSet{Epoch: epoch}
	for i, m := range members {
		pk := m.kexPub()
		p := wire.MemberWrapParams{
			Namespace: w.ns, WorkspaceID: w.ws, Epoch: epoch,
			MemberID: m.id, KexKeyID: m.kexKeyID(), KexPub: pk[:],
		}
		eph := vectors.KexPriv(fmtEph(epoch, i))
		wrap, err := wire.SealMemberWrap(p, eph, vectors.Nonce(fmtEph(epoch, i)+"/nonce"), key)
		if err != nil {
			w.t.Fatal(err)
		}
		set.Wraps = append(set.Wraps, wire.WrapEntry{MemberID: m.id, KexKeyID: m.kexKeyID(), Wrap: wrap})
	}
	escrow, err := wire.SealEscrowWrap(w.ns, w.ws, epoch, vectors.MasterWrapKey,
		vectors.Nonce(fmtEph(epoch, 99)), key)
	if err != nil {
		w.t.Fatal(err)
	}
	set.Escrow = escrow
	d, err := wire.KeywrapDigest(w.ns, epoch, set.Wraps, escrow)
	if err != nil {
		w.t.Fatal(err)
	}
	set.Digest = d
	return set
}

func fmtEph(epoch uint32, i int) string {
	return "kp/eph/" + string(rune('a'+int(epoch))) + "/" + string(rune('a'+i))
}

func (s wrapSet) body(withDigest bool) string {
	wraps := make([]map[string]any, 0, len(s.Wraps))
	for _, e := range s.Wraps {
		wraps = append(wraps, map[string]any{
			"member_id":      vectors.UUID(e.MemberID),
			"kex_key_id_b64": base64.StdEncoding.EncodeToString(e.KexKeyID[:]),
			"wrap_b64":       base64.StdEncoding.EncodeToString(e.Wrap),
		})
	}
	body := map[string]any{
		"epoch":           s.Epoch,
		"wraps":           wraps,
		"escrow_wrap_b64": base64.StdEncoding.EncodeToString(s.Escrow),
	}
	if withDigest {
		body["keywrap_digest_b64"] = base64.StdEncoding.EncodeToString(s.Digest[:])
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

// rotate lands a rotate's effect, committing a digest to the log.
func (w *kpWorld) rotate(from, to uint32, digest [32]byte) {
	w.t.Helper()
	tx, err := w.log.BeginAppend(w.t.Context(), w.ws)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := tx.PutRotate(from, to, digest, 1); err != nil {
		w.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		w.t.Fatal(err)
	}
}

// ── PUT /keywraps ───────────────────────────────────────────────────────────

// Epoch 0 is the one case with no rotate behind it: the request's own digest
// becomes the commitment.
func TestPublishEpochZero(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	set := w.mintSet(0, vectors.ContentKey, owner, other)
	path := "/v1/w/" + vectors.UUID(w.ws) + "/keywraps"

	// Without a digest there is no commitment to establish.
	status, body := w.call("PUT", path, set.body(false))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.MissingKeywrapDigest) {
		t.Fatalf("no digest: %d %v", status, body)
	}

	status, body = w.call("PUT", path, set.body(true))
	if status != http.StatusOK {
		t.Fatalf("publish: %d %v", status, body)
	}
	// The response echoes the caller's own wrap for the epoch just published,
	// and nothing else.
	echoed, _ := body["wraps"].([]any)
	if len(echoed) != 1 {
		t.Fatalf("echo = %v", body["wraps"])
	}
	if echoed[0].(map[string]any)["member_id"] != vectors.UUID(owner.id) {
		t.Errorf("the echo is not the caller's own wrap: %v", echoed[0])
	}

	// Byte-identical replay is idempotent.
	if status, _ := w.call("PUT", path, set.body(true)); status != http.StatusOK {
		t.Errorf("replay: %d", status)
	}
	// A different set for an epoch already published is refused — at epoch 0
	// under keywrap_already_written, because there is no log-committed digest
	// to catch it first.
	fewer := w.mintSet(0, vectors.ContentKey, owner)
	status, body = w.call("PUT", path, fewer.body(true))
	if status != http.StatusConflict || refusalCode(t, body) != string(codes.KeywrapAlreadyWritten) {
		t.Errorf("a different set: %d %v", status, body)
	}
}

// For epoch > 0 the matching rotate must already be in the log, and the set must
// hash to its digest.
func TestPublishNeedsItsRotate(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	set := w.mintSet(1, vectors.ContentKey, owner, other)
	path := "/v1/w/" + vectors.UUID(w.ws) + "/keywraps"

	// A set arriving first is refused rather than trusted: a digest the log has
	// not committed to is just a number the uploader chose.
	status, body := w.call("PUT", path, set.body(true))
	if status != http.StatusConflict || refusalCode(t, body) != string(codes.RotateNotMaterialised) {
		t.Fatalf("before the rotate: %d %v", status, body)
	}

	w.rotate(0, 1, set.Digest)
	if status, body := w.call("PUT", path, set.body(true)); status != http.StatusOK {
		t.Fatalf("after the rotate: %d %v", status, body)
	}

	// A different set now fails the digest the rotate committed, which is what
	// stops the server curating the set.
	fewer := w.mintSet(1, vectors.ContentKey, owner)
	status, body = w.call("PUT", path, fewer.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.KeywrapDigestMismatch) {
		t.Errorf("a curated set: %d %v", status, body)
	}
}

// The digest is what stops the server deciding which wraps exist. A set that
// omits a member, or adds one, hashes to something else.
func TestDigestPinsTheSet(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	full := w.mintSet(1, vectors.ContentKey, owner, other)
	w.rotate(0, 1, full.Digest)
	path := "/v1/w/" + vectors.UUID(w.ws) + "/keywraps"

	// A wrap with a byte changed.
	tampered := full
	tampered.Wraps = append([]wire.WrapEntry(nil), full.Wraps...)
	tampered.Wraps[0].Wrap = append([]byte(nil), full.Wraps[0].Wrap...)
	tampered.Wraps[0].Wrap[0] ^= 0x01
	status, body := w.call("PUT", path, tampered.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.KeywrapDigestMismatch) {
		t.Errorf("a tampered wrap: %d %v", status, body)
	}
}

func TestPublishEntryRefusals(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	set := w.mintSet(0, vectors.ContentKey, owner, other)
	path := "/v1/w/" + vectors.UUID(w.ws) + "/keywraps"

	// A wrap of the wrong length.
	short := set
	short.Wraps = append([]wire.WrapEntry(nil), set.Wraps...)
	short.Wraps[0].Wrap = short.Wraps[0].Wrap[:10]
	status, body := w.call("PUT", path, short.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.MalformedKeywrap) {
		t.Errorf("short wrap: %d %v", status, body)
	}

	// An escrow wrap of the wrong length.
	badEscrow := set
	badEscrow.Escrow = set.Escrow[:10]
	status, body = w.call("PUT", path, badEscrow.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.MalformedEscrowWrap) {
		t.Errorf("short escrow: %d %v", status, body)
	}

	// A member nobody registered here.
	stranger := newKPMember("stranger")
	unknown := w.mintSet(0, vectors.ContentKey, owner, stranger)
	status, body = w.call("PUT", path, unknown.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.UnknownKeywrapMember) {
		t.Errorf("unknown member: %d %v", status, body)
	}

	// A wrap sealed to a key the device does not hold here would be
	// undeliverable, and the device would look orphaned for a reason nothing in
	// the log explained.
	wrongKey := set
	wrongKey.Wraps = append([]wire.WrapEntry(nil), set.Wraps...)
	wrongKey.Wraps[0].KexKeyID = stranger.kexKeyID()
	status, body = w.call("PUT", path, wrongKey.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.KexKeyIdNotRegistered) {
		t.Errorf("wrong kex key: %d %v", status, body)
	}

	// Two wraps for one device: the digest sorts by (member, key), so a
	// duplicate would make the commitment depend on which copy was kept.
	dup := set
	dup.Wraps = append(append([]wire.WrapEntry(nil), set.Wraps...), set.Wraps[0])
	status, body = w.call("PUT", path, dup.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.DuplicateKeywrapMember) {
		t.Errorf("duplicate: %d %v", status, body)
	}

	// And the entry checks run before the epoch's own, which is what makes their
	// position observable: the digest computation would also catch a duplicate,
	// but only after rotate_not_materialised had already answered.
	dupLater := w.mintSet(1, vectors.ContentKey, owner, other)
	dupLater.Wraps = append(append([]wire.WrapEntry(nil), dupLater.Wraps...), dupLater.Wraps[0])
	status, body = w.call("PUT", "/v1/w/"+vectors.UUID(w.ws)+"/keywraps", dupLater.body(true))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.DuplicateKeywrapMember) {
		t.Errorf("a duplicate before the rotate landed: %d %v", status, body)
	}
}

// The upload is gated by the authority role before any digest is looked at.
func TestPublishRequiresOwner(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	set := w.mintSet(0, vectors.ContentKey, owner, other)
	path := "/v1/w/" + vectors.UUID(w.ws) + "/keywraps"

	status, body := w.do(w.asDevice(other.id), "PUT", path, set.body(true))
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.KeywrapRequiresOwner) {
		t.Errorf("a participant published: %d %v", status, body)
	}

	stranger := newKPMember("stranger")
	status, body = w.do(w.asDevice(stranger.id), "PUT", path, set.body(true))
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.NoRegistration) {
		t.Errorf("a stranger published: %d %v", status, body)
	}
}

// ── the two paged reads ─────────────────────────────────────────────────────

func TestMyWrapsAndEpochKeys(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	base := "/v1/w/" + vectors.UUID(w.ws)

	zero := w.mintSet(0, vectors.ContentKey, owner, other)
	if status, body := w.call("PUT", base+"/keywraps", zero.body(true)); status != http.StatusOK {
		t.Fatalf("epoch 0: %d %v", status, body)
	}
	one := w.mintSet(1, vectors.Bytes32("epoch/1/key"), owner, other)
	w.rotate(0, 1, one.Digest)
	if status, body := w.call("PUT", base+"/keywraps", one.body(true)); status != http.StatusOK {
		t.Fatalf("epoch 1: %d %v", status, body)
	}

	// Scoped to the calling device, ordered by epoch ascending, every epoch kept.
	status, body := w.call("GET", base+"/keywraps/me", "")
	if status != http.StatusOK {
		t.Fatalf("%d %v", status, body)
	}
	wraps := body["wraps"].([]any)
	if len(wraps) != 2 {
		t.Fatalf("wraps = %v", wraps)
	}
	for i, want := range []float64{0, 1} {
		e := wraps[i].(map[string]any)
		if e["epoch"] != want {
			t.Errorf("wrap %d epoch = %v", i, e["epoch"])
		}
		if e["member_id"] != vectors.UUID(owner.id) {
			t.Errorf("wrap %d is not the caller's: %v", i, e["member_id"])
		}
	}

	// after_epoch is exclusive and has no default value: absent means from the
	// start, and after_epoch=0 is a different request that skips epoch 0.
	_, body = w.call("GET", base+"/keywraps/me?after_epoch=0", "")
	if got := body["wraps"].([]any); len(got) != 1 || got[0].(map[string]any)["epoch"] != float64(1) {
		t.Errorf("after_epoch=0 gave %v", got)
	}

	// has_more is exact.
	_, body = w.call("GET", base+"/keywraps/me?limit=1", "")
	if body["has_more"] != true {
		t.Error("has_more was false with a further wrap")
	}

	// The escrow wraps, at bar 2.
	status, body = w.call("GET", base+"/epoch-keys", "")
	if status != http.StatusOK {
		t.Fatalf("epoch-keys: %d %v", status, body)
	}
	epochs := body["epochs"].([]any)
	if len(epochs) != 2 {
		t.Fatalf("epochs = %v", epochs)
	}
	first := epochs[0].(map[string]any)
	if first["escrow_wrap_b64"] != base64.StdEncoding.EncodeToString(zero.Escrow) {
		t.Error("the escrow wrap is not what was published")
	}
	if first["keywrap_digest_b64"] != base64.StdEncoding.EncodeToString(zero.Digest[:]) {
		t.Error("the digest served is not the commitment")
	}
}

// An epoch whose escrow wrap has not arrived is absent from every page, never a
// short page and never a gap between two.
func TestUnpublishedEpochsAreOmitted(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	base := "/v1/w/" + vectors.UUID(w.ws)

	zero := w.mintSet(0, vectors.ContentKey, owner, other)
	w.call("PUT", base+"/keywraps", zero.body(true))

	// A rotate lands and its wraps do not: the window this rule exists for.
	one := w.mintSet(1, vectors.Bytes32("epoch/1/key"), owner, other)
	w.rotate(0, 1, one.Digest)
	two := w.mintSet(2, vectors.Bytes32("epoch/2/key"), owner, other)
	w.rotate(1, 2, two.Digest)
	if status, body := w.call("PUT", base+"/keywraps", two.body(true)); status != http.StatusOK {
		t.Fatalf("epoch 2: %d %v", status, body)
	}

	_, body := w.call("GET", base+"/epoch-keys", "")
	epochs := body["epochs"].([]any)
	if len(epochs) != 2 {
		t.Fatalf("epochs = %v, want 0 and 2 with 1 omitted", epochs)
	}
	if epochs[0].(map[string]any)["epoch"] != float64(0) || epochs[1].(map[string]any)["epoch"] != float64(2) {
		t.Errorf("epochs = %v", epochs)
	}

	// has_more counts servable entries only, so a page ending at 0 with 1 omitted
	// and 2 servable answers true — and a caller never has to tell "the page
	// ended" from "an epoch is missing from it".
	_, body = w.call("GET", base+"/epoch-keys?limit=1", "")
	if body["has_more"] != true {
		t.Error("has_more was false with a servable epoch beyond an omitted one")
	}
	_, body = w.call("GET", base+"/epoch-keys?after_epoch=1", "")
	if got := body["epochs"].([]any); len(got) != 1 || got[0].(map[string]any)["epoch"] != float64(2) {
		t.Errorf("after_epoch=1 gave %v", got)
	}
}

// A device with no live grant cannot reach the recovery plane, but can still
// read its own wraps.
func TestEpochKeysBar(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	base := "/v1/w/" + vectors.UUID(w.ws)

	pregrant := newKPMember("pregrant")
	w.log.Seed(w.ws, func(s memstore.Seeder) {
		s.Member(oplog.MemberRecord{MemberID: pregrant.id, Kind: "device", KexPK: pregrant.kexPub()})
	})

	// Bar 1 lets it read its own wraps.
	if status, _ := w.do(w.asDevice(pregrant.id), "GET", base+"/keywraps/me", ""); status != http.StatusOK {
		t.Error("a pre-grant device could not read its own wraps")
	}
	// Bar 2 does not let it read the escrow wraps.
	status, body := w.do(w.asDevice(pregrant.id), "GET", base+"/epoch-keys", "")
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.NoLiveGrant) {
		t.Errorf("a pre-grant device reached the recovery plane: %d %v", status, body)
	}
}

// ── the vault ───────────────────────────────────────────────────────────────

func (w *kpWorld) vaultBody(root ed25519.PrivateKey, locator [32]byte, version int64, blob []byte, pin [32]byte) string {
	sig := ed25519.Sign(root, w.ns.VaultInput(locator, uint64(version), blob))
	raw, _ := json.Marshal(map[string]any{
		"version":      version,
		"blob_b64":     base64.StdEncoding.EncodeToString(blob),
		"root_sig_b64": base64.StdEncoding.EncodeToString(sig),
		"root_pk_b64":  base64.StdEncoding.EncodeToString(pin[:]),
	})
	return string(raw)
}

func TestVaultLifecycle(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)

	root := vectors.SignPriv("vault/root")
	rootPK := to32(root.Public().(ed25519.PublicKey))
	locator := vectors.Bytes32("vault/locator")
	path := "/v1/vault/" + hex.EncodeToString(locator[:])
	blob := vectors.Filler(64)

	// A first write by a Root that has founded nothing.
	status, body := w.call("PUT", path, w.vaultBody(root, locator, 1, blob, rootPK))
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.VaultRequiresGenesis) {
		t.Fatalf("no genesis: %d %v", status, body)
	}

	// Founding is register, then genesis, then vault.
	tx, _ := w.log.BeginAppend(t.Context(), w.ws)
	_ = tx.SetRoot(rootPK)
	_ = tx.Commit()

	if status, body := w.call("PUT", path, w.vaultBody(root, locator, 1, blob, rootPK)); status != http.StatusOK {
		t.Fatalf("first write: %d %v", status, body)
	}

	// A create must be version 1, and stored_version reads unambiguously off a
	// regression.
	status, body = w.call("PUT", path, w.vaultBody(root, locator, 1, blob, rootPK))
	if status != http.StatusConflict || refusalCode(t, body) != string(codes.VaultVersionRegression) {
		t.Fatalf("same version: %d %v", status, body)
	}
	if got := body["detail"].(map[string]any)["stored_version"]; got != float64(1) {
		t.Errorf("stored_version = %v", got)
	}
	empty := vectors.Bytes32("vault/nothing")
	status, body = w.call("PUT", "/v1/vault/"+hex.EncodeToString(empty[:]),
		w.vaultBody(root, empty, 0, blob, rootPK))
	if status != http.StatusUnprocessableEntity || refusalCode(t, body) != string(codes.MalformedVaultVersion) {
		t.Errorf("version 0: %d %v", status, body)
	}

	// A later write is checked against the pinned key, not the one it carries.
	impostor := vectors.SignPriv("vault/impostor")
	impostorPK := to32(impostor.Public().(ed25519.PublicKey))
	status, body = w.call("PUT", path, w.vaultBody(impostor, locator, 2, blob, impostorPK))
	if status != http.StatusForbidden || refusalCode(t, body) != string(codes.BadVaultSignature) {
		t.Errorf("an impostor re-pinned the slot: %d %v", status, body)
	}

	// Only the retiring Root can hand the slot on: root_pk is the Root this
	// record installs, not necessarily the one that signed it.
	successor := vectors.SignPriv("vault/successor")
	successorPK := to32(successor.Public().(ed25519.PublicKey))
	if status, body := w.call("PUT", path, w.vaultBody(root, locator, 2, blob, successorPK)); status != http.StatusOK {
		t.Fatalf("handover: %d %v", status, body)
	}
	// And the pin has moved.
	status, body = w.call("PUT", path, w.vaultBody(root, locator, 3, blob, successorPK))
	if status != http.StatusForbidden {
		t.Errorf("the retired Root still signs: %d %v", status, body)
	}
	if status, _ := w.call("PUT", path, w.vaultBody(successor, locator, 3, blob, successorPK)); status != http.StatusOK {
		t.Error("the installed Root cannot sign")
	}
}

// Every served read is recorded durably before the bytes leave, and the limit
// bounds bytes leaving the slot.
func TestVaultReadIsAuditedAndLimited(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	w.prof.Limits.VaultFetchesPerWindow = 2
	w.prof.Limits.VaultFetchWindow = 60 * time.Second

	root := vectors.SignPriv("vault/root")
	rootPK := to32(root.Public().(ed25519.PublicKey))
	locator := vectors.Bytes32("vault/locator")
	path := "/v1/vault/" + hex.EncodeToString(locator[:])

	// A slot holding nothing must not be able to burn the limit — otherwise
	// twenty pointless requests lock out the one fetch that matters.
	for range 5 {
		if status, _ := w.call("GET", path, ""); status != http.StatusNotFound {
			t.Fatal("an empty slot did not answer no_vault_record")
		}
	}
	if n := len(w.vault.Audit()); n != 0 {
		t.Errorf("a missing slot was audited %d times", n)
	}

	tx, _ := w.log.BeginAppend(t.Context(), w.ws)
	_ = tx.SetRoot(rootPK)
	_ = tx.Commit()
	w.call("PUT", path, w.vaultBody(root, locator, 1, vectors.Filler(64), rootPK))

	for i := range 2 {
		if status, _ := w.call("GET", path, ""); status != http.StatusOK {
			t.Fatalf("fetch %d refused", i)
		}
	}
	if n := len(w.vault.Audit()); n != 2 {
		t.Errorf("audit rows = %d, want 2", n)
	}
	status, body := w.call("GET", path, "")
	if status != http.StatusTooManyRequests || refusalCode(t, body) != string(codes.VaultFetchRateLimited) {
		t.Fatalf("over the limit: %d %v", status, body)
	}
	// A refused fetch serves no bytes, so it records none.
	if n := len(w.vault.Audit()); n != 2 {
		t.Errorf("a rate-limited fetch was audited: %d rows", n)
	}
	if body["detail"].(map[string]any)["retry_after_seconds"] == nil {
		t.Error("no retry_after_seconds")
	}
}

// The locator is 32 bytes of lowercase hex; anything else is an unrouted path.
func TestVaultLocatorShape(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	for _, bad := range []string{
		strings.Repeat("A", 64),
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		"not-hex",
	} {
		status, body := w.call("GET", "/v1/vault/"+bad, "")
		if status != http.StatusNotFound || refusalCode(t, body) != string(codes.NotFound) {
			t.Errorf("%q: %d %v", bad, status, body)
		}
	}
}

// The blob is stored verbatim and never even length-checked.
func TestVaultBlobIsOpaque(t *testing.T) {
	owner, other := newKPMember("owner"), newKPMember("other")
	w := newKPWorld(t, owner, other)
	root := vectors.SignPriv("vault/root")
	rootPK := to32(root.Public().(ed25519.PublicKey))
	tx, _ := w.log.BeginAppend(t.Context(), w.ws)
	_ = tx.SetRoot(rootPK)
	_ = tx.Commit()

	for i, blob := range [][]byte{{}, vectors.Filler(1), vectors.Filler(500)} {
		locator := vectors.Bytes32("vault/opaque/" + string(rune('a'+i)))
		path := "/v1/vault/" + hex.EncodeToString(locator[:])
		if status, body := w.call("PUT", path, w.vaultBody(root, locator, 1, blob, rootPK)); status != http.StatusOK {
			t.Fatalf("blob of %d bytes: %d %v", len(blob), status, body)
		}
		_, body := w.call("GET", path, "")
		if body["blob_b64"] != base64.StdEncoding.EncodeToString(blob) {
			t.Errorf("blob of %d bytes did not round-trip", len(blob))
		}
	}
}
