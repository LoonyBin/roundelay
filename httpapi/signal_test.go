package httpapi_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/internal/vectors"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/signal"
	"github.com/loonybin/roundelay/wire"
)

type sigWorld struct {
	t      *testing.T
	server *httptest.Server
	store  *memstore.Store
	broker *signal.Memory
	pipe   *oplog.Pipeline
	ws     [16]byte
	dev    [16]byte
	seq    uint64
}

// tokenFor lets the fixture speak for whichever device a test dials as.
type dialAuth struct{}

func (dialAuth) Device(_ context.Context, bearer string) ([16]byte, bool) {
	switch bearer {
	case "":
		return [16]byte{}, false
	case "bad":
		return [16]byte{}, false
	case "member":
		return vectors.MemberA, true
	case "stranger":
		return vectors.MemberB, true
	case "revoked":
		return vectors.Bytes16("sig/revoked"), true
	case "pregrant":
		return vectors.Bytes16("sig/pregrant"), true
	}
	return [16]byte{}, false
}

func newSigWorld(t *testing.T) *sigWorld {
	t.Helper()
	p := testprofile.Minimal()
	// The keepalive must be advertisable as whole seconds — a client's idle
	// deadline derives from what GET /health reports — so a test cannot shrink it
	// below one, and the profile validator says so.
	p.Limits.SignalKeepalive = time.Second
	p.Limits.SignalAuthDeadline = 200 * time.Millisecond
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	broker := signal.NewMemory()
	ws, dev := vectors.WorkspaceID, vectors.MemberA

	store.Seed(ws, func(s memstore.Seeder) {
		s.Exists()
		s.Member(oplog.MemberRecord{MemberID: dev, Kind: "device",
			ContentPK: to32(vectors.SignPub(vectors.LabelDeviceAContent))})
		s.Member(oplog.MemberRecord{MemberID: vectors.Bytes16("sig/pregrant"), Kind: "device"})
		s.Member(oplog.MemberRecord{MemberID: vectors.Bytes16("sig/revoked"), Kind: "device"})
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("sig/g"), Member: dev, Role: "owner", GranterIsRoot: true})
		s.Grant(oplog.Grant{GrantID: vectors.Bytes16("sig/gr"), Member: vectors.Bytes16("sig/revoked"),
			Role: "owner", Start: 1, End: 2})
	})
	// The cascade's other half: a revoke closes every live socket the device
	// holds here.
	store.OnSessionsEnded(func(m [16]byte) { broker.EvictAll(m) })

	auth := authority.New(p)
	w := &sigWorld{t: t, store: store, broker: broker, ws: ws, dev: dev,
		pipe: &oplog.Pipeline{Profile: p, Store: store, Authority: auth,
			Notify: func(id [16]byte) { broker.Notify(id) }}}

	sh := &httpapi.SignalHandler{
		Auth: dialAuth{}, Store: store, Profile: p, Authority: auth, Broker: broker,
	}
	if err := sh.Validate(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/w/{workspace_id}/signal", sh)
	w.server = httptest.NewServer(mux)
	t.Cleanup(w.server.Close)
	return w
}

func (w *sigWorld) dialWorkspace(ws [16]byte) (*websocket.Conn, *http.Response) {
	w.t.Helper()
	url := "ws" + w.server.URL[len("http"):] + "/v1/w/" + vectors.UUID(ws) + "/signal"
	conn, resp, err := websocket.Dial(w.t.Context(), url, nil)
	if err != nil {
		w.t.Fatalf("dial: %v", err)
	}
	return conn, resp
}

func (w *sigWorld) dial() *websocket.Conn {
	conn, _ := w.dialWorkspace(w.ws)
	return conn
}

// connect completes the handshake and consumes the acknowledgement frame.
func (w *sigWorld) connect(token string) *websocket.Conn {
	w.t.Helper()
	conn := w.dial()
	if err := conn.Write(w.t.Context(), websocket.MessageText, []byte(token)); err != nil {
		w.t.Fatal(err)
	}
	kind, payload := w.expect(conn)
	if kind != websocket.MessageText || len(payload) != 0 {
		w.t.Fatalf("acknowledgement = %v %q, want an empty text frame", kind, payload)
	}
	return conn
}

func (w *sigWorld) expect(conn *websocket.Conn) (websocket.MessageType, []byte) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.t.Context(), 2*time.Second)
	defer cancel()
	kind, payload, err := conn.Read(ctx)
	if err != nil {
		w.t.Fatalf("read: %v", err)
	}
	return kind, payload
}

// expectClose reads until the socket closes and returns the code.
func (w *sigWorld) expectClose(conn *websocket.Conn) websocket.StatusCode {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.t.Context(), 2*time.Second)
	defer cancel()
	for {
		if _, _, err := conn.Read(ctx); err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

// nothingWithin asserts the socket stays quiet.
func (w *sigWorld) nothingWithin(conn *websocket.Conn, d time.Duration) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(w.t.Context(), d)
	defer cancel()
	_, payload, err := conn.Read(ctx)
	if err == nil {
		w.t.Fatalf("expected silence, got %q", payload)
	}
	if ctx.Err() == nil {
		w.t.Fatalf("socket closed while expecting silence: %v", err)
	}
}

func (w *sigWorld) write(n int) {
	w.t.Helper()
	ops := make([]string, n)
	for i := range n {
		w.seq++
		h := wire.Header{
			OpClass: wire.ClassContent, Suite: wire.SuiteNone,
			WorkspaceID: w.ws, AuthorMemberID: w.dev,
			OpID:        vectors.Bytes16(fmt.Sprintf("sig/op/%d", w.seq)),
			AuthorKeyID: wire.KeyID(vectors.SignPub(vectors.LabelDeviceAContent)),
			AuthorSeq:   w.seq,
		}
		if w.seq > 1 {
			h.PrevAuthorHash = vectors.PrevHash(fmt.Sprint(w.seq))
		}
		body, _ := testprofile.Minimal().SizeClasses.PackBody([]byte("x"))
		ns, _ := wire.NewNamespace(vectors.Namespace)
		env, err := wire.SignOp(vectors.SignPriv(vectors.LabelDeviceAContent), ns.V1(wire.DocOp), h.Marshal(), body)
		if err != nil {
			w.t.Fatal(err)
		}
		ops[i] = base64.StdEncoding.EncodeToString(env)
	}
	if _, r := w.pipe.Append(w.t.Context(), w.ws, w.dev, ops); r != nil {
		w.t.Fatalf("append: %s %v", r.Code, r.Fields)
	}
}

// ── the handshake ───────────────────────────────────────────────────────────

// The connection is accepted before anything is checked, and the immediate
// empty frame is the acknowledgement — which is why a client must not read a
// successful connection as authentication success.
func TestSignalAcceptancePrecedesTheCheck(t *testing.T) {
	w := newSigWorld(t)
	conn, resp := w.dialWorkspace(w.ws)
	defer conn.CloseNow()

	// The upgrade completed before any credential was presented. That is the
	// acceptance, and it is why the empty frame below has to be the
	// acknowledgement — nothing about the connection itself says anything.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", resp.StatusCode)
	}

	if err := conn.Write(t.Context(), websocket.MessageText, []byte("bad")); err != nil {
		t.Fatal(err)
	}
	if got := w.expectClose(conn); got != websocket.StatusCode(codes.CloseInvalidToken) {
		t.Errorf("close = %d, want 4401", got)
	}
}

func TestSignalCloseCodes(t *testing.T) {
	for _, c := range []struct {
		name  string
		token string
		want  int
	}{
		{"invalid token", "bad", codes.CloseInvalidToken},
		{"no registration here", "stranger", codes.CloseNoMembership},
		{"revoked", "revoked", codes.CloseNoMembership},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newSigWorld(t)
			conn := w.dial()
			defer conn.CloseNow()
			if err := conn.Write(t.Context(), websocket.MessageText, []byte(c.token)); err != nil {
				t.Fatal(err)
			}
			if got := w.expectClose(conn); got != websocket.StatusCode(c.want) {
				t.Errorf("close = %d, want %d", got, c.want)
			}
		})
	}
}

// No token in time, or a binary first frame: a protocol error the client must
// fix.
func TestSignalProtocolErrors(t *testing.T) {
	w := newSigWorld(t)

	silent := w.dial()
	defer silent.CloseNow()
	if got := w.expectClose(silent); got != websocket.StatusCode(codes.CloseProtocolError) {
		t.Errorf("no token in time: close = %d, want 4400", got)
	}

	binary := w.dial()
	defer binary.CloseNow()
	if err := binary.Write(t.Context(), websocket.MessageBinary, []byte("member")); err != nil {
		t.Fatal(err)
	}
	if got := w.expectClose(binary); got != websocket.StatusCode(codes.CloseProtocolError) {
		t.Errorf("binary first frame: close = %d, want 4400", got)
	}
}

// A device with zero grants passes bar 1, here as everywhere.
func TestSignalPreGrantDeviceSubscribes(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("pregrant")
	defer conn.CloseNow()
}

// Before a genesis there is nothing to be registered in, so the socket is
// accepted and behaves as a subscription to an empty Workspace.
func TestSignalOnAnUncreatedWorkspace(t *testing.T) {
	w := newSigWorld(t)
	other := vectors.Bytes16("sig/no-such-workspace")
	conn, _ := w.dialWorkspace(other)
	defer conn.CloseNow()

	if err := conn.Write(t.Context(), websocket.MessageText, []byte("stranger")); err != nil {
		t.Fatal(err)
	}
	kind, payload := w.expect(conn)
	if kind != websocket.MessageText || len(payload) != 0 {
		t.Fatalf("a stranger was gated on an empty Workspace: %v %q", kind, payload)
	}
}

// ── the feed ────────────────────────────────────────────────────────────────

// A poke carries nothing: the Workspace is in the URL.
func TestPokeIsAnEmptyFrame(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	w.write(1)
	kind, payload := w.expect(conn)
	if kind != websocket.MessageText || len(payload) != 0 {
		t.Errorf("poke = %v %q, want an empty text frame", kind, payload)
	}
}

// A burst never delivers more pokes than there were appends, and the read it
// provokes sweeps up everything.
//
// Strict coalescing — N appends before the subscriber wakes deliver exactly one
// poke — is asserted at the broker, where it is deterministic. At the socket it
// cannot be: a subscriber that is already awake and draining legitimately sees
// more than one, and a test that demanded otherwise would be testing the
// scheduler.
func TestBurstDeliversNoMorePokesThanAppends(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	const appends = 5
	for range appends {
		w.write(1)
	}

	pokes := 0
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		_, payload, err := conn.Read(ctx)
		cancel()
		if err != nil {
			break
		}
		if len(payload) != 0 {
			break // the keepalive; the run is over
		}
		pokes++
		if pokes > appends {
			t.Fatalf("%d appends delivered more than %d pokes", appends, appends)
		}
	}
	if pokes == 0 {
		t.Fatal("a burst delivered no poke at all")
	}
	// And what the poke told the client to do finds everything.
	if got := len(w.store.Ops(w.ws)); got != appends {
		t.Errorf("the log holds %d ops, want %d", got, appends)
	}
}

// A pure repeat is not news.
func TestRepeatsDoNotPoke(t *testing.T) {
	w := newSigWorld(t)
	w.write(1)
	stored := w.store.Ops(w.ws)
	if len(stored) != 1 {
		t.Fatal("setup")
	}
	same := base64.StdEncoding.EncodeToString(stored[0].Envelope)

	conn := w.connect("member")
	defer conn.CloseNow()

	if _, r := w.pipe.Append(t.Context(), w.ws, w.dev, []string{same}); r != nil {
		t.Fatalf("replay: %s", r.Code)
	}
	w.nothingWithin(conn, 200*time.Millisecond)
}

// An empty batch changes nothing and pokes nobody.
func TestEmptyBatchDoesNotPoke(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	if _, r := w.pipe.Append(t.Context(), w.ws, w.dev, nil); r != nil {
		t.Fatal(r.Code)
	}
	w.nothingWithin(conn, 200*time.Millisecond)
}

// The keepalive fires only in the absence of news, so it is the exact
// complement of a poke.
func TestKeepaliveIsIdleOnly(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	kind, payload := w.expect(conn)
	if kind != websocket.MessageText || string(payload) != httpapi.Keepalive {
		t.Fatalf("idle frame = %v %q, want the literal text %q", kind, payload, httpapi.Keepalive)
	}

	// A poke restarts the idle clock. Sleep most of a keepalive interval, poke,
	// and the remainder must pass in silence — under a clock that was not reset
	// the keepalive would arrive on the original schedule.
	time.Sleep(600 * time.Millisecond)
	w.write(1)
	if _, payload := w.expect(conn); len(payload) != 0 {
		t.Fatalf("expected a poke, got %q", payload)
	}
	w.nothingWithin(conn, 600*time.Millisecond)
}

// A refused batch pokes nobody: the poke happens after the commit, and there was
// none.
func TestRefusedBatchDoesNotPoke(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	// A gap in the author chain refuses the whole batch.
	w.seq = 40
	ops := make([]string, 1)
	h := wire.Header{
		OpClass: wire.ClassContent, Suite: wire.SuiteNone,
		WorkspaceID: w.ws, AuthorMemberID: w.dev,
		OpID:        vectors.Bytes16("sig/refused"),
		AuthorKeyID: wire.KeyID(vectors.SignPub(vectors.LabelDeviceAContent)),
		AuthorSeq:   41,
	}
	h.PrevAuthorHash = vectors.PrevHash("refused")
	body, _ := testprofile.Minimal().SizeClasses.PackBody([]byte("x"))
	ns, _ := wire.NewNamespace(vectors.Namespace)
	env, err := wire.SignOp(vectors.SignPriv(vectors.LabelDeviceAContent), ns.V1(wire.DocOp), h.Marshal(), body)
	if err != nil {
		t.Fatal(err)
	}
	ops[0] = base64.StdEncoding.EncodeToString(env)

	if _, r := w.pipe.Append(t.Context(), w.ws, w.dev, ops); r == nil {
		t.Fatal("the batch was expected to fail")
	}
	w.nothingWithin(conn, 200*time.Millisecond)
}

// Inbound frames after the handshake are ignored.
func TestInboundFramesAreIgnored(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	for _, msg := range []string{"", "hello", "member"} {
		if err := conn.Write(t.Context(), websocket.MessageText, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	// Still live, and still poking.
	w.write(1)
	if _, payload := w.expect(conn); len(payload) != 0 {
		t.Errorf("after inbound noise the feed gave %q", payload)
	}
}

// Revocation closes the socket; token expiry does not. The cascade's third part
// lands here.
func TestRevocationClosesTheSocket(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	tx, err := w.store.BeginAppend(t.Context(), w.ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.EndDeviceSessions(w.dev); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if got := w.expectClose(conn); got != websocket.StatusCode(codes.CloseNoMembership) {
		t.Errorf("close = %d, want 4403", got)
	}
}

// A rolled-back batch closes nothing: every effect lands after the commit.
func TestRolledBackRevocationClosesNothing(t *testing.T) {
	w := newSigWorld(t)
	conn := w.connect("member")
	defer conn.CloseNow()

	tx, _ := w.store.BeginAppend(t.Context(), w.ws)
	_ = tx.EndDeviceSessions(w.dev)
	_ = tx.Rollback()

	w.nothingWithin(conn, 200*time.Millisecond)
}

// ── the broker ──────────────────────────────────────────────────────────────

// The server keeps no per-subscriber state: no cursor, no memory of who saw
// what. What it keeps is a channel with room for one pending poke.
func TestBrokerCoalescesAndScopes(t *testing.T) {
	b := signal.NewMemory()
	ws, other := vectors.WorkspaceID, vectors.Bytes16("other-ws")
	alice, bob := vectors.MemberA, vectors.MemberB

	a := b.Subscribe(ws, alice)
	defer a.Close()
	bo := b.Subscribe(ws, bob)
	defer bo.Close()
	elsewhere := b.Subscribe(other, alice)
	defer elsewhere.Close()

	for range 10 {
		b.Notify(ws)
	}
	// Every subscriber to the Workspace, whichever device holds it — and exactly
	// one pending poke each.
	if len(a.C) != 1 || len(bo.C) != 1 {
		t.Errorf("pending = %d and %d, want one each", len(a.C), len(bo.C))
	}
	if len(elsewhere.C) != 0 {
		t.Error("a poke crossed a Workspace boundary")
	}

	// Eviction is per (Workspace, device), and displaces a pending poke: a socket
	// about to close has nothing to sync.
	b.Evict(ws, alice)
	if got := <-a.C; got != signal.Evict {
		t.Errorf("alice got %v, want Evict", got)
	}
	// bob keeps his poke. Checking the length alone would pass an eviction that
	// displaced it, since Evict occupies the same one slot.
	if len(bo.C) != 1 {
		t.Fatal("bob's pending event vanished")
	}
	if got := <-bo.C; got != signal.Poke {
		t.Errorf("bob got %v; an eviction crossed devices", got)
	}

	// A closed subscription stops receiving.
	a.Close()
	a.Close() // idempotent
	b.Notify(ws)
	if len(a.C) != 0 {
		t.Error("a closed subscription still received")
	}
}
