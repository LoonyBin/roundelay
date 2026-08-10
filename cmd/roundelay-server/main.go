// Command roundelay-server is a runnable deployment of the core.
//
// The core is a library and carries no profile. This binary supplies one — the
// fictional acme/p1 of the profile-obligations document — so that there is
// something to point a conformance suite at. A real deployment ships its own
// profile in its own repository and wires the same handlers; nothing here is
// part of the specification.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	ossignal "os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/internal/memstore"
	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/keyplane"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/pgstore"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/signal"
	"github.com/loonybin/roundelay/wire"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	dsn := flag.String("dsn", os.Getenv("ROUNDELAY_DSN"), "Postgres DSN; empty uses the in-memory store")
	version := flag.String("version", "0.0.1", "the deploy label GET /health reports")
	admission := flag.String("admission", "open", "open | token:<value>")
	// Two rows the reference answers "none". A deployment that takes them up is
	// a different deployment, and several conformance items are about exactly
	// what changes when it does — so they are knobs rather than constants.
	opaque := flag.String("opaque-classes", "", "comma-separated hex classes in 40-7f, e.g. 40,41")
	extensions := flag.String("extension-classes", "", "comma-separated <hex>=<name>, e.g. cc=purge")
	// Consumption. The core defines no unit; this deployment counts stored ops,
	// which is a measure and not the measure — any other would conform too.
	wsQuota := flag.Int("quota-ops-per-workspace", -1, "refuse a non-exempt write once the Workspace holds this many ops; -1 for no bound")
	memberQuota := flag.Int("quota-ops-per-member", -1, "the same, per member; -1 for no bound")
	flag.Parse()

	if err := run(*addr, *dsn, *version, *admission, *opaque, *extensions,
		*wsQuota, *memberQuota); err != nil {
		log.Fatal(err)
	}
}

// referenceProfile is acme/p1, verbatim: every row answered, no optional row
// taken up, three rows answered "none".
//
// A server refuses to start with any row unset, so this is what answering them
// looks like rather than a set of defaults — there are none.
func referenceProfile(version string, admission profile.Admission,
	opaque []byte, extensions map[byte]string) *profile.Profile {
	return &profile.Profile{
		Name:              "acme/p1",
		Namespace:         "acme",
		Creation:          profile.CreationDerived,
		DerivedNamespaces: testprofile.DerivedNamespaces,
		// No predicate under `derived`: the answer is uuid8(NS, root_pk), which
		// the core computes. A deployment that provisions per Workspace cannot
		// use this row at all — see row 2's note.
		Admission: admission,
		InitialRoleTable: profile.RoleTable{
			"owner":       {Classes: []byte{0x01, 0x02, 0x80, 0x81, 0xBF}},
			"participant": {Classes: []byte{0x01}},
		},
		MemberKinds:         []string{"device"},
		GrantAdmissible:     profile.Say[profile.GrantAdmissible](nil),
		SizeClasses:         wire.Ladder{Classes: []int{512, 4096}, Step: 4096},
		DeployLabel:         profile.Say(regexp.MustCompile(`^\d+\.\d+\.\d+$`)),
		OpaqueClasses:       profile.Say(opaque),
		ExtensionClasses:    profile.Say(extensions),
		HolderRefDerivation: "the holder's Root public key, verbatim",
		Version:             version,
		Limits:              profile.Defaults(),
	}
}

// tokenAdmission is the reference gate: one shared opaque string.
//
// The core defines no mechanism and no format — only the carrier. This is a
// deployment's choice and nothing here is protocol.
type tokenAdmission struct{ want string }

func (a tokenAdmission) Admit(_ context.Context, got string) bool {
	return a.want != "" && got == a.want
}

// parseOpaque reads the opaque-class list: hex bytes in 0x40-0x7f.
func parseOpaque(spec string) ([]byte, error) {
	if spec == "" {
		return nil, nil
	}
	var out []byte
	for _, part := range strings.Split(spec, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 16, 8)
		if err != nil {
			return nil, fmt.Errorf("opaque class %q: %w", part, err)
		}
		out = append(out, byte(n))
	}
	return out, nil
}

// parseExtensions reads the extension map: <hex>=<name>, the NAME being the
// thing two deployments must agree on for one class byte to mean one thing.
func parseExtensions(spec string) (map[byte]string, error) {
	if spec == "" {
		return nil, nil
	}
	out := map[byte]string{}
	for _, part := range strings.Split(spec, ",") {
		key, name, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, fmt.Errorf("extension class %q: want <hex>=<name>", part)
		}
		n, err := strconv.ParseUint(key, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("extension class %q: %w", part, err)
		}
		out[byte(n)] = name
	}
	return out, nil
}

// countingQuota is the reference measure: non-exempt ops this process has
// admitted, per Workspace and per member.
//
// It is *a* measure and not *the* measure. A deployment would count bytes
// currently held, or bytes written per month, or bytes excluding everything
// already reprised — all conformant, and a client cannot tell which one refused
// it. That is why the core defines none of it, and why nothing about this
// counter reaches the store interface: what an operator charges for is not the
// log's business.
//
// It counts in memory and starts again on restart, which a real one would not.
// Nothing observable depends on that: the verdict is what the suite reads.
type countingQuota struct {
	perWorkspace int
	perMember    int

	mu        sync.Mutex
	workspace map[[16]byte]int
	member    map[[32]byte]int
}

func newCountingQuota(perWorkspace, perMember int) *countingQuota {
	return &countingQuota{
		perWorkspace: perWorkspace, perMember: perMember,
		workspace: map[[16]byte]int{}, member: map[[32]byte]int{},
	}
}

// memberKey scopes a member's count to the Workspace it wrote in: the same
// device in two Workspaces is two accounts, because a Workspace is the only
// thing this protocol counts.
func memberKey(workspace, author [16]byte) [32]byte {
	var k [32]byte
	copy(k[:16], workspace[:])
	copy(k[16:], author[:])
	return k
}

func (q *countingQuota) Check(_ context.Context, workspace, author [16]byte, ops []oplog.Op) *oplog.Refusal {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.perWorkspace >= 0 && q.workspace[workspace] >= q.perWorkspace {
		// No index: every op in a batch shares one Workspace, so there is no op
		// for the refusal to name. And nothing else — no amount, no allowance,
		// no plan, no price, no URL. A deployment's commercial surface is not
		// protocol, and a code that carried one would be a code every client had
		// to parse differently per server.
		return &oplog.Refusal{Status: http.StatusPaymentRequired, Code: codes.WorkspaceQuotaExhausted}
	}

	key := memberKey(workspace, author)
	held := q.member[key]
	charged := 0
	for i, op := range ops {
		if exemptClass(op.Header().OpClass) {
			continue
		}
		if q.perMember >= 0 && held+charged >= q.perMember {
			// index names the first op at which the bound was crossed, which is
			// the only index that is a fact about the batch rather than about
			// the accounting: it is where counting stopped.
			return &oplog.Refusal{
				Status: http.StatusPaymentRequired, Code: codes.MemberQuotaExhausted,
				Fields: map[string]any{"index": i},
			}
		}
		charged++
	}

	// Admitted, so charge for it. The batch may still be refused below on its
	// own merits, which would overcount — a real measure reads what is stored
	// rather than what was let past, and this one is a reference.
	q.workspace[workspace] += charged
	q.member[key] += charged
	return nil
}

// exemptClass mirrors the core's own exemption, so the count never charges for
// an op the core will never refuse.
func exemptClass(class byte) bool {
	return class == wire.ClassControl || class == wire.ClassPrune
}

func run(addr, dsn, version, admissionSpec, opaqueSpec, extensionSpec string,
	wsQuota, memberQuota int) error {
	placement := profile.AdmissionOpen
	var admitter identity.Admitter = identity.AdmitAll{}
	switch {
	case admissionSpec == "open":
	case len(admissionSpec) > 6 && admissionSpec[:6] == "token:":
		placement = profile.AdmissionServer
		admitter = tokenAdmission{want: admissionSpec[6:]}
	default:
		return fmt.Errorf("unrecognised -admission %q", admissionSpec)
	}

	opaque, err := parseOpaque(opaqueSpec)
	if err != nil {
		return err
	}
	extensions, err := parseExtensions(extensionSpec)
	if err != nil {
		return err
	}

	prof := referenceProfile(version, placement, opaque, extensions)
	if err := prof.Validate(); err != nil {
		return err
	}

	ctx := context.Background()
	var (
		logStore oplog.Store
		ids      identity.Store
		vaults   keyplane.VaultStore
		probe    httpapi.Probe
		onEnded  func(func(member [16]byte))
	)

	if dsn == "" {
		mem := memstore.New()
		logStore, ids, vaults = mem, memstore.NewIdentity(mem), memstore.NewVault(mem)
		probe = func(context.Context) error { return nil }
		onEnded = mem.OnSessionsEnded
		log.Printf("store: in-memory (nothing survives a restart)")
	} else {
		pg, err := pgstore.Open(ctx, dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
		logStore, ids, vaults = pg, pgstore.NewIdentity(pg), pgstore.NewVault(pg)
		probe = func(ctx context.Context) error { return pg.Pool().Ping(ctx) }
		onEnded = pg.OnSessionsEnded
		log.Printf("store: postgres")
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	tokens := &identity.Tokens{
		Secret:     secret,
		AccessTTL:  prof.Limits.AccessTokenLifetime,
		RefreshTTL: prof.Limits.RefreshTokenLifetime,
	}
	if err := tokens.Validate(); err != nil {
		return err
	}

	broker := signal.NewMemory()
	auth := authority.New(prof)
	tokenAuth := httpapi.TokenAuth{Tokens: tokens}

	// The cascade: losing the last live grant, or amending a control key, kills
	// the device's refresh tokens and closes its live sockets. It fires after the
	// commit, which is where the store puts it.
	onEnded(func(member [16]byte) {
		_ = ids.RevokeRefreshFor(ctx, member)
		broker.EvictAll(member)
	})

	pipeline := &oplog.Pipeline{
		Profile: prof, Store: logStore, Authority: auth,
		Notify: func(ws [16]byte) { broker.Notify(ws) },
	}
	if wsQuota >= 0 || memberQuota >= 0 {
		pipeline.Quota = newCountingQuota(wsQuota, memberQuota)
		log.Printf("quota: %d ops per workspace, %d per member", wsQuota, memberQuota)
	}

	lookup := workspaceLookup{store: logStore}
	idh := &httpapi.IdentityHandler{
		Registrar: &identity.Registrar{
			Profile: prof, Store: ids, Lookup: lookup, Admission: admitter,
		},
		Sessions: &identity.Sessions{Profile: prof, Store: ids, Tokens: tokens},
	}
	reads := &httpapi.ReadHandler{Auth: tokenAuth, Store: logStore, Profile: prof, Authority: auth}
	kp := &httpapi.KeyplaneHandler{
		Auth: tokenAuth, Store: logStore, Profile: prof, Authority: auth, Bar2: auth,
		Publisher: &keyplane.Publisher{Profile: prof, Owner: auth},
	}
	vault := &httpapi.VaultHandler{Vault: &keyplane.Vault{Profile: prof, Store: vaults}}
	sig := &httpapi.SignalHandler{
		Auth: tokenAuth, Store: logStore, Profile: prof, Authority: auth, Broker: broker,
	}
	if err := sig.Validate(); err != nil {
		return err
	}

	router := httpapi.NewRouter(httpapi.NewHealth(prof, probe))
	v1 := http.NewServeMux()
	v1.Handle("POST /w/{workspace_id}/ops", &httpapi.OpsHandler{Auth: tokenAuth, Pipeline: pipeline})
	v1.HandleFunc("GET /w/{workspace_id}/ops", reads.ServeOps)
	v1.HandleFunc("GET /w/{workspace_id}/members", reads.ServeMembers)
	v1.HandleFunc("PUT /w/{workspace_id}/keywraps", kp.ServePublish)
	v1.HandleFunc("GET /w/{workspace_id}/keywraps/me", kp.ServeMyWraps)
	v1.HandleFunc("GET /w/{workspace_id}/epoch-keys", kp.ServeEpochKeys)
	v1.Handle("/w/{workspace_id}/signal", sig)
	v1.HandleFunc("POST /members", idh.ServeRegister)
	v1.HandleFunc("POST /members/{member_id}/challenge", idh.ServeChallenge)
	v1.HandleFunc("POST /members/{member_id}/token", idh.ServeToken)
	v1.HandleFunc("POST /members/{member_id}/token/refresh", idh.ServeRefresh)
	v1.HandleFunc("PUT /vault/{locator}", vault.ServeWrite)
	v1.HandleFunc("GET /vault/{locator}", vault.ServeRead)
	// Everything else under a served version is an ordinary unrouted path.
	v1.HandleFunc("/", httpapi.NotFound)
	router.Contract("v1", v1)

	srv := &http.Server{
		Addr: addr,
		// The body bound wraps everything, including /health and the socket
		// upgrade: "on any route" is the rule, and a rule enforced route by
		// route is one route away from being false.
		Handler:           httpapi.BoundBodies(prof.Limits.MaxRequestBytes, router),
		ReadHeaderTimeout: 10 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	// os/signal is aliased because `signal` here is the protocol's subscription
	// package.
	ossignal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("roundelay %s (%s) listening on %s", prof.Name, version, addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// workspaceLookup answers POST /v1/members' joining branch from the log.
type workspaceLookup struct{ store oplog.Store }

func (l workspaceLookup) CurrentRoot(ctx context.Context, ws [16]byte) ([32]byte, bool, error) {
	tx, err := l.store.BeginAppend(ctx, ws)
	if err != nil {
		return [32]byte{}, false, err
	}
	defer tx.Rollback()
	exists, err := tx.WorkspaceExists()
	if err != nil || !exists {
		return [32]byte{}, false, err
	}
	return tx.CurrentRoot()
}

func (l workspaceLookup) LiveDelegations(ctx context.Context, ws [16]byte) ([][32]byte, error) {
	tx, err := l.store.BeginAppend(ctx, ws)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at, err := tx.NextSeq()
	if err != nil {
		return nil, err
	}
	dels, err := tx.LiveDelegationsAt(at)
	if err != nil {
		return nil, err
	}
	out := make([][32]byte, 0, len(dels))
	for _, d := range dels {
		out = append(out, d.PK)
	}
	return out, nil
}
