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
	"syscall"
	"time"

	"github.com/loonybin/roundelay/authority"
	"github.com/loonybin/roundelay/httpapi"
	"github.com/loonybin/roundelay/identity"
	"github.com/loonybin/roundelay/internal/memstore"
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
	flag.Parse()

	if err := run(*addr, *dsn, *version, *admission); err != nil {
		log.Fatal(err)
	}
}

// referenceProfile is acme/p1, verbatim: every row answered, no optional row
// taken up, three rows answered "none".
//
// A server refuses to start with any row unset, so this is what answering them
// looks like rather than a set of defaults — there are none.
func referenceProfile(version string, admission profile.Admission) *profile.Profile {
	return &profile.Profile{
		Name:              "acme/p1",
		Namespace:         "acme",
		Creation:          profile.CreationDerived,
		DerivedNamespaces: []string{"main"},
		// Under `derived` the predicate is arithmetic the profile owns. This
		// reference admits any id, which a deployment that provisions per
		// Workspace must not do — see row 2's note.
		Creatable: func([32]byte, [16]byte) bool { return true },
		Admission: admission,
		InitialRoleTable: profile.RoleTable{
			"owner":       {Classes: []byte{0x01, 0x02, 0x80, 0x81, 0xBF}},
			"participant": {Classes: []byte{0x01}},
		},
		MemberKinds:         []string{"device"},
		GrantAdmissible:     profile.Say[profile.GrantAdmissible](nil),
		SizeClasses:         wire.Ladder{Classes: []int{512, 4096}, Step: 4096},
		DeployLabel:         profile.Say(regexp.MustCompile(`^\d+\.\d+\.\d+$`)),
		OpaqueClasses:       profile.Say[[]byte](nil),
		ExtensionClasses:    profile.Say[map[byte]string](nil),
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

func run(addr, dsn, version, admissionSpec string) error {
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

	prof := referenceProfile(version, placement)
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
		Addr:              addr,
		Handler:           router,
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
