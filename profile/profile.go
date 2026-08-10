// Package profile carries the eleven decisions the core refuses to make.
//
// A running server is core plus exactly one profile. There are no defaults:
// Validate refuses every unanswered row, because a silent default here is either
// a security hole or a convergence bug — a guessed protocol namespace would let
// two unrelated deployments' signatures verify against each other, and a guessed
// creation rule would let one identity mint Workspace ids that belong to
// another.
//
// "None" is an answer and absence is not, which is why the emptiable rows are
// wrapped in Declared rather than left to a nil slice. A profile that means to
// declare no opaque classes says so; a profile that forgot the row does not
// start.
package profile

import (
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/loonybin/roundelay/wire"
)

// Declared distinguishes an answered row from an unanswered one, for rows whose
// answer may be empty.
type Declared[T any] struct {
	v   T
	set bool
}

// Say answers a row. Say[[]byte](nil) is "none", which is different from leaving
// the row alone.
func Say[T any](v T) Declared[T] { return Declared[T]{v: v, set: true} }

// Get returns the answer and whether the row was answered at all.
func (d Declared[T]) Get() (T, bool) { return d.v, d.set }

// Value returns the answer, zero where the row was unanswered. Callers that have
// run Validate may use it freely.
func (d Declared[T]) Value() T { return d.v }

// Answered reports whether the row was answered.
func (d Declared[T]) Answered() bool { return d.set }

// Creation is row 2: how Workspace ids come into being.
type Creation uint8

const (
	// CreationUnset is the zero value, and never valid.
	CreationUnset Creation = iota
	// CreationDerived computes a Root's Workspace ids offline from frozen
	// namespaces. Nothing external observes a founding, so a deployment that
	// provisions, quotas or bills per Workspace cannot use it: it acquires
	// Workspaces it never issued and cannot attribute to an account.
	CreationDerived
	// CreationExplicit assigns ids through the profile's own creation authority.
	// It is the only policy with an issuing step, and that step is where
	// provisioning attaches.
	CreationExplicit
	// CreationPredicate is a profile-defined predicate that is neither.
	CreationPredicate
)

// Admission is row 3: where the founding registration is gated, never how it
// decides. The mechanism is deployment policy and the core defines no field,
// header or format for one.
type Admission uint8

const (
	// AdmissionUnset is the zero value, and never valid.
	AdmissionUnset Admission = iota
	// AdmissionOpen enforces nothing, and is a legitimate declaration: a
	// self-hosted deployment serving one person has no abuse boundary worth
	// defending, and saying so explicitly beats a policy nobody enforces.
	AdmissionOpen
	// AdmissionServer gates inside the server, at POST /v1/members.
	AdmissionServer
	// AdmissionUpstream gates in a layer in front of the server.
	AdmissionUpstream
)

// RoleEntry is one role's lane set.
type RoleEntry struct {
	// Classes is the op classes this role may author.
	Classes []byte
	// PruneTypes restricts what an entry naming 0x81 confers. Empty confers
	// `prune` and nothing else — the bare entry — so a role that must fold an
	// extension class or reclaim bytes names the types explicitly.
	PruneTypes []string
}

// RoleTable is row 4, keyed by role token.
type RoleTable map[string]RoleEntry

// OwnerRole is the one token every table must carry exactly once.
const OwnerRole = "owner"

// Creatable answers row 2's predicate: may this Root bring this Workspace id
// into being? It is consulted at every genesis and sees both halves.
type Creatable func(rootPK [32]byte, workspaceID [16]byte) bool

// GrantAdmissible answers row 6. Absent means admit everything.
type GrantAdmissible func(role string, granter, grantee [16]byte) bool

// Limits are the deployment-tunable settings. Unlike the eleven rows these do
// have defaults, which a profile inherits unless it says otherwise.
type Limits struct {
	MaxOpsPerBatch        int
	MaxPageSize           int
	DefaultPageSize       int
	SignalKeepalive       time.Duration
	SignalAuthDeadline    time.Duration
	ChallengeLifetime     time.Duration
	ChallengesPerWindow   int
	ChallengeWindow       time.Duration
	VaultFetchesPerWindow int
	VaultFetchWindow      time.Duration
	AccessTokenLifetime   time.Duration
	RefreshTokenLifetime  time.Duration

	// MaxRequestBytes bounds the total request body, on every route.
	//
	// Compatibility §8 tables no default for this one: the conventions say a
	// deployment SHOULD bound its request bodies and MUST document the bound,
	// leaving the number to the deployment. What is not the deployment's is the
	// code — request_too_large is in the closed vocabulary precisely so that the
	// one limit every route shares has a name in it. So a value lives here, and
	// a deployment overrides it.
	MaxRequestBytes int64
}

// Defaults are the values Compatibility §8 tables.
func Defaults() Limits {
	return Limits{
		MaxOpsPerBatch:        1000,
		MaxPageSize:           1000,
		DefaultPageSize:       500,
		SignalKeepalive:       25 * time.Second,
		SignalAuthDeadline:    10 * time.Second,
		ChallengeLifetime:     120 * time.Second,
		ChallengesPerWindow:   120,
		ChallengeWindow:       86400 * time.Second,
		VaultFetchesPerWindow: 20,
		VaultFetchWindow:      86400 * time.Second,
		AccessTokenLifetime:   15 * time.Minute,
		RefreshTokenLifetime:  365 * 24 * time.Hour,
		// Room for a full batch: a thousand ops of the larger size class, with
		// base64 expansion and JSON around them.
		MaxRequestBytes: 8 << 20,
	}
}

// Profile is the eleven rows, plus the deployment's tunables and its deploy
// label.
type Profile struct {
	// Name is "<namespace>/<revision>", reported as `profile` by GET /health.
	Name string

	// Row 1.
	Namespace wire.Namespace
	// Row 2.
	Creation Creation
	// DerivedNamespaces is row 2's ordered frozen namespaces under
	// CreationDerived, and unused otherwise.
	//
	// Frozen literals, never recomputed at startup: recomputing them would make
	// Workspace identity depend on two languages' UUID libraries agreeing, and
	// a Workspace id is signed into every header the Workspace will ever carry.
	// So they are sixteen bytes here rather than a name to be hashed.
	DerivedNamespaces [][16]byte
	// Creatable is row 2's predicate under CreationExplicit or
	// CreationPredicate. Under CreationDerived it is unused and MUST be nil:
	// the answer there is arithmetic, and Derives computes it.
	Creatable Creatable
	// Row 3.
	Admission Admission
	// Row 4.
	InitialRoleTable RoleTable
	// Row 5.
	MemberKinds []string
	// Row 6, optional: Say[GrantAdmissible](nil) admits everything.
	GrantAdmissible Declared[GrantAdmissible]
	// Row 7.
	SizeClasses wire.Ladder
	// Row 8, optional: Say[*regexp.Regexp](nil) constrains nothing. Opaque to
	// clients either way.
	DeployLabel Declared[*regexp.Regexp]
	// Row 9, optional: Say[[]byte](nil) declares no opaque classes.
	OpaqueClasses Declared[[]byte]
	// Row 10: may be empty, but every member carries a mandatory NAME.
	ExtensionClasses Declared[map[byte]string]
	// Row 11: how a registration's 32 opaque bytes are computed. The server never
	// computes one — the derivation happens on the device — so this is a
	// declaration rather than a function. It is required all the same: a
	// deployment whose clients differ has silently stopped grouping anybody's
	// devices, and nothing refuses.
	HolderRefDerivation string

	// Version is the deploy label GET /health reports, governed by row 8.
	Version string
	// Limits are the tunables. Start from Defaults.
	Limits Limits
}

// Error is every problem with a profile, so a misconfigured deployment learns
// all of them at once rather than one restart at a time.
type Error struct{ Problems []string }

func (e *Error) Error() string {
	s := fmt.Sprintf("profile: %d unanswered or invalid rows:", len(e.Problems))
	for _, p := range e.Problems {
		s += "\n  - " + p
	}
	return s
}

// Validate refuses a profile with any row unset or inconsistent. A server calls
// it at startup and does not start without it.
func (p *Profile) Validate() error {
	var probs []string
	bad := func(format string, args ...any) { probs = append(probs, fmt.Sprintf(format, args...)) }

	if p.Name == "" {
		bad("profile name is unset; a server MUST report it as `profile` in GET /health")
	}

	// Row 1.
	if _, err := wire.NewNamespace(string(p.Namespace)); err != nil {
		bad("row 1 PROTOCOL_NAMESPACE: %v", err)
	}

	// Row 2.
	switch p.Creation {
	case CreationUnset:
		bad("row 2 creation policy is unset")
	case CreationDerived:
		if len(p.DerivedNamespaces) == 0 {
			bad("row 2 is `derived` but declares no frozen namespaces")
		}
		if p.Creatable != nil {
			// Otherwise the row says one thing and the predicate does another,
			// and which one decides is whichever the core happens to consult.
			bad("row 2 is `derived` and also supplies a predicate")
		}
	case CreationExplicit, CreationPredicate:
		if p.Creatable == nil {
			bad("row 2 is `explicit` or a predicate but supplies no Creatable")
		}
	default:
		bad("row 2 creation policy %d is not a policy", p.Creation)
	}

	// Row 3.
	if p.Admission == AdmissionUnset {
		bad("row 3 admission placement is unset; `open` is a legal answer and must be said")
	}

	// Row 4.
	owners := 0
	for token, entry := range p.InitialRoleTable {
		if !wire.ValidToken(token) {
			bad("row 4 role token %q is not a 1-32 byte kebab-case token", token)
		}
		if token == OwnerRole {
			owners++
		}
		for _, c := range entry.Classes {
			if !p.servesClass(c) {
				bad("row 4 role %q names class %#x, which this profile does not serve", token, c)
			}
		}
		for _, t := range entry.PruneTypes {
			if !slices.Contains(wire.PruneTypes, t) {
				bad("row 4 role %q names prune type %q, which is not a served type", token, t)
			}
		}
	}
	switch {
	case len(p.InitialRoleTable) == 0:
		bad("row 4 initial role table is unset")
	case owners != 1:
		bad("row 4 initial role table carries %d `owner` entries; it MUST carry exactly one", owners)
	}

	// Row 5.
	if len(p.MemberKinds) == 0 {
		bad("row 5 member-kind set is unset")
	}
	for _, k := range p.MemberKinds {
		if !wire.ValidToken(k) {
			bad("row 5 member kind %q is not a 1-32 byte kebab-case token", k)
		}
	}

	// Row 6.
	if !p.GrantAdmissible.Answered() {
		bad("row 6 grant admissibility is unanswered; Say[GrantAdmissible](nil) admits everything")
	}

	// Row 7.
	if err := p.SizeClasses.Validate(); err != nil {
		bad("row 7 size classes: %v", err)
	} else if p.SizeClasses.AmbiguousOversize() {
		bad("row 7 largest size class %d is not a multiple of the oversize step %d, so two "+
			"conforming implementations pad the same payload to different lengths",
			p.SizeClasses.Largest(), p.SizeClasses.Step)
	}

	// Row 8.
	if !p.DeployLabel.Answered() {
		bad("row 8 deploy-label format is unanswered; Say[*regexp.Regexp](nil) constrains nothing")
	} else if re := p.DeployLabel.Value(); re != nil && p.Version != "" && !re.MatchString(p.Version) {
		bad("deploy label %q does not match row 8's format %q", p.Version, re)
	}

	// Row 9.
	if !p.OpaqueClasses.Answered() {
		bad("row 9 opaque class set is unanswered; Say[[]byte](nil) declares none")
	}
	for _, c := range p.OpaqueClasses.Value() {
		if c&0xC0 != 0x40 {
			bad("row 9 declares class %#x, which is outside the profile range 0x40-0x7F", c)
		}
	}

	// Row 10.
	if !p.ExtensionClasses.Answered() {
		bad("row 10 extension class set is unanswered; Say[map[byte]string](nil) enables none")
	}
	seen := map[string]byte{}
	for c, name := range p.ExtensionClasses.Value() {
		if !wire.IsExtension(c) {
			bad("row 10 enables class %#x, which is outside the extension range 0xC0-0xFF", c)
		}
		if !wire.ValidToken(name) {
			bad("row 10 NAME %q for class %#x is not a 1-32 byte kebab-case token", name, c)
		}
		if prev, dup := seen[name]; dup {
			bad("row 10 NAME %q is bound to both %#x and %#x; it must be unique within the namespace", name, prev, c)
		}
		seen[name] = c
	}

	// Row 11.
	if p.HolderRefDerivation == "" {
		bad("row 11 holder_ref derivation is undeclared")
	}

	probs = append(probs, p.Limits.problems()...)

	if len(probs) > 0 {
		slices.Sort(probs)
		return &Error{Problems: probs}
	}
	return nil
}

func (l Limits) problems() []string {
	var probs []string
	check := func(name string, v int) {
		if v <= 0 {
			probs = append(probs, fmt.Sprintf("limit %s is %d; start from profile.Defaults()", name, v))
		}
	}
	check("max_ops_per_batch", l.MaxOpsPerBatch)
	check("max_page_size", l.MaxPageSize)
	check("default_page_size", l.DefaultPageSize)
	check("signal_keepalive_seconds", int(l.SignalKeepalive/time.Second))
	if l.DefaultPageSize > l.MaxPageSize {
		probs = append(probs, fmt.Sprintf("default_page_size %d exceeds max_page_size %d",
			l.DefaultPageSize, l.MaxPageSize))
	}
	return probs
}

// servesClass reports whether a class byte is one this profile accepts: a core
// assignment, a declared opaque class, or an enabled extension class.
func (p *Profile) servesClass(c byte) bool {
	if slices.Contains(wire.CoreOpClasses, c) {
		return true
	}
	if slices.Contains(p.OpaqueClasses.Value(), c) {
		return true
	}
	_, ok := p.ExtensionClasses.Value()[c]
	return ok
}

// ServesClass reports whether this profile accepts a class byte. A byte absent
// from it is refused unsupported_op_class.
func (p *Profile) ServesClass(c byte) bool { return p.servesClass(c) }

// ServedOpClasses is every class byte this server accepts — core assignments,
// the profile's opaque classes and the enabled extension classes alike —
// ascending, with nothing to say which range a byte came from.
func (p *Profile) ServedOpClasses() []byte {
	out := slices.Clone(wire.CoreOpClasses)
	out = append(out, p.OpaqueClasses.Value()...)
	for c := range p.ExtensionClasses.Value() {
		out = append(out, c)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ExtensionName returns the NAME an extension class is enabled under.
func (p *Profile) ExtensionName(c byte) (string, bool) {
	name, ok := p.ExtensionClasses.Value()[c]
	return name, ok
}

// Derives reports whether this Root may found this Workspace id under a derived
// creation policy: whether the id is uuid8(NS, root_pk) for one of the frozen
// namespaces.
//
// Under `derived` a Root's Workspace ids are computable offline by anyone
// holding the key, which is the whole of the row's value — so the server
// computes the same arithmetic rather than taking the id on trust.
func (p *Profile) Derives(rootPK [32]byte, workspace [16]byte) bool {
	for _, ns := range p.DerivedNamespaces {
		if wire.UUID8(ns, rootPK) == workspace {
			return true
		}
	}
	return false
}
