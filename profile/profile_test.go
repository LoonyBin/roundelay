package profile_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/internal/testprofile"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

func TestMinimalProfileValidates(t *testing.T) {
	if err := testprofile.Minimal().Validate(); err != nil {
		t.Fatalf("acme/p1 was refused:\n%v", err)
	}
	if err := testprofile.Extended().Validate(); err != nil {
		t.Fatalf("acme/p2 was refused:\n%v", err)
	}
}

// There are no defaults. Every row unanswered is a refusal to start, because a
// silent default here is either a security hole or a convergence bug.
// conformance: CONF-PROF-001
//
// A server refuses to start with any obligation unset. There are no defaults
// for the eleven rows — a default is a decision made by whoever wrote the
// library rather than by the deployment answering for it — so an unset row is
// a build that must not serve.
func TestEveryRowMustBeAnswered(t *testing.T) {
	for _, c := range []struct {
		row    string
		break_ func(p *profile.Profile)
		want   string
	}{
		{"1 namespace", func(p *profile.Profile) { p.Namespace = "" }, "row 1"},
		{"2 creation", func(p *profile.Profile) { p.Creation = profile.CreationUnset }, "row 2"},
		{"2 derived without namespaces", func(p *profile.Profile) { p.DerivedNamespaces = nil }, "row 2"},
		{"3 admission", func(p *profile.Profile) { p.Admission = profile.AdmissionUnset }, "row 3"},
		{"4 role table", func(p *profile.Profile) { p.InitialRoleTable = nil }, "row 4"},
		{"5 member kinds", func(p *profile.Profile) { p.MemberKinds = nil }, "row 5"},
		{"6 grant admissibility", func(p *profile.Profile) { p.GrantAdmissible = profile.Declared[profile.GrantAdmissible]{} }, "row 6"},
		{"7 size classes", func(p *profile.Profile) { p.SizeClasses = wire.Ladder{} }, "row 7"},
		{"8 deploy label", func(p *profile.Profile) { p.DeployLabel = profile.Declared[*regexp.Regexp]{} }, "row 8"},
		{"9 opaque classes", func(p *profile.Profile) { p.OpaqueClasses = profile.Declared[[]byte]{} }, "row 9"},
		{"10 extension classes", func(p *profile.Profile) { p.ExtensionClasses = profile.Declared[map[byte]string]{} }, "row 10"},
		{"11 holder_ref", func(p *profile.Profile) { p.HolderRefDerivation = "" }, "row 11"},
		{"name", func(p *profile.Profile) { p.Name = "" }, "profile name"},
	} {
		t.Run(c.row, func(t *testing.T) {
			p := testprofile.Minimal()
			c.break_(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("a profile with %s unanswered started", c.row)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error does not name %q:\n%v", c.want, err)
			}
		})
	}
}

// "None" is an answer and absence is not. A row explicitly answered empty must
// validate, and the same row left alone must not.
func TestNoneIsAnAnswer(t *testing.T) {
	p := testprofile.Minimal()
	if err := p.Validate(); err != nil {
		t.Fatalf("Say(nil) on rows 6, 8, 9 and 10 was refused:\n%v", err)
	}
	p.OpaqueClasses = profile.Declared[[]byte]{}
	if p.Validate() == nil {
		t.Error("an unanswered row 9 was indistinguishable from Say(nil)")
	}
}

// Row 4 must carry exactly one owner.
// conformance: CONF-PROF-004
//
// Exactly one role named owner. It is the role the core itself names — an
// owner grant requires root, and only owner may author 0x80 — so a table
// without one describes a Workspace nobody can administer.
func TestRoleTableOwnerCount(t *testing.T) {
	p := testprofile.Minimal()
	delete(p.InitialRoleTable, "owner")
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Errorf("a table with no owner started: %v", err)
	}
}

// A role may not name a class the profile does not serve: a lane nobody can
// write in is a table that cannot mean what it says.
func TestRoleTableCannotNameAnUnservedClass(t *testing.T) {
	p := testprofile.Minimal()
	p.InitialRoleTable["participant"] = profile.RoleEntry{Classes: []byte{0x45}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "0x45") {
		t.Errorf("a role naming an undeclared opaque class started: %v", err)
	}
}

// Row 7 has no additive direction and one shape that is worse than either:
// a ladder whose largest class is not a multiple of its step separates the two
// readings of the oversize rule, so two conforming peers pad differently.
func TestAmbiguousLadderIsRefused(t *testing.T) {
	p := testprofile.Minimal()
	p.SizeClasses = wire.Ladder{Classes: []int{512, 3000}, Step: 1024}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "row 7") {
		t.Errorf("an ambiguous ladder started: %v", err)
	}
}

// Row 10's NAMEs must be unique within the namespace: two implementations must
// agree what a class means before either writes one.
func TestExtensionNamesAreUnique(t *testing.T) {
	p := testprofile.Extended()
	p.ExtensionClasses = profile.Say(map[byte]string{0xC5: "sweep", 0xC6: "sweep"})
	p.InitialRoleTable["owner"] = profile.RoleEntry{Classes: []byte{0x01, 0x02, 0x45, 0x80, 0x81, 0xBF, 0xC5, 0xC6}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Errorf("two classes shared a NAME: %v", err)
	}
}

func TestClassRanges(t *testing.T) {
	p := testprofile.Minimal()
	p.OpaqueClasses = profile.Say([]byte{0x01}) // core-assigned, not profile range
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "0x40-0x7F") {
		t.Errorf("a core class was accepted as an opaque declaration: %v", err)
	}

	p = testprofile.Minimal()
	p.ExtensionClasses = profile.Say(map[byte]string{0x45: "x"})
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "0xC0-0xFF") {
		t.Errorf("a profile class was accepted as an extension: %v", err)
	}
}

// Every class byte the server accepts, all three ranges alike, ascending, with
// nothing to say which range a byte came from.
func TestServedOpClasses(t *testing.T) {
	got := testprofile.Minimal().ServedOpClasses()
	want := []byte{0x01, 0x02, 0x80, 0x81, 0xBF}
	if string(got) != string(want) {
		t.Errorf("minimal serves %x, want %x", got, want)
	}

	got = testprofile.Extended().ServedOpClasses()
	want = []byte{0x01, 0x02, 0x45, 0x80, 0x81, 0xBF, 0xC5}
	if string(got) != string(want) {
		t.Errorf("extended serves %x, want %x", got, want)
	}

	p := testprofile.Extended()
	for _, c := range want {
		if !p.ServesClass(c) {
			t.Errorf("%#x is served but ServesClass says otherwise", c)
		}
	}
	for _, c := range []byte{0x00, 0x03, 0x44, 0x7F, 0x82, 0xBE, 0xC0, 0xFF} {
		if p.ServesClass(c) {
			t.Errorf("%#x is not served but ServesClass admits it", c)
		}
	}
}

// The deploy label is governed by row 8 when row 8 names a format.
func TestDeployLabelMatchesItsFormat(t *testing.T) {
	p := testprofile.Minimal()
	p.Version = "not-a-version"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "deploy label") {
		t.Errorf("a label outside row 8's format started: %v", err)
	}
}

// The tunables do have defaults, unlike the eleven rows — but a forgotten zero
// is not one of them.
func TestLimitsMustBePositive(t *testing.T) {
	p := testprofile.Minimal()
	p.Limits = profile.Limits{}
	err := p.Validate()
	if err == nil {
		t.Fatal("a profile with zeroed limits started")
	}
	for _, want := range []string{"max_ops_per_batch", "max_page_size", "default_page_size", "signal_keepalive_seconds"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s:\n%v", want, err)
		}
	}

	p = testprofile.Minimal()
	p.Limits.DefaultPageSize = p.Limits.MaxPageSize + 1
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds max_page_size") {
		t.Errorf("a default page size above the maximum started: %v", err)
	}
}

// A misconfigured deployment learns everything at once rather than one restart
// at a time.
func TestValidateReportsEveryProblem(t *testing.T) {
	p := testprofile.Minimal()
	p.Namespace = ""
	p.Admission = profile.AdmissionUnset
	p.HolderRefDerivation = ""

	var e *profile.Error
	err := p.Validate()
	if err == nil {
		t.Fatal("three unanswered rows started")
	}
	if !asProfileError(err, &e) || len(e.Problems) < 3 {
		t.Fatalf("got %v, want at least three problems", err)
	}
}

func asProfileError(err error, target **profile.Error) bool {
	e, ok := err.(*profile.Error)
	if ok {
		*target = e
	}
	return ok
}

// The advisory reservation is a place kept, with no member in it.
func TestAdvisoryTypesAreReservedAndEmpty(t *testing.T) {
	for _, ct := range wire.ControlTypes {
		if wire.Advisory(ct) {
			t.Errorf("v1 serves an advisory control type: %q", ct)
		}
	}
	if !wire.Advisory("note_something") {
		t.Error("note_something is not recognised as advisory")
	}
	if wire.Advisory("note_") {
		t.Error("the bare prefix is not a type")
	}
	if wire.Advisory("notes") {
		t.Error("notes was read as advisory")
	}
}

// The served sets are sorted the way GET /health must serve them.
func TestServedSetsAreSorted(t *testing.T) {
	for _, set := range [][]string{wire.ControlTypes, wire.PruneTypes, wire.ExtBindingTypes} {
		for i := 1; i < len(set); i++ {
			if set[i-1] >= set[i] {
				t.Errorf("%v is not sorted lexicographically at %d", set, i)
			}
		}
	}
	if len(wire.ControlTypes) != 10 {
		t.Errorf("v1 defines %d control types, want 10", len(wire.ControlTypes))
	}
	if len(wire.PruneTypes) != 3 {
		t.Errorf("v1 defines %d prune types, want 3", len(wire.PruneTypes))
	}
}

// conformance: CONF-PROF-006
//
// Every role token in an initial table is the protocol's one token shape, which
// is the shape a role_table certificate is held to. A profile that started with
// a role no certificate could name would have a table with no in-band
// replacement: the only way to change it would be to redeploy.
func TestInitialRoleTokensAreReplaceable(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	for role := range testprofile.Minimal().InitialRoleTable {
		if !shape.MatchString(role) {
			t.Errorf("role %q is not a token a role_table could carry", role)
		}
		if n := len(role); n < 1 || n > 32 {
			t.Errorf("role %q is %d bytes, outside 1-32", role, n)
		}
	}

	for _, bad := range []string{"Owner", "-owner", "owner-", "", strings.Repeat("o", 33)} {
		p := testprofile.Minimal()
		p.InitialRoleTable[bad] = p.InitialRoleTable["owner"]
		if err := p.Validate(); err == nil {
			t.Errorf("a table naming %q started", bad)
		}
	}
}

// conformance: CONF-PROF-001
//
// Row 2 answered two ways at once is a profile that does not say what it does:
// under `derived` the answer is arithmetic the core computes, and a predicate
// beside it would mean whichever the core happened to consult decides.
func TestDerivedTakesNoPredicate(t *testing.T) {
	p := testprofile.Minimal()
	p.Creatable = func([32]byte, [16]byte) bool { return true }
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "row 2") {
		t.Errorf("derived with a predicate started: %v", err)
	}
}
