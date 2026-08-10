package conformance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loonybin/roundelay/internal/conformance"
)

func load(t *testing.T) *conformance.Checklist {
	t.Helper()
	c, err := conformance.Load(filepath.Join("..", "..", "conformance", "checklist.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The README says both lints currently pass. This is the thing that says so.
func TestTheCheckedInChecklistPasses(t *testing.T) {
	c := load(t)
	vocab := conformance.Vocabulary()
	for _, r := range []conformance.Result{
		c.Structure(),
		c.Coverage(vocab),
		c.Vocabulary(vocab),
		c.Observability(),
	} {
		if !r.OK() {
			t.Errorf("%s failed with %d problems:\n  %s", r.Lint, len(r.Problems),
				strings.Join(r.Problems, "\n  "))
		}
	}
}

func TestChecklistShape(t *testing.T) {
	c := load(t)
	if len(c.Items) != 250 {
		t.Errorf("%d items, the README says 250", len(c.Items))
	}
	if n := len(conformance.Vocabulary()); n != 122 {
		t.Errorf("%d codes, the document lists 117 server plus 5 client", n)
	}
}

// A synthetic checklist, so the lints are exercised against failure rather than
// only against a file that passes.
func lint(t *testing.T, body string) map[string][]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checklist.yaml")
	if err := writeFile(path, body); err != nil {
		t.Fatal(err)
	}
	c, err := conformance.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	vocab := conformance.Vocabulary()
	out := map[string][]string{}
	for _, r := range []conformance.Result{c.Structure(), c.Coverage(vocab), c.Vocabulary(vocab), c.Observability()} {
		out[r.Lint] = r.Problems
	}
	return out
}

func TestCoverageCatchesAnUnexercisedCode(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: CONF-LOG-001
    requirement: something observable
    spec: "docs/01-the-log.md"
    subject: server
    observable: black-box
    codes: [not_found]
    test: tests/conformance/test_oplog.py::test_x
`)
	if len(got["coverage"]) == 0 {
		t.Fatal("coverage passed a checklist exercising one code out of 122")
	}
	if len(got["vocabulary"]) != 0 {
		t.Errorf("vocabulary flagged a real code: %v", got["vocabulary"])
	}
}

// The lint that catches the mistake anybody actually makes.
func TestVocabularyCatchesAnInventedCode(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: CONF-LOG-001
    requirement: something observable
    spec: "docs/01-the-log.md"
    subject: server
    observable: black-box
    codes: [not_fnud]
    test: tests/conformance/test_oplog.py::test_x
`)
	if len(got["vocabulary"]) != 1 || !strings.Contains(got["vocabulary"][0], "not_fnud") {
		t.Errorf("vocabulary = %v", got["vocabulary"])
	}
}

func TestStructureCatchesShapeProblems(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: LOG-1
    requirement: bad id
    spec: "x"
    subject: nobody
    observable: grey-box
    codes: []
    test: not-a-binding
  - id: CONF-LOG-001
    requirement: ok
    spec: "x"
    subject: server
    observable: black-box
    codes: [not_found, not_found]
    test: tests/conformance/test_oplog.py::test_x
  - id: CONF-LOG-001
    requirement: duplicate id
    spec: "x"
    subject: server
    observable: black-box
    codes: []
    test: tests/conformance/test_oplog.py::test_y
`)
	joined := strings.Join(got["structure"], "\n")
	for _, want := range []string{"id is not", "subject", "observable", "test binding", "duplicate id", "codes repeat"} {
		if !strings.Contains(joined, want) {
			t.Errorf("structure missed %q:\n%s", want, joined)
		}
	}
}

// The failure mode observability exists for: an internal fact marked black-box
// with nothing observable beside it.
func TestObservabilityCatchesAMislabelledInternalItem(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: CONF-DISC-001
    requirement: Bodies of any class with bit 7 clear are never parsed.
    spec: "docs/README.md"
    subject: server
    observable: black-box
    codes: []
    test: tests/conformance/test_discipline.py::test_x
`)
	if len(got["observability"]) != 1 {
		t.Fatalf("observability = %v", got["observability"])
	}
}

// And the case it must not fire on: a compound requirement that mentions an
// internal property in passing while asserting observable ones beside it.
func TestObservabilityIgnoresCompoundRequirementsWithEvidence(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: CONF-WIRE-011
    requirement: >
      A profile-defined opaque class is handled exactly as 0x01: stored and served
      byte-identically, never parsed, and admitted only by a role that names it. One
      the profile has not declared is refused unsupported_op_class.
    spec: "docs/01-the-log.md"
    subject: server
    observable: black-box
    codes: [unsupported_op_class, role_forbids_op_class]
    test: tests/conformance/test_wire.py::test_x
`)
	if len(got["observability"]) != 0 {
		t.Errorf("observability fired on an item with observable evidence: %v", got["observability"])
	}
}

// Marking the same item white-box is never a problem, whatever it says.
func TestObservabilityOnlyJudgesBlackBoxItems(t *testing.T) {
	got := lint(t, `
version: 1
items:
  - id: CONF-DISC-001
    requirement: Bodies of any class with bit 7 clear are never parsed.
    spec: "docs/README.md"
    subject: server
    observable: white-box
    codes: []
    test: tests/conformance/test_discipline.py::test_x
`)
	if len(got["observability"]) != 0 {
		t.Errorf("observability judged a white-box item: %v", got["observability"])
	}
}

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o644) }

// ── the bindings lint ───────────────────────────────────────────────────────

func bindingList() *conformance.Checklist {
	return &conformance.Checklist{Items: []conformance.Item{
		{ID: "CONF-A-001", Observable: "black-box", Test: "tests/conformance/test_a.py::test_one"},
		{ID: "CONF-A-002", Observable: "white-box", Test: "oplog/oplog_test.go::TestTwo"},
		{ID: "CONF-A-003", Observable: "black-box", Test: "tests/conformance/test_a.py::test_three"},
	}}
}

func TestBindingsAcceptsWhatTheSuiteCollected(t *testing.T) {
	// Collected node ids are suite-relative and carry pytest's parametrisation
	// tag; the column is repository-relative and names the function.
	r := bindingList().Bindings(&conformance.Bindings{Items: map[string][]string{
		"CONF-A-001": {"test_a.py::test_one[128-encrypted_control_op]", "test_a.py::test_one[129-x]"},
	}})
	if !r.OK() {
		t.Fatalf("expected agreement, got %v", r.Problems)
	}
	if !strings.Contains(r.Checked, "1 of 3") || !strings.Contains(r.Checked, "2 described only") {
		t.Errorf("the count is the point of the lint: %q", r.Checked)
	}
}

func TestBindingsCatchesDrift(t *testing.T) {
	r := bindingList().Bindings(&conformance.Bindings{Items: map[string][]string{
		"CONF-A-001": {"test_a.py::test_renamed"},
	}})
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "test_renamed") {
		t.Fatalf("a renamed test must be reported: %v", r.Problems)
	}
}

func TestBindingsCatchesAnOrphan(t *testing.T) {
	// A typo in a marker otherwise reads as coverage of something.
	r := bindingList().Bindings(&conformance.Bindings{Items: map[string][]string{
		"CONF-A-004": {"test_a.py::test_four"},
	}})
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "no such item") {
		t.Fatalf("an unknown item id must be reported: %v", r.Problems)
	}
}

// The observability lint's mechanical half: a black-box item may only be
// decided inside the suite, because everywhere else has a store handle in reach.
func TestObservabilityRefusesABlackBoxItemDecidedInGo(t *testing.T) {
	list := bindingList()
	list.Items[0].Test = "oplog/oplog_test.go::TestOne"
	r := list.Observability()
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "outside tests/conformance/") {
		t.Fatalf("black-box decided in a Go package must be reported: %v", r.Problems)
	}
	// A white-box item decided there is the normal case, and the row that just
	// has not been placed yet is caught by Structure, not here.
	list.Items[0].Observable = "white-box"
	if r := list.Observability(); !r.OK() {
		t.Fatalf("white-box in Go is the normal case: %v", r.Problems)
	}
}
