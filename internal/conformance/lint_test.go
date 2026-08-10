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
