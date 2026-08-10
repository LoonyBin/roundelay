// Package conformance reads the checklist and holds the lints over it.
//
// The checklist is authoritative: "the five layer documents defer to this file".
// So a lint here is not a style check — it is the thing that stops the
// authoritative document and the vocabulary it cites from drifting apart.
package conformance

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Item is one checklist row.
type Item struct {
	ID          string   `yaml:"id"`
	Requirement string   `yaml:"requirement"`
	Spec        string   `yaml:"spec"`
	Subject     string   `yaml:"subject"`
	Observable  string   `yaml:"observable"`
	Codes       []string `yaml:"codes"`
	Test        string   `yaml:"test"`
}

// Checklist is the parsed file.
type Checklist struct {
	Version int    `yaml:"version"`
	Spec    string `yaml:"spec"`
	Items   []Item `yaml:"items"`
}

// Load reads the checklist.
func Load(path string) (*Checklist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Checklist
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Result is one lint's verdict.
type Result struct {
	Lint     string
	Problems []string
	// Checked says what the lint was able to decide, for a lint that cannot
	// decide the whole of what it is named for.
	Checked string
}

// OK reports whether the lint passed.
func (r Result) OK() bool { return len(r.Problems) == 0 }

var (
	idPattern   = regexp.MustCompile(`^CONF-[A-Z]+-\d{3}$`)
	testPattern = regexp.MustCompile(`^[\w./-]+::[\w:]+$`)
	subjects    = []string{"server", "client", "profile"}
	observables = []string{"black-box", "white-box"}
)

// Structure checks the shape every item must have. It is not one of the two
// named lints; it is what those two assume.
func (c *Checklist) Structure() Result {
	r := Result{Lint: "structure", Checked: "every item's id, subject, observable, test binding and code list"}
	seen := map[string]bool{}
	for _, it := range c.Items {
		bad := func(format string, args ...any) {
			r.Problems = append(r.Problems, it.ID+": "+fmt.Sprintf(format, args...))
		}
		if !idPattern.MatchString(it.ID) {
			bad("id is not CONF-<AREA>-<NNN>")
		}
		if seen[it.ID] {
			bad("duplicate id")
		}
		seen[it.ID] = true
		if strings.TrimSpace(it.Requirement) == "" {
			bad("requirement is empty")
		}
		if !slices.Contains(subjects, it.Subject) {
			bad("subject %q is not one of %v", it.Subject, subjects)
		}
		if !slices.Contains(observables, it.Observable) {
			bad("observable %q is not one of %v", it.Observable, observables)
		}
		if !testPattern.MatchString(it.Test) {
			bad("test binding %q is not <file>::<name>", it.Test)
		}
		for i := 1; i < len(it.Codes); i++ {
			if it.Codes[i-1] == it.Codes[i] {
				bad("codes repeat %q", it.Codes[i])
			}
		}
	}
	return r
}

// Coverage is the first named lint: every code in the code list appears in some
// item's codes.
//
// A code nothing exercises is a rule nothing tests, and the vocabulary is closed
// precisely so that every member of it means something a client can meet.
func (c *Checklist) Coverage(vocabulary []string) Result {
	r := Result{Lint: "coverage", Checked: "every code in the code list appears in some item's codes"}
	cited := map[string]bool{}
	for _, it := range c.Items {
		for _, code := range it.Codes {
			cited[code] = true
		}
	}
	for _, code := range vocabulary {
		if !cited[code] {
			r.Problems = append(r.Problems, "no item exercises "+code)
		}
	}
	slices.Sort(r.Problems)
	return r
}

// Vocabulary runs coverage the other way: every code an item cites exists in the
// code list.
//
// Not one of the two named lints, and the one that catches the mistake anybody
// actually makes. A code a server may not invent locally is one a checklist item
// may not invent either, and a typo in a `codes` list is otherwise invisible —
// it silently satisfies coverage for nothing.
func (c *Checklist) Vocabulary(vocabulary []string) Result {
	r := Result{Lint: "vocabulary", Checked: "every code an item cites exists in the code list"}
	known := map[string]bool{}
	for _, code := range vocabulary {
		known[code] = true
	}
	// The signal close codes are numbers, and the checklist cites them as such.
	for _, n := range []string{"4400", "4401", "4403"} {
		known[n] = true
	}
	seen := map[string]bool{}
	for _, it := range c.Items {
		for _, code := range it.Codes {
			if known[code] || seen[it.ID+code] {
				continue
			}
			seen[it.ID+code] = true
			r.Problems = append(r.Problems, it.ID+" cites "+code+", which is not in the code list")
		}
	}
	slices.Sort(r.Problems)
	return r
}

// internalVocabulary is the language of a fact no observer holds. A requirement
// that uses one of these is describing server-side state rather than traffic.
var internalVocabulary = []struct {
	phrase string
	why    string
}{
	{"from server storage", "names what the store holds, which no response carries"},
	{"durably recorded", "a durable write is not visible in the response it precedes"},
	{"never parsed", "not parsing is the absence of an effect, and absence is not traffic"},
	{"refuses to start", "startup happens before any request exists to observe it"},
	{"at rest", "names what is on disk"},
	{"frozen wrap vectors", "asserted against a fixture rather than against a response"},
}

// Observability is the second named lint, and it has two halves.
//
// As stated — "every black-box item is decidable from HTTP and WebSocket
// traffic alone" — it is a property of the test that implements an item rather
// than of the row that describes it. The mechanical form is "the test bound to
// this item reaches for no fixture but the transport", and that became
// decidable when the suite arrived: the conftest under SuiteRoot publishes one
// fixture, the server's base URL, and builds every other out of HTTP calls
// against it. So an item decided in there satisfies the property by
// construction, and an item decided anywhere else cannot, because everywhere
// else in this repository is a Go package with a store handle in reach. That is
// the second half, and it holds over every row rather than only the bound ones,
// because the column is a claim about where the item will be decided.
//
// The first half is the failure mode the lint was written for: an item marked
// black-box whose requirement is written in the language of a fact no observer
// holds. Together they catch both the mislabelled row and the row that quietly
// plans to settle a black-box requirement with a store handle.
func (c *Checklist) Observability() Result {
	r := Result{
		Lint:    "observability",
		Checked: "every black-box item speaks of observable evidence, and is decided in " + SuiteRoot,
	}
	for _, it := range c.Items {
		if it.Observable != "black-box" {
			continue
		}
		if test := strings.TrimSpace(it.Test); !strings.HasPrefix(test, SuiteRoot) {
			r.Problems = append(r.Problems, fmt.Sprintf(
				"%s is black-box but is decided by %s, which is outside %s and so has more than the transport in reach",
				it.ID, test, SuiteRoot))
		}
		// An item that cites a code has observable evidence by construction: a
		// refusal is traffic. So the net is only cast over items with none —
		// which is where a mislabelled internal fact actually hides.
		//
		// Without this the lint fires on compound requirements that mention an
		// internal property in passing while asserting several observable ones
		// beside it, and the internal clause is separately covered white-box.
		// That is prose, not a mislabelling.
		if len(it.Codes) > 0 {
			continue
		}
		lower := strings.ToLower(it.Requirement)
		for _, v := range internalVocabulary {
			if strings.Contains(lower, v.phrase) {
				r.Problems = append(r.Problems,
					fmt.Sprintf("%s is black-box but says %q, which %s", it.ID, v.phrase, v.why))
			}
		}
	}
	slices.Sort(r.Problems)
	return r
}
