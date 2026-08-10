package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// SuiteRoot is where the black-box suite lives, and the only directory a
// black-box item may be decided in.
//
// The observability lint's real form is "the test bound to this item reaches
// for no fixture but the transport". That is not a property of a row, and no
// amount of reading the checklist decides it. It becomes decidable when the
// suite it points into offers nothing else: the conftest under this root
// publishes one fixture, the server's base URL, and every other fixture is
// built out of HTTP calls against it. So for an item bound here, the property
// holds by construction — and for a black-box item bound anywhere else it
// fails, because everywhere else is a Go package with a store handle in reach.
const SuiteRoot = "tests/conformance/"

// Bindings is the item → test map the suite writes as it collects.
//
// It is written by the suite rather than read from the checklist on purpose.
// The checklist's `test` column is a claim; this file is a record of what was
// collected. Comparing them is the whole point: a column naming a test that no
// longer exists reads exactly like a column naming one that does.
type Bindings struct {
	Items map[string][]string `json:"items"`
}

// LoadBindings reads the file the suite writes. A missing file is not an error
// — it means the suite has not been run — and yields an empty set.
func LoadBindings(path string) (*Bindings, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Bindings{Items: map[string][]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var b Bindings
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Items == nil {
		b.Items = map[string][]string{}
	}
	return &b, nil
}

// paramSuffix is pytest's parametrisation tag: one test function, many cases.
// The binding is to the function, so the tag comes off before comparing.
var paramSuffix = regexp.MustCompile(`\[[^\]]*\]$`)

// normalise turns a collected node id into the spelling the checklist uses:
// suite-root-relative in the file, repository-relative in the column.
func normalise(nodeID string) string {
	id := paramSuffix.ReplaceAllString(nodeID, "")
	if !strings.HasPrefix(id, SuiteRoot) {
		id = SuiteRoot + id
	}
	return id
}

// Bindings is the third lint, and the one that makes the `test` column mean
// something.
//
// Without it the column is prose: a path and a function name that nobody
// checks, which stays plausible long after the test it names has been renamed
// or deleted. The suite writes down what it actually collected; this compares
// the two and reports the difference in both directions.
//
// An item nothing has bound is not a failure. The suite is admittedly partial,
// and a checklist that refused to describe a requirement until someone had
// tested it would be a worse document. But the count is reported, because
// "250 items" and "250 items that run" are very different claims and the
// distance between them should be visible in the output rather than in
// somebody's head.
func (c *Checklist) Bindings(b *Bindings) Result {
	r := Result{Lint: "bindings"}
	known := map[string]*Item{}
	for i := range c.Items {
		known[c.Items[i].ID] = &c.Items[i]
	}

	// A binding naming an item that is not in the checklist. Usually a typo in
	// a marker, and one that would otherwise look like coverage.
	var orphans []string
	for id := range b.Items {
		if _, ok := known[id]; !ok {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	for _, id := range orphans {
		r.Problems = append(r.Problems,
			fmt.Sprintf("%s: bound by %s, but no such item", id, strings.Join(b.Items[id], ", ")))
	}

	bound, blackBox := 0, 0
	for _, item := range c.Items {
		nodes, ok := b.Items[item.ID]
		if !ok {
			continue
		}
		bound++
		if item.Observable == "black-box" {
			blackBox++
		}

		got := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n = normalise(n); !slices.Contains(got, n) {
				got = append(got, n)
			}
		}
		sort.Strings(got)

		if !slices.Contains(got, strings.TrimSpace(item.Test)) {
			r.Problems = append(r.Problems, fmt.Sprintf(
				"%s: test column says %q, suite collected %s",
				item.ID, item.Test, strings.Join(got, ", ")))
		}
	}

	r.Checked = fmt.Sprintf("%d of %d items decided by a test that runs (%d black-box); %d described only",
		bound, len(c.Items), blackBox, len(c.Items)-bound)
	return r
}

// Reconcile rewrites the `test` column of every bound item to the node id the
// suite actually collected, and reports what it changed.
//
// The column is hand-written, so it drifts the moment a test is renamed — and
// a stale binding is invisible, because a path that names nothing looks exactly
// like a path that names something. Rewriting is a line edit rather than a
// YAML round-trip on purpose: this file carries the prose that makes it
// authoritative, and a marshaller would reflow every folded block in it to fix
// one string.
func Reconcile(path string, c *Checklist, b *Bindings) ([]string, error) {
	want := map[string]string{}
	for _, item := range c.Items {
		nodes, ok := b.Items[item.ID]
		if !ok || len(nodes) == 0 {
			continue
		}
		got := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n = normalise(n); !slices.Contains(got, n) {
				got = append(got, n)
			}
		}
		sort.Strings(got)
		// One item, one binding. Several tests may exercise a requirement, but
		// the column names the one that decides it, and picking the first in
		// sorted order keeps the file stable across collection orders.
		if got[0] != strings.TrimSpace(item.Test) {
			want[item.ID] = got[0]
		}
	}
	if len(want) == 0 {
		return nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	var changed []string
	id := ""
	for i, line := range lines {
		if rest, ok := strings.CutPrefix(line, "- id: "); ok {
			id = strings.TrimSpace(rest)
			continue
		}
		if !strings.HasPrefix(line, "  test: ") || id == "" {
			continue
		}
		if to, ok := want[id]; ok {
			changed = append(changed, fmt.Sprintf("%s: %s → %s",
				id, strings.TrimPrefix(line, "  test: "), to))
			lines[i] = "  test: " + to
			delete(want, id)
		}
		id = ""
	}
	for id := range want {
		return nil, fmt.Errorf("%s: no `test:` line found for %s", path, id)
	}
	return changed, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}
