// Command conformance-lint runs the lints over the conformance checklist.
//
// A conforming release runs them. Exit status is non-zero if any lint fails.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/loonybin/roundelay/internal/conformance"
)

// allLints is every lint this command can run, in the order it reports them.
//
// Two of them decide a checklist against *this* repository rather than against
// itself: coverage compares the cited codes to the vocabulary compiled into
// this tree, and bindings compares the items to the tests collected from it. A
// checklist that lives on another branch — `main` carries the spec but none of
// the implementation — can only be held to the three that read the document
// alone. Hence -lints.
var allLints = []string{"structure", "coverage", "vocabulary", "observability", "bindings"}

func main() {
	// -fix reconciles the checklist's test column with what the suite collected.
	// It is the one direction that is safe to automate: the suite is the record
	// of what ran, and the column is a claim about it.
	fix := flag.Bool("fix", false, "rewrite the test column of bound items to match the suite")
	only := flag.String("lints", "", "comma-separated subset of "+strings.Join(allLints, ",")+" (default: all)")
	flag.Parse()
	path := "conformance/checklist.yaml"
	if flag.NArg() > 0 {
		path = flag.Arg(0)
	}

	// An unknown name is a typo in a CI invocation, and a typo that silently
	// ran nothing would report green. Refuse it instead.
	selected := map[string]bool{}
	for _, name := range strings.Split(*only, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.Contains(allLints, name) {
			log.Fatalf("unknown lint %q: choose from %s", name, strings.Join(allLints, ", "))
		}
		selected[name] = true
	}
	runs := func(name string) bool { return len(selected) == 0 || selected[name] }

	list, err := conformance.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	// The binding collectors read this repository, so load them only when
	// something is going to ask them a question. Linting another branch's
	// checklist must not depend on a bindings file it never had.
	var bindings *conformance.Bindings
	if *fix || runs("bindings") {
		if bindings, err = conformance.LoadBindings("conformance/bindings.json"); err != nil {
			log.Fatal(err)
		}
		// Two collectors, one record. The black-box suite writes its file as it
		// collects; the white-box claims are comments in Go tests, read here.
		goBindings, err := conformance.GoBindings(".")
		if err != nil {
			log.Fatal(err)
		}
		bindings.Merge(goBindings)
	}
	vocab := conformance.Vocabulary()

	fmt.Printf("%s: %d items, %d codes\n", path, len(list.Items), len(vocab))

	if *fix {
		changed, err := conformance.Reconcile(path, list, bindings)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range changed {
			fmt.Printf("  · %s\n", c)
		}
		fmt.Printf("  %d bindings reconciled\n", len(changed))
		if list, err = conformance.Load(path); err != nil {
			log.Fatal(err)
		}
	}

	var results []conformance.Result
	for _, name := range allLints {
		if !runs(name) {
			continue
		}
		switch name {
		case "structure":
			results = append(results, list.Structure())
		case "coverage":
			results = append(results, list.Coverage(vocab))
		case "vocabulary":
			results = append(results, list.Vocabulary(vocab))
		case "observability":
			results = append(results, list.Observability())
		case "bindings":
			results = append(results, list.Bindings(bindings))
		}
	}

	failed := false
	for _, r := range results {
		if r.OK() {
			fmt.Printf("  ✓ %-14s %s\n", r.Lint, r.Checked)
			continue
		}
		failed = true
		fmt.Printf("  ✗ %-14s %d problems\n", r.Lint, len(r.Problems))
		for _, p := range r.Problems {
			fmt.Printf("      %s\n", p)
		}
	}
	if failed {
		os.Exit(1)
	}
}
