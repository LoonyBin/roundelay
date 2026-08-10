// Command conformance-lint runs the lints over the conformance checklist.
//
// A conforming release runs them. Exit status is non-zero if any lint fails.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/loonybin/roundelay/internal/conformance"
)

func main() {
	// -fix reconciles the checklist's test column with what the suite collected.
	// It is the one direction that is safe to automate: the suite is the record
	// of what ran, and the column is a claim about it.
	fix := flag.Bool("fix", false, "rewrite the test column of bound items to match the suite")
	flag.Parse()
	path := "conformance/checklist.yaml"
	if flag.NArg() > 0 {
		path = flag.Arg(0)
	}
	list, err := conformance.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	bindings, err := conformance.LoadBindings("conformance/bindings.json")
	if err != nil {
		log.Fatal(err)
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

	failed := false
	for _, r := range []conformance.Result{
		list.Structure(),
		list.Coverage(vocab),
		list.Vocabulary(vocab),
		list.Observability(),
		list.Bindings(bindings),
	} {
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
