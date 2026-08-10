// Command conformance-lint runs the lints over the conformance checklist.
//
// A conforming release runs them. Exit status is non-zero if any lint fails.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/loonybin/roundelay/internal/conformance"
)

func main() {
	path := "conformance/checklist.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	list, err := conformance.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	vocab := conformance.Vocabulary()

	fmt.Printf("%s: %d items, %d codes\n", path, len(list.Items), len(vocab))

	failed := false
	for _, r := range []conformance.Result{
		list.Structure(),
		list.Coverage(vocab),
		list.Vocabulary(vocab),
		list.Observability(),
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
