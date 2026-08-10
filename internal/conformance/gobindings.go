package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

// itemMarker is how a Go test claims a checklist item, in a doc comment:
//
//	// conformance: CONF-PROF-004
//	func TestExactlyOneOwner(t *testing.T) { … }
//
// pytest has markers and a collection hook; Go has neither, so the claim is a
// comment and this reads it. Which is the same contract either way — the suite
// says what it decided, and the lint compares that against what the checklist
// claims, rather than trusting one of them.
var itemMarker = regexp.MustCompile(`\bCONF-[A-Z]+-\d+\b`)

// GoBindings collects item claims from every _test.go file under root.
//
// The black-box items are pytest's; these are the white-box ones — a profile
// that refuses to start, a role table with exactly one owner — which are
// properties of the build rather than of any request, and have no traffic for
// a black-box suite to look at.
func GoBindings(root string) (*Bindings, error) {
	out := &Bindings{Items: map[string][]string{}}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Neither the toolchain's business nor ours.
			if name := d.Name(); name == "vendor" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// A file that does not parse is the compiler's problem to report,
			// not this lint's — it has nothing to say about bindings.
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			for _, id := range itemMarker.FindAllString(fn.Doc.Text(), -1) {
				node := filepath.ToSlash(rel) + "::" + fn.Name.Name
				out.Items[id] = append(out.Items[id], node)
			}
		}
		return nil
	})
	return out, err
}

// Merge folds another source's claims in. Two sources may claim one item —
// a property worth deciding twice is worth recording twice.
func (b *Bindings) Merge(other *Bindings) {
	for id, nodes := range other.Items {
		b.Items[id] = append(b.Items[id], nodes...)
	}
}
