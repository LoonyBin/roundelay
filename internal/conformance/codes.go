package conformance

import "github.com/loonybin/roundelay/codes"

// Vocabulary is every code the document carries, taken from the generated
// package rather than re-parsed from the markdown.
//
// One reader of the code list, not two. A second parser is a second answer to
// "what is a code", and the whole point of generating the package was that there
// be one.
func Vocabulary() []string {
	out := make([]string, 0, len(codes.All))
	for _, s := range codes.All {
		out = append(out, string(s.Code))
	}
	return out
}
