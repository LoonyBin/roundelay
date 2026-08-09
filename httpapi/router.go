package httpapi

import (
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/loonybin/roundelay/codes"
)

// versionShaped is the first-segment test.
//
// It is not the `^v[0-9]+$` of Compatibility §3. That pattern matches `v01`,
// which the same document and the conformance checklist both list as an ordinary
// unrouted path answering 404 not_found — and the checklist is authoritative
// where the layers and it disagree. A canonical version carries no leading zero,
// so `v01` is a mistyped URL rather than a version this server is older than.
var versionShaped = regexp.MustCompile(`^v(0|[1-9][0-9]*)$`)

// Router is the contract-version demultiplexer, and the only thing that decides
// between "this server is older than me" and "I built the wrong URL".
//
// Both are 404s and a client must be able to tell them apart: the first is
// recoverable and worth surfacing to someone, the second is a bug in the client.
// A bare 404 for an unserved version cannot be told from a typo, which is why
// unsupported_contract_version exists and carries what is served.
type Router struct {
	contracts map[string]http.Handler
	served    []string
	health    *Health
}

// NewRouter returns a router serving the health endpoints and no contract
// version. Add versions with Contract.
func NewRouter(h *Health) *Router {
	return &Router{contracts: map[string]http.Handler{}, health: h}
}

// Contract registers the handler for a contract version, named without its
// slash — "v1".
//
// A functional route is never added to a version already served: a new route
// ships under a new version, so that "does this server have the route" is always
// answered by contract_versions before a request is built, and never by a 404 a
// client has to interpret.
func (rt *Router) Contract(version string, h http.Handler) {
	if !versionShaped.MatchString(version) {
		panic("httpapi: contract version " + strconv.Quote(version) + " is not version-shaped")
	}
	rt.contracts[version] = h
	rt.served = append(rt.served, version)
	slices.SortFunc(rt.served, compareVersions)
	if rt.health != nil {
		rt.health.contracts = slices.Clone(rt.served)
	}
}

// Served is the contract versions this router serves, ascending.
func (rt *Router) Served() []string { return slices.Clone(rt.served) }

// compareVersions orders by the number, not by the text.
//
// The document says `served` is ascending without saying ascending in what, and
// the two readings part company at v10: lexicographically it precedes v2. A
// version is a number with a letter in front of it, so this sorts as one.
func compareVersions(a, b string) int {
	an, _ := strconv.Atoi(strings.TrimPrefix(a, "v"))
	bn, _ := strconv.Atoi(strings.TrimPrefix(b, "v"))
	return an - bn
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	seg, rest := firstSegment(r.URL.Path)

	// The health endpoints sit outside the version prefix, because a client must
	// be able to ask what the server supports before it knows what the server
	// supports. Putting discovery behind the thing being discovered is a
	// bootstrap failure.
	if seg == "health" {
		switch rest {
		case "/":
			rt.health.serveHealth(w, r)
		case "/db":
			rt.health.serveDB(w, r)
		default:
			notFound(w)
		}
		return
	}

	if !versionShaped.MatchString(seg) {
		notFound(w)
		return
	}
	h, ok := rt.contracts[seg]
	if !ok {
		Refuse(w, codes.UnsupportedContractVersion, map[string]any{
			"requested": seg,
			"served":    rt.Served(),
		})
		return
	}

	r2 := r.Clone(r.Context())
	r2.URL.Path = rest
	h.ServeHTTP(w, r2)
}

// firstSegment splits "/v1/w/x/ops" into "v1" and "/w/x/ops". A path with one
// segment yields a rest of "/", so a version handler sees a root request rather
// than an empty path.
func firstSegment(p string) (seg, rest string) {
	p = strings.TrimPrefix(p, "/")
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return p, "/"
	}
	return p[:i], p[i:]
}

// notFound is the ordinary unrouted answer: no such thing.
//
// It is also what a request with an unexpected method receives. The status table
// carries no 405 and the vocabulary is closed, so there is no code for "not that
// verb" — and "no such thing" is true of a route that exists only under another
// method.
func notFound(w http.ResponseWriter) { Refuse(w, codes.NotFound, nil) }

// NotFound writes the ordinary unrouted answer. A contract version's own mux
// uses it for a suffix it does not serve.
func NotFound(w http.ResponseWriter, _ *http.Request) { notFound(w) }
