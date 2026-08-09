package httpapi

import (
	"context"
	"net/http"
	"slices"
	"strconv"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

// Probe answers whether the backing store is reachable, by making it answer a
// trivial query.
type Probe func(ctx context.Context) error

// Health serves the two unversioned, unauthenticated discovery endpoints.
type Health struct {
	profile   *profile.Profile
	probe     Probe
	contracts []string
}

// NewHealth returns the health endpoints for a validated profile. The probe is
// what GET /health/db asks; it is never consulted by GET /health.
func NewHealth(p *profile.Profile, probe Probe) *Health {
	return &Health{profile: p, probe: probe, contracts: []string{}}
}

// ServedSets is the four in-band vocabularies GET /health advertises.
//
// Four of the five, and the omission is deliberate: ext_binding types are the
// one set nothing batches on, so there is no all-or-nothing batch for a client
// to be spared.
type ServedSets struct {
	Suites       []int    `json:"suites"`
	OpClasses    []int    `json:"op_classes"`
	ControlTypes []string `json:"control_types"`
	PruneTypes   []string `json:"prune_types"`
}

// HealthResponse is the discovery document.
type HealthResponse struct {
	Status            string            `json:"status"`
	Version           string            `json:"version"`
	ContractVersions  []string          `json:"contract_versions"`
	ProtocolNamespace string            `json:"protocol_namespace"`
	Profile           string            `json:"profile"`
	ExtensionClasses  map[string]string `json:"extension_classes"`
	ServedSets        ServedSets        `json:"served_sets"`
	Limits            map[string]int    `json:"limits"`
}

// Document builds what GET /health serves. It reads no store and can answer
// while one is unavailable, which is the whole of what this endpoint is for.
func (h *Health) Document() HealthResponse {
	p := h.profile

	// Every enabled extension class mapped to its NAME, and {} when none —
	// present always, never absent, because absent is indistinguishable from a
	// server too old to carry the field, and a client that cannot tell those
	// apart guesses.
	//
	// Keys are the class number in decimal as a JSON string: JSON has no other
	// kind of key. No leading zeros, no hex spelling.
	ext := map[string]string{}
	for c, name := range p.ExtensionClasses.Value() {
		ext[strconv.Itoa(int(c))] = name
	}

	suites := make([]int, 0, len(wire.Suites))
	for _, s := range wire.Suites {
		suites = append(suites, int(s))
	}
	slices.Sort(suites)

	// Every class byte this server accepts, all three ranges alike, with nothing
	// to say which range a byte came from.
	classes := make([]int, 0, 8)
	for _, c := range p.ServedOpClasses() {
		classes = append(classes, int(c))
	}

	control := slices.Clone(wire.ControlTypes)
	slices.Sort(control)
	prune := slices.Clone(wire.PruneTypes)
	slices.Sort(prune)

	return HealthResponse{
		Status:            "ok",
		Version:           p.Version,
		ContractVersions:  slices.Clone(h.contracts),
		ProtocolNamespace: string(p.Namespace),
		Profile:           p.Name,
		ExtensionClasses:  ext,
		ServedSets: ServedSets{
			Suites:       suites,
			OpClasses:    classes,
			ControlTypes: control,
			PruneTypes:   prune,
		},
		Limits: map[string]int{
			"max_ops_per_batch":        p.Limits.MaxOpsPerBatch,
			"max_page_size":            p.Limits.MaxPageSize,
			"default_page_size":        p.Limits.DefaultPageSize,
			"signal_keepalive_seconds": int(p.Limits.SignalKeepalive.Seconds()),
		},
	}
}

func (h *Health) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		notFound(w)
		return
	}
	WriteJSON(w, http.StatusOK, h.Document())
}

func (h *Health) serveDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		notFound(w)
		return
	}
	if h.probe == nil {
		// A server with no probe cannot claim its store answers. Failing closed
		// here is the same rule every other unanswered question follows.
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	if err := h.probe(r.Context()); err != nil {
		Refuse(w, codes.StoreUnavailable, nil)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
