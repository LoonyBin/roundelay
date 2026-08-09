package wire

// The in-band vocabularies of v1. Anything outside them fails closed: an unknown
// suite, op class, control type, prune type or ext_binding type is a refusal,
// never a shrug, because a value that is permitted-and-ignored is one a future
// reader might start honouring — and two implementations disagreeing about
// whether it counts is a convergence bug.
//
// Widening one of these is how a new representation ships. They live here rather
// than with the profile because they are the core's, and a core implementation
// must be able to run any profile: it cannot, if profiles dictate what it parses.

// Suites is the envelope constructions v1 serves.
var Suites = []byte{SuiteNone, SuiteEncrypted}

// CoreOpClasses is the classes the core assigns. A profile adds opaque classes
// in 0x40-0x7F and enables extension classes in 0xC0-0xFF; those are the
// profile's rows, and served_sets.op_classes carries all three ranges together.
var CoreOpClasses = []byte{ClassContent, ClassReprise, ClassControl, ClassPrune, ClassExtBinding}

// Control types — the ten payload types of class 0x80.
const (
	CtlWorkspaceGenesis = "workspace_genesis"
	CtlMemberRegister   = "member_register"
	CtlMemberAmend      = "member_amend"
	CtlGrant            = "grant"
	CtlRevoke           = "revoke"
	CtlRoleTable        = "role_table"
	CtlDelegate         = "delegate"
	CtlRevokeDelegation = "revoke_delegation"
	CtlRootHandover     = "root_handover"
	CtlRotate           = "rotate"
)

// ControlTypes is sorted lexicographically, which is the order GET /health
// serves it in.
var ControlTypes = []string{
	CtlDelegate,
	CtlGrant,
	CtlMemberAmend,
	CtlMemberRegister,
	CtlRevoke,
	CtlRevokeDelegation,
	CtlRoleTable,
	CtlRootHandover,
	CtlRotate,
	CtlWorkspaceGenesis,
}

// Prune types — the three payload types of class 0x81.
const (
	PruneSoft = "prune"
	PruneExt  = "prune_ext"
	PruneHard = "hard_prune"
)

// PruneTypes is sorted lexicographically.
var PruneTypes = []string{PruneHard, PruneSoft, PruneExt}

// ext_binding types — the two payload types of class 0xBF.
const (
	ExtBind   = "bind"
	ExtUnbind = "unbind"
)

// ExtBindingTypes is the fifth served set, and the one GET /health does not
// advertise.
//
// The other four exist to spare a client an all-or-nothing batch: one op of an
// unserved class fails the batch around it, so a client that cannot ask learns
// the vocabulary by bisecting its own queue. Nothing batches bindings — a
// deployment posts one per class, by hand, and reads the answer immediately —
// so there is no such batch here to spare.
var ExtBindingTypes = []string{ExtBind, ExtUnbind}

// AdvisoryPrefix marks a control type as advisory for ever: it bears no
// authority, alters no derived state, and a reader that does not serve one
// hash-chains past it without interpreting it.
//
// v1 defines no advisory type. The reservation is not a feature; it is a place
// kept — and kept now, in v1, because the readers that will meet the future
// types are the v1 readers, being the ones that never update. A reservation made
// in v3 would reach nobody who needs it.
const AdvisoryPrefix = "note_"

// Advisory reports whether a control type is advisory. No load-bearing type may
// ever be named this way; the partition is fixed in v1 and no later version may
// cross it.
func Advisory(controlType string) bool {
	return len(controlType) > len(AdvisoryPrefix) && controlType[:len(AdvisoryPrefix)] == AdvisoryPrefix
}
