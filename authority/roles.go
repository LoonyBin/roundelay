package authority

import (
	"slices"
	"strings"

	"github.com/loonybin/roundelay/codes"
	"github.com/loonybin/roundelay/oplog"
	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/strictjson"
	"github.com/loonybin/roundelay/wire"
)

// CheckRoleTable applies the rules a role_table certificate must satisfy from
// its own bytes.
//
// All of them are self-contained: they read no log, decide no authority and
// record nothing, which is the whole of what a check above the signature may do.
// Two of them judge values for what they say, and they are shape here on the
// precedent a rotation that skips an epoch already sets.
func CheckRoleTable(roles []RoleEntry) *oplog.Refusal {
	bad := refuse(unproc, codes.MalformedRoleTable, nil)

	seen := map[string]bool{}
	owners := 0
	for _, e := range roles {
		if !strictjson.ValidToken(e.Role) {
			return bad
		}
		if seen[e.Role] {
			return bad
		}
		seen[e.Role] = true
		if e.Role == profile.OwnerRole {
			owners++
		}

		classes := map[byte]bool{}
		for _, c := range e.Classes {
			if classes[c] {
				return bad
			}
			classes[c] = true
		}
		// Rule 2: 0x80 ops, when not Root-signed, require owner and no other
		// role — so no other role may name the class at all.
		if e.Role != profile.OwnerRole && classes[wire.ClassControl] {
			return bad
		}

		types := map[string]bool{}
		for _, t := range e.PruneTypes {
			if !slices.Contains(wire.PruneTypes, t) || types[t] {
				return bad
			}
			types[t] = true
		}
		// prune_types is present in every entry, and a non-empty one on an entry
		// that does not name 0x81 describes a lane the role cannot enter.
		if len(e.PruneTypes) > 0 && !classes[wire.ClassPrune] {
			return bad
		}
	}
	// Rule 1: exactly one role is named owner — the authority role.
	if owners != 1 {
		return bad
	}
	return nil
}

// PermitsClass reports whether a role entry admits an op class.
func PermitsClass(e profile.RoleEntry, class byte) bool {
	return slices.Contains(e.Classes, class)
}

// PermitsPruneType applies rule 5, the one destructive lane.
//
// An entry naming 0x81 confers prune only; every other payload type is conferred
// only by naming it explicitly. This is the only place a role is finer than a
// class, and it is deliberate rather than a general mechanism: hard_prune is the
// single operation in this protocol that destroys, so an unqualified grant that
// silently included it would be the one misgrant with no repair.
//
// The default runs the safe way, which is why every profile written before the
// type existed keeps meaning exactly what it meant: fold, do not destroy.
func PermitsPruneType(e profile.RoleEntry, pruneType string) bool {
	if !PermitsClass(e, wire.ClassPrune) {
		return false
	}
	if len(e.PruneTypes) == 0 {
		return pruneType == wire.PruneSoft
	}
	return slices.Contains(e.PruneTypes, pruneType)
}

// ToProfileTable converts a certificate's rows into the table shape the rest of
// the server reads, so that the profile's initial table and one adopted in band
// are the same type and cannot drift.
func ToProfileTable(roles []RoleEntry) profile.RoleTable {
	out := make(profile.RoleTable, len(roles))
	for _, e := range roles {
		out[e.Role] = profile.RoleEntry{
			Classes:    slices.Clone(e.Classes),
			PruneTypes: slices.Clone(e.PruneTypes),
		}
	}
	return out
}

// SortedRoles is the roles a refusal carries, sorted lexicographically.
//
// Determinism, on the precedent the fields list of an unknown-field refusal
// already sets. The set a device holds has no natural order, so without a stated
// one two servers answer the same state with different bytes, and anything that
// compares refusals — a test, a cache, a client that dedupes its alarms — sees a
// difference that is not there.
func SortedRoles(roles []string) []string {
	out := slices.Clone(roles)
	slices.Sort(out)
	return slices.Compact(out)
}

// onlyPath reports whether a decode failure names exactly the one path.
//
// It is how a shape verdict with a code of its own — malformed_root_pk on a
// delegate, say — is told apart from the general malformed_control_payload
// without parsing the document twice.
func onlyPath(err error, path string) bool { return onlyPaths(err, path) }

func onlyPaths(err error, paths ...string) bool {
	m, ok := err.(*strictjson.Malformed)
	if !ok || len(m.Fields) == 0 {
		return false
	}
	for _, f := range m.Fields {
		if !slices.Contains(paths, f) {
			return false
		}
	}
	return true
}

// underRoles reports whether every offending path sits inside the roles array,
// which is what makes a misshapen entry the table's verdict rather than the
// payload's.
func underRoles(err error) bool {
	var fields []string
	switch e := err.(type) {
	case *strictjson.Malformed:
		fields = e.Fields
	case *strictjson.UnknownFields:
		fields = e.Fields
	default:
		return false
	}
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if f != "roles" && !strings.HasPrefix(f, "roles.") {
			return false
		}
	}
	return true
}
