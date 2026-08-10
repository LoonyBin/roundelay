// Package testprofile carries the fictional profiles the tests run against.
//
// acme/p1 is the minimal profile of the profile-obligations document, verbatim:
// every row answered, no optional row taken up, three rows answered "none".
// Nothing here is shipped or borrowed — the core carries no profile, and a
// profile that had to exist would be a dependency wearing a different hat.
package testprofile

import (
	"regexp"

	"github.com/loonybin/roundelay/profile"
	"github.com/loonybin/roundelay/wire"
)

// Minimal is acme/p1: the smallest thing that starts.
//
// A server started against it serves 0x01, 0x02, 0x80, 0x81 and 0xBF, and
// refuses every other class byte. 0xBF is on that list because it is
// core-assigned and a core class is served whatever a profile says — an empty
// row 10 does not withdraw the class, it empties what a binding may name.
// DerivedNamespaces are the frozen literals the reference profile derives
// Workspace ids from — four of them, so one identity holds four Workspaces and
// no more.
//
// A namespace is sixteen bytes chosen once and written down, never a name
// hashed at startup: recomputing one would make Workspace identity depend on
// two languages' UUID libraries agreeing, and an id is signed into every header
// the Workspace will ever carry.
var DerivedNamespaces = [][16]byte{
	{0x9e, 0x4f, 0x2c, 0x1a, 0x7b, 0x63, 0x84, 0xd5, 0xa0, 0x11, 0x36, 0xe8, 0xcf, 0x52, 0x9d, 0x07},
	{0x41, 0xd8, 0x0b, 0x6f, 0x92, 0x27, 0xe3, 0x50, 0x18, 0xbc, 0x74, 0xa9, 0x3f, 0x66, 0xd1, 0x2e},
	{0x08, 0xa3, 0x5d, 0xc4, 0x1f, 0xb0, 0x76, 0x99, 0xe2, 0x4d, 0x8a, 0x31, 0x55, 0xcb, 0x07, 0xf4},
	{0xb7, 0x12, 0x69, 0xae, 0x30, 0xd4, 0x8c, 0x2b, 0x5f, 0x93, 0xe0, 0x17, 0xaa, 0x48, 0xc6, 0x85},
}

func Minimal() *profile.Profile {
	return &profile.Profile{
		Name:              "acme/p1",
		Namespace:         "acme",
		Creation:          profile.CreationDerived,
		DerivedNamespaces: DerivedNamespaces,
		Admission:         profile.AdmissionServer,
		InitialRoleTable: profile.RoleTable{
			"owner":       {Classes: []byte{0x01, 0x02, 0x80, 0x81, 0xBF}},
			"participant": {Classes: []byte{0x01}},
		},
		MemberKinds:         []string{"device"},
		GrantAdmissible:     profile.Say[profile.GrantAdmissible](nil),
		SizeClasses:         wire.Ladder{Classes: []int{512, 4096}, Step: 4096},
		DeployLabel:         profile.Say(regexp.MustCompile(`^\d+\.\d+\.\d+$`)),
		OpaqueClasses:       profile.Say[[]byte](nil),
		ExtensionClasses:    profile.Say[map[byte]string](nil),
		HolderRefDerivation: "the holder's Root public key, verbatim",
		Version:             "1.4.2",
		Limits:              profile.Defaults(),
	}
}

// Extended takes up the two optional class rows, so that served_sets.op_classes
// carries a byte from each of the three ranges and extension_classes has a
// member to report.
func Extended() *profile.Profile {
	p := Minimal()
	p.Name = "acme/p2"
	p.OpaqueClasses = profile.Say([]byte{0x45})
	p.ExtensionClasses = profile.Say(map[byte]string{0xC5: "retention-sweep"})
	p.InitialRoleTable = profile.RoleTable{
		"owner": {Classes: []byte{0x01, 0x02, 0x45, 0x80, 0x81, 0xBF, 0xC5},
			PruneTypes: []string{wire.PruneSoft, wire.PruneExt, wire.PruneHard}},
		"participant": {Classes: []byte{0x01, 0x45}},
	}
	return p
}
