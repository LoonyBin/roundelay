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
func Minimal() *profile.Profile {
	return &profile.Profile{
		Name:              "acme/p1",
		Namespace:         "acme",
		Creation:          profile.CreationDerived,
		DerivedNamespaces: []string{"main"},
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
