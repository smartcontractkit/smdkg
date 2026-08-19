package v1

import "testing"

// Hard enforcement of this package's test-only purpose (see the package documentation in tdh2shim.go): any
// binary other than a test binary that links this package panics at startup, before the deprecated pre-fix
// G_bar derivation could ever be executed. This guard lives in a separate file so that tdh2shim.go remains a
// verbatim copy of the pre-fix implementation.
func init() {
	if !testing.Testing() {
		panic("dkgocr/internal/tdh2shim/v1 is the deprecated pre-fix TDH2 shim, preserved for upgrade path " +
			"tests only; it must never be linked into a non-test binary - use dkgocr/tdh2shim instead")
	}
}
