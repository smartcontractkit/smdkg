package vess

import (
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/mre"
	"github.com/smartcontractkit/smdkg/internal/crypto/xof"
)

// All members that need to be serialized when sending a dealing over the network.

// A unverified dealing is the underlying data structure holding the result of the vess.Deal(...) operation.
// When received a dealing over the network, it should first be deserialized into an UnverifiedDealing, and then
// verified using vess.VerifyDealing(...). Only after a dealing has been successfully verified, it can be used for
// decryption of secret shares.
type UnverifiedDealing struct {
	c      PolynomialCommitment // len(c) == t (not using uppercase C here to avoid exporting the value)
	h      []byte               // len(h) == digestSize
	ρ_ωʺ   []Scalars            // only set for k ∈ S, len(ρ_wʺ) == M, len(ρ_wʺ[i]) == t
	ρ_E    []Ciphertext         // only set for k ∈ S, len(ρ_E) == M
	ρ_seed []ExpansionSeed      // only set for k ∉ S, len(ρ_seed) == N-M
}

// A verified dealing is a wrapper around an unverified dealing that has successfully passed the verification step.
// A locally generated dealing is always considered verified.
type VerifiedDealing struct {
	UnverifiedDealing
}

func (d *UnverifiedDealing) IsNil() bool {
	return d == nil
}

func (d *UnverifiedDealing) MarshalTo(target codec.Target) {
	if len(d.ρ_ωʺ) != len(d.ρ_E) {
		panic(fmt.Sprintf(
			"dealing.MarshalTo: inconsistent number of values in ρ_wʺ (%d) and ρ_E (%d)",
			len(d.ρ_ωʺ), len(d.ρ_E),
		))
	}

	C := d.c
	curve := C[0].Curve()

	t := len(d.c)
	N := len(d.ρ_ωʺ) + len(d.ρ_seed)
	M := len(d.ρ_ωʺ)

	curve.MarshalTo(target)
	target.WriteInt(t)
	target.WriteInt(N)
	target.WriteInt(M)

	for _, Cₖ := range C {
		Cₖ.MarshalTo(target)
	}

	target.WriteBytes(d.h)

	for i := range d.ρ_ωʺ {
		for _, w := range d.ρ_ωʺ[i] {
			w.MarshalTo(target)
		}
		target.WriteLengthPrefixedBytes(d.ρ_E[i])
	}

	for _, seedᵢ := range d.ρ_seed {
		target.WriteBytes(seedᵢ[:])
	}
}

func (d *UnverifiedDealing) UnmarshalFrom(source codec.Source) *UnverifiedDealing {
	curve := math.UnmarshalCurve(source)
	t := source.ReadInt()
	N := source.ReadInt()
	M := source.ReadInt()
	if t < 1 || N < 0 || M < 1 || N < M {
		panic(fmt.Sprintf("dealing.UnmarshalFrom: invalid parameters t=%d, N=%d, M=%d", t, N, M))
	}

	C := make(PolynomialCommitment, t)
	for k := range C {
		Cₖ := curve.Point()
		Cₖ.UnmarshalFrom(source)
		C[k] = Cₖ
	}
	d.c = C

	d.h = source.ReadBytes(xof.DigestLength)

	d.ρ_ωʺ = make([]math.Scalars, M)
	d.ρ_E = make([]Ciphertext, M)
	for i := range d.ρ_ωʺ {
		ρ_wʺ := make(math.Scalars, t)
		for j := range ρ_wʺ {
			ρ_wʺ[j] = curve.Scalar()
			ρ_wʺ[j].UnmarshalFrom(source)
		}
		d.ρ_ωʺ[i] = ρ_wʺ
		d.ρ_E[i] = source.ReadLengthPrefixedBytes()
	}

	d.ρ_seed = make([]ExpansionSeed, N-M)
	for i := range d.ρ_seed {
		var seedᵢ ExpansionSeed
		source.ReadBytesInto(seedᵢ[:])
		d.ρ_seed[i] = seedᵢ
	}

	return d
}

func (vd *VerifiedDealing) IsNil() bool {
	return vd == nil
}

func (vd *VerifiedDealing) MarshalTo(target codec.Target) {
	vd.UnverifiedDealing.MarshalTo(target)
}

func (vd *VerifiedDealing) UnmarshalFrom(source codec.Source) *VerifiedDealing {
	vd.UnverifiedDealing = *(&UnverifiedDealing{}).UnmarshalFrom(source)
	return vd
}

func (vd *VerifiedDealing) AsUnverifiedDealing() *UnverifiedDealing {
	return &vd.UnverifiedDealing
}

func (vd *VerifiedDealing) Commitment() PolynomialCommitment {
	return vd.c
}

// Returns the expected size of a serialized VESS dealing.
func dealingSize(curve math.Curve, n int, t int, N int, M int) int {
	// Recall the member fields of a dealing:
	//  - C      PolynomialCommitment // len(C) == t
	//  - h      []byte               // len(h) == digestSize
	//  - ρ_wʺ   [][]math.Scalar      // only set for k ∈ S, len(ρ_wʺ) == M, len(ρ_wʺ[i]) == t
	//  - ρ_E    []Ciphertext         // only set for k ∈ S, len(ρ_E) == M
	//  - ρ_seed []ExpansionSeed      // only set for k ∉ S, len(ρ_seed) == N-M
	//
	// Additionally the curve, t, N, M are serialized.

	// Compute the size of each VESS ciphertext ρ_E[i].
	totalPlaintextSize := 0
	totalPlaintextSize += n * curve.ScalarBytes()         // n scalar
	totalPlaintextSize += t * curve.ScalarBytes()         // 1 polynomial commitment (t coefficients)
	E_size := mre.CiphertextSize(n+1, totalPlaintextSize) // M ciphertexts, each encrypting n scalars + 1 polynomial commitment

	// Compute the size of each tuple (ρ_wʺ[i], ρ_E[i]).
	ρ_wʺ_E_size := 0
	ρ_wʺ_E_size += t * curve.ScalarBytes() // ρ_wʺ[i]
	ρ_wʺ_E_size += codec.IntSize           // length prefix for ρ_E[i]
	ρ_wʺ_E_size += E_size                  // ρ_E[i]

	// Now compute the total size of the dealing.
	size := 0
	size += 1                      // curve type
	size += codec.IntSize          // t
	size += codec.IntSize          // N
	size += codec.IntSize          // M
	size += t * curve.PointBytes() // C
	size += xof.DigestLength
	size += M * ρ_wʺ_E_size             // M tuples (ρ_wʺ[i], ρ_E[i])
	size += (N - M) * expansionSeedSize // N-M expansion seeds

	return size
}
