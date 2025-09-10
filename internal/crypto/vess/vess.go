package vess

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/crs"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/mre"
	"github.com/smartcontractkit/smdkg/internal/crypto/xof"
)

type (
	Scalar               = math.Scalar
	Scalars              = math.Scalars
	Point                = math.Point
	Polynomial           = math.Polynomial
	PolynomialCommitment = math.PolynomialCommitment
	Ciphertext           = []byte
)

const (
	expansionSeedSize                  = 16
	statisticalSecurityBits            = 64
	computeWeightForParameterSelection = 50 // trade-off factor for optimal parameter selection, in percent [0, 100]
)

type ExpansionSeed = [expansionSeedSize]byte

type VESS interface {
	internal() *vess

	// Deal generates a VESS dealing for the secret s, with the polynomial degree t - 1, for n recipients.
	// The set of recipients R (with their encryption keys) is set upon initialization of the VESS instance.
	// Additional associated data is provided in ad.
	// The function returns a VerifiedDealing containing:
	//  - the commitment vector C,
	//  - the hash h,
	//  - and the ρ vector (forming the ZKP).
	Deal(s Scalar, ad []byte, rand io.Reader) (*VerifiedDealing, error)

	// Verifies a given dealing against the VESS instance parameters.
	// Only after a successful verification the dealing instance may be used to decrypt a participant's share.
	VerifyDealing(D *UnverifiedDealing, ad []byte) (*VerifiedDealing, error)

	// Given the VESS dealing D, decrypt the secret share for recipient R using its keyring for operations against R's
	// secret key dk_R (abstracted in the provided dkgtypes.P256Keyring interface).
	Decrypt(R int, dk_R dkgtypes.P256Keyring, D *VerifiedDealing, ad []byte) (Scalar, error)

	// Verifies the validity of the share s_R for recipient R, given the dealing D.
	// Returns nil if the share s_R is valid, or an error if the share is invalid.
	VerifyShare(s_R Scalar, D *VerifiedDealing, R int) error

	// Returns the VESS instance parameters used, an (N, M) tuple.
	Params() VESSParams
}

type vess struct {
	curve      math.Curve               // elliptic curve used for the VESS protocol
	crs        dkgtypes.P256PublicKey   // common reference string, derived from the DKG's instance ID
	n          int                      // number of recipients
	t          int                      // secret sharing threshold
	recipients []dkgtypes.P256PublicKey // recipient public keys
	ek         []dkgtypes.P256PublicKey // recipient public keys || crs
	N          int                      // repetition parameter
	M          int                      // subset size parameter
}

type VESSParams struct {
	N int // repetition parameter
	M int // subset size parameter
}

// Initialize a new VESS instance for the given curve and DKG instance id.
// The DKG's InstanceID is used to derive the common reference string (CRS) for the VESS & MRE protocol.
// When initializing a VESS instance for decryption only, `nil` may be passed as value for the list of recipients.
func NewVESS(curve math.Curve, iid dkgtypes.InstanceID, tag string, n int, t int, recipients []dkgtypes.P256PublicKey) (VESS, error) {
	if t <= 0 || n <= 0 || n < t {
		return nil, fmt.Errorf("invalid parameters n (%d) and t (%d)", n, t)
	}

	crs, err := crs.NewP256CRS(iid, tag)
	if err != nil {
		return nil, err
	}

	CPs := candidateParameters(curve, n, t, statisticalSecurityBits)
	OP := selectOptimalParameters(CPs, computeWeightForParameterSelection)

	var ek []dkgtypes.P256PublicKey
	var R []dkgtypes.P256PublicKey

	if recipients != nil {
		if len(recipients) != n {
			return nil, fmt.Errorf("number of recipient public keys (%d) does not match n (%d)", len(recipients), n)
		}
		ek = make([]dkgtypes.P256PublicKey, n+1)
		copy(ek, recipients)
		ek[n] = crs
		R = ek[:n:n]
	}

	return &vess{curve, crs, n, t, R, ek, OP.N, OP.M}, nil
}

func (v *vess) internal() *vess {
	return v
}

// Generates a VESS dealing for the secret s, with random polynomial of degree t - 1.
func (v *vess) Deal(s Scalar, ad []byte, rand io.Reader) (*VerifiedDealing, error) {
	// Safeguard to ensure only VESS instances initialized with recipient public keys are used for dealing.
	if v.recipients == nil {
		return nil, fmt.Errorf("cannot create dealing without recipient public keys")
	}

	// Initialize the coefficients of a random polynomial ω(x) of degree t - 1, its 1st coefficient is set to s.
	ω, err := math.RandomPolynomial(s, v.t, rand)
	if err != nil {
		return nil, err
	}

	// Commit to that polynomial, i.e. compute [C] <- g^[ω]
	C := ω.Commitment(v.curve)

	seed := make([]ExpansionSeed, v.N)
	Cꞌ := make([][]Point, v.N)
	E := make([]Ciphertext, v.N)
	ωꞌ := make([]math.Polynomial, v.N)

	for k := 0; k < v.N; k++ {
		// Generate a random expansion seedₖ.
		if _, err := io.ReadFull(rand, seed[k][:]); err != nil {
			return nil, err
		}
		if ωꞌ[k], Cꞌ[k], E[k], err = v.zkpCommitRound(k, seed[k], ad); err != nil {
			return nil, err
		}
	}

	// Compute h <-- hComp(C'₁, E₁, ..., C'_N, E_N, ad).
	h := v.hComp(Cꞌ, E, ad)

	// Compute S <-- hCh(C, h, ad), where S represents a uniformly at random selected subset of size M of the set
	// {0, 1, 2, ..., N-1}.
	S, err := v.hCh(C, h, ad)
	if err != nil {
		return nil, err
	}

	// Response phase of the non-interactive zero-knowledge proof.
	ρ_ωʺ := make([]math.Scalars, 0, v.M)
	ρ_E := make([]Ciphertext, 0, v.M)
	ρ_seed := make([]ExpansionSeed, 0, v.N-v.M)
	ωʺ := make([]math.Polynomial, v.N)

	for k, kInS := range S {
		if kInS {
			// if k ∈ S, compute [ω"ₖ] <-- [ω] + [ω′ₖ] and set the response ρₖ <-- (ω"ₖ, Eₖ)
			ωʺ[k] = math.ScalarsAddElementWise(ω, ωꞌ[k])
			ρ_ωʺ = append(ρ_ωʺ, ωʺ[k])
			ρ_E = append(ρ_E, E[k])
		} else {
			// if k ∉ S, set the response ρₖ <-- seedₖ
			ρ_seed = append(ρ_seed, seed[k])
		}
	}

	return &VerifiedDealing{UnverifiedDealing{C, h, ρ_ωʺ, ρ_E, ρ_seed}}, nil
}

// Verifies a given dealing D against the VESS instance parameters and the associated data ad.
func (v *vess) VerifyDealing(D *UnverifiedDealing, ad []byte) (*VerifiedDealing, error) {
	// Safeguard to ensure only VESS instances initialized with recipient public keys are used for verification.
	if v.recipients == nil {
		return nil, fmt.Errorf("VESS instance not initialized with the recipients's public keys")
	}

	// Verify that the received data structure is well-formed.
	if err := v.validateDealing(D); err != nil {
		return nil, err
	}

	// Extract the components of the dealing for easier access.
	C, h, ρ_ωʺ, ρ_E, ρ_seed := D.c, D.h, D.ρ_ωʺ, D.ρ_E, D.ρ_seed

	// Recompute S <-- hCh([C], h, ad) for verification.
	S, err := v.hCh(C, h, ad)
	if err != nil {
		return nil, err
	}

	// Recompute (C'ₖ, Eₖ) for all k ∈ { 0, 1, ..., N-1 }.
	Cꞌ := make([][]Point, v.N)
	E := make([]Ciphertext, v.N)
	ωʺ := make([]Polynomial, v.N)

	i := 0 // index for ρ_ωʺ and ρ_E
	j := 0 // index for ρ_seed
	for k, kInS := range S {
		if kInS {
			// if k ∈ S, parse ρₖ = ([ω"ₖ], Eₖ) and compute [C′ₖ] <-- g^[ω"ₖ] / [C].
			ωʺₖ := ρ_ωʺ[i]
			Eₖ := ρ_E[i]
			i++

			ωʺ[k], E[k] = ωʺₖ, Eₖ
			Cꞌ[k] = ωʺₖ.Commitment(v.curve)
			for j, Cj := range C {
				Cꞌ[k][j].Subtract(Cꞌ[k][j], Cj)
			}
		} else {
			// if k ∉ S, parse ρₖ = seedₖ and recompute ([C'ₖ], Eₖ) using the round function.
			seedₖ := ρ_seed[j]
			j++

			if _, Cꞌ[k], E[k], err = v.zkpCommitRound(k, seedₖ, ad); err != nil {
				return nil, err
			}
		}
	}

	// Recompute h <-- hComp(C'₁, E₁, ..., C'_N, E_N, ad) and compare to the original h.
	hd := v.hComp(Cꞌ, E, ad)
	if subtle.ConstantTimeCompare(h, hd) != 1 {
		return nil, fmt.Errorf("invalid dealing (hash mismatch)")
	}

	return &VerifiedDealing{*D}, nil
}

// Uses recipient R's secret key dk_(R_i) to decrypt its secret shares included the dealing.
// Returns the secret share for recipient R, or an error if the decryption failed.
func (v *vess) Decrypt(R int, dkᵢ dkgtypes.P256Keyring, D *VerifiedDealing, ad []byte) (Scalar, error) {
	n := v.n
	C, h, ρ_ωʺ, ρ_E := D.c, D.h, D.ρ_ωʺ, D.ρ_E

	S, err := v.hCh(C, h, ad)
	if err != nil {
		return nil, err
	}

	// index for ρ_ωʺ and ρ_E
	i := 0
	for /* k */ _, kInS := range S {
		if !kInS {
			continue
		}

		ωʺₖ := ρ_ωʺ[i]
		Eₖ := ρ_E[i]
		i++

		sꞌ_R_bytes, err := mre.Decrypt(n+1, R, dkᵢ, Eₖ, ad)
		if err != nil {
			// For some iterations, the decryption may fail, this is okay and expected, we retry in another iteration.
			// This could in principle also happen despite of a successful prior call to VerifyDealing, which only
			// guarantees that some iteration will succeed.
			continue
		}
		sꞌ_R, err := v.curve.Scalar().SetBytes(sꞌ_R_bytes)
		if err != nil {
			// Also retry in another iteration here.
			continue
		}

		// Compute s_R <-- [ω"ₖ](R) - s'_R
		s_R := ωʺₖ.Eval(R).Subtract(sꞌ_R)

		// Check whether g^(s_R) == [C]^(R)
		if err = v.VerifyShare(s_R, D, R); err != nil {
			// Verification failed, continue to the next k.
			continue
		}

		// If we reach this point, the decryption was successful and the share is valid.
		return s_R, nil
	}

	// If we reach this point, no round passed the verification check.
	// This should not happen, as the probability for this is negligible for correct parameters N and M.
	return nil, fmt.Errorf("decryption failed (no round passed verification check)")
}

// Checks the validity of the share s_R for recipient R, given the dealing D.
func (v *vess) VerifyShare(s_R Scalar, D *VerifiedDealing, R int) error {
	if s_R == nil {
		return fmt.Errorf("invalid share (nil)")
	}
	if !s_R.Modulus().Equal(v.curve.GroupOrder()) {
		return fmt.Errorf("invalid share (scalar not of expected modulus)")
	}

	C := D.c
	gᶺs_R := v.curve.Point().ScalarBaseMult(s_R) // Compute g^(s_R)
	CᶺR := C.Eval(R)
	if !gᶺs_R.Equal(CᶺR) {
		return fmt.Errorf("share verification failed: g^(s_R) != [C]^(R)")
	}
	return nil
}

// Returns the VESS instance parameters used, an (N, M) tuple.
func (v *vess) Params() VESSParams {
	return VESSParams{v.N, v.M}
}

// Derives the polynomial ωꞌₖ of degree t-1, its commitment Cꞌₖ, and the zkpCommitRound k's MRE ciphertext Eₖ.
func (v *vess) zkpCommitRound(k int, seedₖ ExpansionSeed, ad []byte) (ωꞌₖ Polynomial, Cꞌₖ []Point, Eₖ Ciphertext, err error) {
	// Compute (rₖ, [ω'ₖ]) <-- H_exp^t(k, seedₖ, ad)
	var rₖ ExpansionSeed
	if rₖ, ωꞌₖ, err = v.hExp(k, seedₖ, ad); err != nil {
		return
	}

	// Compute [C'ₖ] <-- g^[ω'ₖ]
	Cꞌₖ = ωꞌₖ.Commitment(v.curve)

	// Compute [m] <-- [ω'ₖ]([R]) || ⟨ω'ₖ⟩
	m := make([][]byte, v.n+1)
	for i := 0; i < v.n; i++ {
		m[i] = ωꞌₖ.Eval(i).Bytes()
	}
	if m[v.n], err = codec.Marshal(ωꞌₖ); err != nil {
		return
	}

	// Compute [Eₖ] <-- MRE.Enc([ek_R], [ω'ₖ]([R]), ad, rₖ)
	Eₖ, err = mre.Encrypt(v.ek, m, ad, rₖ)
	return
}

// Helper function to check if a given unverified dealing is well-formed (in the context of this VESS instance).
// Cryptographic verification is performed in the VerifyDealing function.
func (v *vess) validateDealing(D *UnverifiedDealing) error {
	if D == nil {
		return fmt.Errorf("invalid dealing (nil)")
	}

	C, h, ρ_ωʺ, ρ_E, ρ_seed := D.c, D.h, D.ρ_ωʺ, D.ρ_E, D.ρ_seed

	if err := v.validateCommitment(C); err != nil {
		return err
	}
	if len(h) != xof.DigestLength {
		return fmt.Errorf("invalid dealing (expected hash length: %d, got %d)", xof.DigestLength, len(h))
	}
	if err := v.validateResponses(ρ_ωʺ, ρ_E, ρ_seed); err != nil {
		return err
	}

	return nil
}

// Helper for the well-formed check of a polynomial commitment (in the context of this VESS instance).
func (v *vess) validateCommitment(C PolynomialCommitment) error {
	if v.t != len(C) {
		return fmt.Errorf("invalid dealing (expected commitment length: %d, got %d", v.t, len(C))
	}
	for _, Cₖ := range C {
		if Cₖ == nil {
			return fmt.Errorf("invalid dealing (nil point in commitment)")
		}
		if Cₖ.Curve() != v.curve {
			return fmt.Errorf("invalid dealing (point in commitment not on expected curve")
		}
	}
	return nil
}

// Helper for the well-formed check of the responses (in the context of this VESS instance).
func (v *vess) validateResponses(ρ_ωʺ []Scalars, ρ_E []Ciphertext, ρ_seed []ExpansionSeed) error {
	t, N, M := v.t, v.N, v.M
	if len(ρ_ωʺ) != len(ρ_E) || len(ρ_ωʺ) != M {
		return fmt.Errorf(
			"invalid dealing (expected number of ([ωʺₖ], Eₖ) responses: (%d, %d), got (%d, %d))",
			M, M, len(ρ_ωʺ), len(ρ_E),
		)
	}

	for _, ρ_ωʺᵢ := range ρ_ωʺ {
		if len(ρ_ωʺᵢ) != t {
			return fmt.Errorf("invalid dealing (expected polynomial degree: %d, got %d)", t-1, len(ρ_ωʺᵢ)-1)
		}
		for _, s := range ρ_ωʺᵢ {
			if s == nil {
				return fmt.Errorf("invalid dealing (nil scalar in polynomial)")
			}
			if !s.Modulus().Equal(v.curve.GroupOrder()) {
				return fmt.Errorf("invalid dealing (scalar not of expected modulus)")
			}
		}
	}

	for _, ρ_Eᵢ := range ρ_E {
		if ρ_Eᵢ == nil {
			return fmt.Errorf("invalid dealing (nil ciphertext in ([ωʺₖ], Eₖ) response)")
		}
	}

	if len(ρ_seed) != N-M {
		return fmt.Errorf(
			"invalid dealing (expected number of seed responses: %d, got %d)",
			N-M, len(ρ_seed),
		)
	}
	return nil
}

// Computes the hash hExp(t, k, seedₖ, ad).
func (v *vess) hExp(k int, seedₖ ExpansionSeed, ad []byte) (ExpansionSeed, []Scalar, error) {
	h := xof.New("smartcontract.com/dkg/vess/hExp")
	h.WriteInt(v.t)
	h.WriteInt(k)
	h.WriteBytes(seedₖ[:])
	h.WriteBytes(ad)

	var rₖ ExpansionSeed
	if _, err := h.Read(rₖ[:]); err != nil {
		return rₖ, nil, err
	}

	ωꞌₖ := make([]Scalar, v.t)
	for i := 0; i < v.t; i++ {
		var err error
		ωꞌₖ[i], err = v.curve.Scalar().SetRandom(h)
		if err != nil {
			return rₖ, nil, err
		}
	}

	return rₖ, ωꞌₖ, nil
}

// Compute the hash hComp(C'₁, E₁, ..., C'_N, E_N, ad).
func (v *vess) hComp(Cꞌ [][]Point, E []Ciphertext, ad []byte) []byte {
	h := xof.New("smartcontract.com/dkg/vess/hComp")
	for i, Cꞌᵢ := range Cꞌ {
		for _, Cꞌᵢⱼ := range Cꞌᵢ {
			h.WriteBytes(Cꞌᵢⱼ.Bytes())
		}
		h.WriteBytes(E[i])
	}
	h.WriteBytes(ad)
	return h.Digest()
}

// Derive a uniformly random selected subset S of size M from the set { 0, 1, 2, ..., N-1 } via a hash function.
// The set S is represented as a boolean array S of size N, where S[k] == true if k ∈ S, and S[k] == false otherwise.
// The derivation is based on Fisher-Yates shuffle algorithm.
//
// N... repetition count
// M... size of the subset to be selected
func (v *vess) hCh(C []Point, h []byte, ad []byte) ([]bool, error) {
	hasher := xof.New("smartcontract.com/dkg/vess/hCh")
	hasher.WriteInt(v.N)
	hasher.WriteInt(v.M)
	for _, Cᵢ := range C {
		hasher.WriteBytes(Cᵢ.Bytes())
	}
	hasher.WriteBytes(h)
	hasher.WriteBytes(ad)

	// Helper function to read a (bias-free) random integer in the range {0, 1, ..., modulus-1} from the hasher's output
	// via rejection sampling.
	getNextUniformRandIntBelow := func(modulus int) int {
		var randBuffer [4]byte
		var mask uint32 = (1 << bits.Len32(uint32(modulus))) - 1
		for {
			// Read a uint32 from the hasher, for all our purposes this is sufficient to cover the range of modulus.
			_, _ = hasher.Read(randBuffer[:])
			r := binary.BigEndian.Uint32(randBuffer[:])

			// Use rejection sampling to avoid modulo bias.
			rMasked := int(r & mask)
			if rMasked < modulus {
				return rMasked
			}
		}
	}

	// Initialize the permutation with the first N integers.
	permutation := make([]int, v.N)
	for i := 0; i < v.N; i++ {
		permutation[i] = i
	}

	// Perform a (deterministic) Fisher-Yates shuffle to randomly permute the subset.
	for i := v.N - 1; i >= 1; i-- {
		j := getNextUniformRandIntBelow(i + 1) // j := random integer sampled from {0, 1, ..., i}

		// Swap the elements at indices i and j.
		t := permutation[i]
		permutation[i] = permutation[j]
		permutation[j] = t
	}

	// Convert the permutation into a boolean array of size N, where the first M elements are true.
	S := make([]bool, v.N)
	for i := 0; i < v.N; i++ {
		S[i] = permutation[i] < v.M
	}
	return S, nil
}

// Returns the expected size of a serialized VESS dealing, given the curve used, the number of recipients n and
// threshold t. The given estimate is an upper bound and typically (=when all MRE encryptions succeed) tight.
func EstimateDealingSize(curve math.Curve, n int, t int) int {
	// Compute optimal parameters N and M for the given n and t.
	CPs := candidateParameters(curve, n, t, statisticalSecurityBits)
	OP := selectOptimalParameters(CPs, computeWeightForParameterSelection)

	// Return the expected size of a serialized VESS dealing for the given parameters.
	return dealingSize(curve, n, t, OP.N, OP.M)
}
