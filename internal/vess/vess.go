package vess

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	stdmath "math"
	"math/big"

	"github.com/smartcontractkit/smdkg/internal/crs"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/hash"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/smdkg/internal/mre"
	"github.com/smartcontractkit/smdkg/internal/serialization"
)

type Scalar = math.Scalar
type Point = math.Point
type Polynomial = math.Polynomial
type PolynomialCommitment = math.PolynomialCommitment

type PrivateIdentity = dkgtypes.PrivateIdentity
type PublicIdentity = dkgtypes.PublicIdentity
type P256PublicKey = dkgtypes.P256PublicKey

type Ciphertext = []byte

const (
	digestSize                         = 32
	expansionSeedSize                  = 16
	statisticalSecurityBits            = 64
	computeWeightForParameterSelection = 0.5
)

type ExpansionSeed = [expansionSeedSize]byte

type VESS interface {
	// Deal generates a VESS dealing for the secret s, with the polynomial degree t - 1, for N recipients with
	// identities R. `nil` may be passed as value for R, in which case the default identities {1, 2, ..., N} are used.
	// The encryption keys for the recipients are provided in ekR, and additional authenticated data is provided in ad.
	// The function returns the a serialized dealing containing:
	//  - the commitment vector C,
	//  - the hash h,
	//  - and the ρ vector (forming the ZKP).
	Deal(s Scalar, to []PublicIdentity, ad []byte, rand io.Reader) (Dealing, error)

	// Parses a serialized VESS dealing D and verifies it.
	// After a successful verification the returned dealing instance can be used to decrypt a participant's share.
	VerifyDealing(D []byte, to []PublicIdentity, ad []byte) (Dealing, error)

	// Given the VESS dealing D, decrypt the secret share for recipient R using its secret key.
	Decrypt(R PrivateIdentity, D Dealing) (Scalar, error)

	// Verifies the validity of the share s_R for recipient R, given the dealing D.
	// Returns nil if the share is valid, or an error if the share is invalid.
	VerifyShare(s_R Scalar, D Dealing, R PublicIdentity) error
}

// Dealing interface to hide the implementation details.
// There is (and must be) only one implementation of this interface, which is the `dealing` struct.
type Dealing interface {
	internal() *dealing               // Prevent external code from implementing this interface.
	Bytes() ([]byte, error)           // Serializes the dealing into a byte slice.
	Commitment() PolynomialCommitment // Returns the commitment vector C of the dealing.
}

// The only implementation of the Dealing interface.
type dealing struct {
	// members for serialization
	C PolynomialCommitment
	h []byte
	ρ [][]byte

	// non-serialized members
	n  int
	ad []byte
	S  []bool
	wʺ []math.Polynomial
	E  []Ciphertext
}

func (d *dealing) internal() *dealing {
	return d
}

func (d *dealing) Commitment() PolynomialCommitment {
	return d.C
}

type vess struct {
	curve math.Curve             // elliptic curve used for the VESS protocol
	crs   dkgtypes.P256PublicKey // common reference string, derived from the DKG's instance ID
	n     int                    // number of recipients
	t     int                    // secret sharing threshold
	N     int                    // repetition parameter
	M     int                    // subset size parameter
}

// Initialize a new VESS instance for the given curve and DKG instance id.
// The DKG instance id is used to derive the common reference string (CRS) for the VESS & MRE protocol.
func NewVESS(curve math.Curve, iid dkgtypes.InstanceID, tag string, n int, t int) (VESS, error) {
	crs, err := crs.NewP256CRS(iid, tag)
	if err != nil {
		return nil, err
	}

	CPs := candidateParameters(curve, n, t, statisticalSecurityBits)
	OP := selectOptimalParameters(CPs, computeWeightForParameterSelection)

	return &vess{curve, crs, n, t, OP.N, OP.M}, nil
}

// Generates a VESS dealing for the secret s, with random polynomial of degree t - 1.
func (v *vess) Deal(s Scalar, to []PublicIdentity, ad []byte, rand io.Reader) (Dealing, error) {
	if len(to) != v.n {
		return nil, fmt.Errorf("expected %d recipients, got %d", v.n, len(to))
	}
	ek := v.prepareEncryptionKeys(to) // Set ek <-- ek_R || crs = [to[0].PublicKey, ..., to[n-1].PublicKey, v.crs]

	// Initialize the coefficients of a random polynomial ω(x) of degree t - 1, its 1st coefficient is set to s.
	w, err := math.RandomPolynomial(s, v.t, rand)
	if err != nil {
		return nil, err
	}

	// Commit to that polynomial, i.e. compute [C] <- g^[w]
	C := w.Commitment(v.curve)

	seed := make([]ExpansionSeed, v.N)
	Cd := make([][]Point, v.N)
	E := make([]Ciphertext, v.N)
	wꞌ := make([][]Scalar, v.N)
	wʺ := make([]math.Polynomial, v.N)
	ρ := make([][]byte, v.N)

	for k := 0; k < v.N; k++ {
		// Generate a random expansion seedₖ.
		if _, err := io.ReadFull(rand, seed[k][:]); err != nil {
			return nil, err
		}
		if wꞌ[k], Cd[k], E[k], err = v.round(to, ek, k, seed[k], ad); err != nil {
			return nil, err
		}
	}

	// Compute h <-- hComp(C'₁, E₁, ..., C'_N, E_N, ad).
	h, err := v.hComp(Cd, E, ad)
	if err != nil {
		return nil, err
	}

	// Compute S <-- hCh(C, h, ad), where S represents a uniformly at random selected subset of size M of the set
	// {0, 1, 2, ..., N-1}.

	S, err := v.hCh(C, h, ad)
	if err != nil {
		return nil, err
	}

	for k, kInS := range S {
		if kInS {
			// if k ∈ S, compute [ω"ₖ] <-- [ω] + [ω′ₖ] and set the response ρₖ <-- (ω"ₖ, Eₖ).
			wʺ[k] = make([]Scalar, v.t)
			for j := 0; j < v.t; j++ {
				wʺ[k][j] = w[j].Clone().Add(wꞌ[k][j])
			}
			if ρ[k], err = v.packRho(wʺ[k], E[k]); err != nil {
				return nil, err
			}
		} else {
			// if k ∉ S, sets the response ρₖ <-- seedₖ ,
			ρ[k] = seed[k][:]
		}
	}

	return &dealing{C, h, ρ, v.n, ad, S, wʺ, E}, nil
}

// Verify parses the serialized dealing D, verifies it, and returns a Dealing instance if the verification is
// successful. The returned Dealing instance can then be used to decrypt the ciphertext for particular recipient.
func (v *vess) VerifyDealing(D []byte, to []PublicIdentity, ad []byte) (Dealing, error) {
	if len(to) != v.n {
		return nil, fmt.Errorf("expected %d recipients, got %d", v.n, len(to))
	}
	ek := v.prepareEncryptionKeys(to) // Set [ek] <-- [ek_R] || crs

	d, err := v.loadDealing(D)
	if err != nil {
		return nil, fmt.Errorf("invalid dealing (parsing failed): %w", err)
	}

	C, h, ρ := d.C, d.h, d.ρ

	// Recompute S <-- hCh([C], h, ad) for verification.
	S, err := v.hCh(C, h, ad)
	if err != nil {
		return nil, err
	}

	// Recompute (C'ₖ, Eₖ) for all k.
	Cꞌ := make([][]Point, v.N)
	E := make([]Ciphertext, v.N)
	wʺ := make([]Polynomial, v.N)
	for k, kInS := range S {
		if kInS {
			// if k ∈ S, parse ρₖ = ([ω"ₖ], Eₖ) and compute [C′ₖ] <-- g^[ω"ₖ] / [C].
			if wʺ[k], E[k], err = v.unpackRho(ρ[k]); err != nil {
				return nil, fmt.Errorf("invalid dealing (unpacking ρₖ failed): %w", err)
			}
			Cꞌ[k] = wʺ[k].Commitment(v.curve)
			for j, Cj := range C {
				Cꞌ[k][j].Subtract(Cꞌ[k][j], Cj)
			}
		} else {
			// if k ∉ S, parse ρₖ = seedₖ and recompute ([C'ₖ], Eₖ) using the round function.
			var seed [16]byte
			if len(ρ[k]) != 16 {
				return nil, fmt.Errorf("invalid dealing (ρₖ is not a valid seed)")
			}
			copy(seed[:], ρ[k])
			if _, Cꞌ[k], E[k], err = v.round(to, ek, k, seed, ad); err != nil {
				return nil, err
			}
		}
	}

	// Recompute h <-- hComp(C'₁, E₁, ..., C'_N, E_N, ad) and compare to the original h.
	hd, err := v.hComp(Cꞌ, E, ad)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(h, hd) != 1 {
		return nil, fmt.Errorf("invalid dealing (hash mismatch)")
	}

	return &dealing{C, h, ρ, v.n, ad, S, wʺ, E}, nil
}

// Uses recipient R's secret key dk_(R_i) to decrypt its secret shares included the dealing.
// Returns the secret share for recipient R, or an error if the decryption failed.
func (v *vess) Decrypt(R PrivateIdentity, D Dealing) (Scalar, error) {
	d := D.internal()
	n, ad, wʺ, E := d.n, d.ad, d.wʺ, d.E

	for k, kInS := range d.S {
		if !kInS {
			continue
		}

		sꞌ_R_bytes, err := mre.Decrypt(n+1, R, E[k], ad)
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

		// Compute s_R <-- [w"ₖ](R) - s'_R
		s_R := wʺ[k].Eval(R.XCoord()).Subtract(sꞌ_R)

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

func (v *vess) VerifyShare(s_R Scalar, D Dealing, R PublicIdentity) error {
	d := D.internal()
	C := d.C

	gᶺs_R := v.curve.Point().ScalarBaseMult(s_R) // Compute g^(s_R)
	CᶺR := C.Eval(R.XCoord())                    // Compute [C]^(R)
	if !gᶺs_R.Equal(CᶺR) {
		return fmt.Errorf("share verification failed: g^(s_R) != [C]^(R)")
	}
	return nil
}

func (v *vess) prepareEncryptionKeys(to []PublicIdentity) []P256PublicKey {
	ek := make([]P256PublicKey, len(to)+1)
	for j, identity := range to {
		ek[j] = identity.PublicKey()
	}
	ek[len(to)] = v.crs
	return ek
}

func (v *vess) round(to []PublicIdentity, ek []P256PublicKey, k int, seedₖ ExpansionSeed, ad []byte) (wꞌₖ Polynomial, Cdk []Point, Ek Ciphertext, err error) {
	// Compute (rₖ, [w'ₖ]) <-- H_exp^t(k, seedₖ, ad)
	var rₖ [16]byte
	if rₖ, wꞌₖ, err = v.hExp(k, seedₖ, ad); err != nil {
		return
	}

	// Compute [C'ₖ] <-- g^[w'ₖ]
	Cdk = wꞌₖ.Commitment(v.curve)

	// Compute [m] <-- [w'ₖ]([R]) || ⟨w'ₖ⟩
	m := make([][]byte, v.n+1)
	for i, recipient := range to {
		m[i] = wꞌₖ.Eval(recipient.XCoord()).Bytes()
	}
	if m[v.n], err = wꞌₖ.Bytes(); err != nil {
		return
	}

	// Compute [Eₖ] <-- MRE.Enc([ek_R], [ω'ₖ]([R]), ad, rₖ)
	Ek, err = mre.Encrypt(ek, m, ad, rₖ)
	return
}

// Return the serialized response ρₖ <-- ([ω"ₖ], Eₖ).
func (v *vess) packRho(wʺₖ []Scalar, Eₖ Ciphertext) ([]byte, error) {
	encoder := serialization.NewEncoder()
	for _, w := range wʺₖ {
		encoder.WriteBytes(w.Bytes())
	}
	encoder.WriteBytes(Eₖ)
	return encoder.Bytes()
}

// Unpack ρₖ into the coefficients [w”ₖ] and the ciphertext Eₖ.
func (v *vess) unpackRho(ρₖ []byte) ([]Scalar, Ciphertext, error) {
	decoder := serialization.NewDecoder(ρₖ)

	wʺₖ := make([]Scalar, v.t)
	for i := 0; i < v.t; i++ {
		var err error
		if wʺₖ[i], err = v.curve.Scalar().SetBytes(decoder.ReadBytes()); err != nil {
			return nil, nil, err
		}
	}

	Eₖ := decoder.ReadBytes()

	if err := decoder.Finish(); err != nil {
		return nil, nil, err
	}
	return wʺₖ, Eₖ, nil
}

// Computes the hash hExp(t, k, seedₖ, ad).
func (v *vess) hExp(k int, seedₖ ExpansionSeed, ad []byte) (ExpansionSeed, []Scalar, error) {
	h := hash.NewHash("smartcontract.com/dkg/vess/hExp")
	// TODO:
	// 	 - h.WriteString(curve.Name())?
	h.WriteInt(v.t)
	h.WriteInt(k)
	h.WriteBytes(seedₖ[:])
	h.WriteBytes(ad)

	var rₖ ExpansionSeed
	if _, err := h.Read(rₖ[:]); err != nil {
		return rₖ, nil, err
	}

	wꞌₖ := make([]Scalar, v.t)
	for i := 0; i < v.t; i++ {
		var err error
		wꞌₖ[i], err = v.curve.Scalar().SetRandom(h)
		if err != nil {
			return rₖ, nil, err
		}
	}

	return rₖ, wꞌₖ, nil
}

// Computes the hash hComp(Cd_1, E_1, , ..., Cd_N, E_N, ad).
func (v *vess) hComp(Cd [][]Point, E []Ciphertext, ad []byte) ([]byte, error) {
	h := hash.NewHash("smartcontract.com/dkg/vess/hComp")
	for i, Ci := range Cd {
		for _, Cij := range Ci {
			h.WriteBytes(Cij.Bytes())
		}
		h.WriteBytes(E[i])
	}
	h.WriteBytes(ad)
	return h.Digest(digestSize)
}

// Derive a uniformly random selected subset S of size M from the set {0, 1, 2, ..., N-1} via a hash function.
// The set S is represented as a boolean array S of size N, where S[k] == true if k ∈ S, and S[k] == false otherwise.
// The derivation is based on Fisher-Yates shuffle algorithm.
//
// N... repetition count
// M... size of the subset to be selected
func (v *vess) hCh(C []Point, h []byte, ad []byte) ([]bool, error) {
	hasher := hash.NewHash("smartcontract.com/dkg/vess/hCh")
	hasher.WriteInt(v.N)
	hasher.WriteInt(v.M)
	for _, Ci := range C {
		hasher.WriteBytes(Ci.Bytes())
	}
	hasher.WriteBytes(h)
	hasher.WriteBytes(ad)

	// Initialize the permutation with the first N integers.
	permutation := make([]int, v.N)
	for i := 0; i < v.N; i++ {
		permutation[i] = i
	}

	// Perform a Fisher-Yates shuffle to randomly permute the subset.
	rBuf := make([]byte, 8)
	for i := v.N - 1; i >= 1; i-- {
		// Give a (very close to uniform) random index in the range {0, 1, ..., i}.
		_, err := hasher.Read(rBuf)
		if err != nil {
			return nil, err
		}
		r := binary.LittleEndian.Uint64(rBuf)
		j := int(r % uint64(i+1))

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

// Serializes this dealing into a byte slice for transmission over the network.
func (d *dealing) Bytes() ([]byte, error) {
	encoder := serialization.NewEncoder()
	for _, Ci := range d.C {
		encoder.WriteBytes(Ci.Bytes())
	}
	encoder.WriteBytes(d.h)
	for _, r := range d.ρ {
		encoder.WriteBytes(r)
	}
	return encoder.Bytes()
}

func (v *vess) loadDealing(D []byte) (*dealing, error) {
	decoder := serialization.NewDecoder(D)

	C := make([]Point, v.t)
	for i := range C {
		var err error
		C[i], err = v.curve.Point().SetBytes(decoder.ReadBytes())
		if err != nil {
			return nil, fmt.Errorf("failed to decode point C[%d]: %w", i, err)
		}
	}

	h := decoder.ReadBytes()

	ρ := make([][]byte, v.N)
	for i := range ρ {
		ρ[i] = decoder.ReadBytes()
	}

	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	return &dealing{C, h, ρ, 0, nil, nil, nil, nil}, nil
}

type candidateParams struct {
	N           int
	M           int
	DealingSize int
}

// Computes a set of suitable parameters for the VESS protocol based on the given security level with different
// trade-offs between compute cost and size of the dealing. The returned parameters are sorted by increasing compute
// cost (N) and decreasing dealing size.
func candidateParameters(curve math.Curve, n int, t int, statisticalSecurityBits int) []candidateParams {
	// Checks if the parameter choices N and M are sufficient for the given security level.
	achievesSecurityLevel := func(N, M int) bool {
		choices := new(big.Int).Binomial(int64(N), int64(M))
		return choices.BitLen() > statisticalSecurityBits
	}

	// Determine the initial parameters N and M that are sufficient for the security level.
	N, M := 2, 1
	for !achievesSecurityLevel(N, M) {
		N += 2
		M += 1
	}
	for achievesSecurityLevel(N, M-1) {
		M--
	}

	minDealingSize := dealingSize(curve, n, t, N, M)

	params := make([]candidateParams, 0)
	params = append(params, candidateParams{N, M, minDealingSize})

	for {
		N++
		if !achievesSecurityLevel(N, M-1) {
			continue
		}
		M--
		for achievesSecurityLevel(N, M-1) {
			M--
		}

		currentDealingSize := dealingSize(curve, n, t, N, M)
		if currentDealingSize > minDealingSize {
			break
		}

		minDealingSize = currentDealingSize
		params = append(params, candidateParams{N, M, currentDealingSize})
	}

	return params
}

// Selects the optimal parameters from the given candidates based on the computeWeight.
// The computeWeight is a value in the range [0.0, 1.0] that determines the weight of the compute cost relative to the
// size of the dealing. A value of 0.0 means that the size is the only factor, while a value of 1.0 means that the
// compute cost is the only factor. Only pass results from candidateParameters() to this function, the function assumes
// that the candidates are sorted by increasing N / decreasing dealing size.
func selectOptimalParameters(params []candidateParams, computeWeight float64) candidateParams {
	if computeWeight < 0.0 || computeWeight > 1.0 {
		panic("computeWeight must be in the range [0.0, 1.0], got: " + fmt.Sprint(computeWeight))
	}

	minN := params[0].N
	minDealingSize := params[0].DealingSize

	minWeight := stdmath.MaxFloat64
	bestParams := candidateParams{}

	for _, p := range params {
		computeMultiplier := float64(p.N) / float64(minN)
		sizeMultiplier := float64(p.DealingSize) / float64(minDealingSize)
		weight := (computeMultiplier * computeWeight) + (sizeMultiplier * (1 - computeWeight))

		if weight < minWeight {
			minWeight = weight
			bestParams = p
		}
	}
	return bestParams
}

// Returns the size of a serialized dealing.
func dealingSize(curve math.Curve, n int, t int, N int, M int) int {
	encodedSizeOf := serialization.SizeOfEncodedBytesByLength

	// Commitment vector C, containing t points
	size := encodedSizeOf(curve.PointBytes()) * t

	// Size of the hash h
	size += encodedSizeOf(digestSize)

	// Size of ρₖ:
	// a) if k ∈ S, ρₖ = ([ω"ₖ], Eₖ) where [ω"ₖ] is a polynomial of degree t-1, and Eₖ is a ciphertext
	// b) if k ∉ S, ρₖ = seedₖ

	plaintextSizes := make([]int, n+1)
	for i := 0; i < n; i++ {
		plaintextSizes[i] = curve.ScalarBytes()
	}
	polySize := encodedSizeOf(curve.ScalarBytes()) * t
	plaintextSizes[n] = polySize

	ciphertextSize := encodedSizeOf(mre.CiphertextSize(plaintextSizes))

	ρA := encodedSizeOf(polySize + ciphertextSize)
	ρB := serialization.SizeOfEncodedBytesByLength(expansionSeedSize)

	size += M * ρA
	size += (N - M) * ρB

	return size
}
