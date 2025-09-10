package dkg

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/vess"
	"github.com/smartcontractkit/smdkg/internal/crypto/xof"
)

// Stateless DKG instance to be used with the DKG plugin. Abstracts all cryptographic operations required for the DKG
// protocol. Use NewInitialDKG(...) or NewResharingDKG(...) to create a new instance for a fresh or re-sharing DKG.
// All state transitions are handled by the DKG plugin, i.e., after initialization the DKG instance's variables are
// not modified anymore.

type DKG interface {
	internal() *dkg

	// Returns the elliptic curve used by this DKG instance. This curve is used for the secret sharing, is not
	// necessarily the same curve as used by the dealers' and recipients' public keys (as those are used for VESS/MRE).
	Curve() math.Curve

	// Returns the list of dealers' public identities (wrapping their public keys, indexes and x-coordinates).
	Dealers() []dkgtypes.P256PublicKey

	// Returns the list of recipients' public identities (wrapping their public keys, indexes and x-coordinates).
	Recipients() []dkgtypes.P256PublicKey

	// Indicates how many initial dealings must be collected and validated successfully by the plugin before nodes can
	// start to decrypt their decryption shares, corresponds to |L|. This parameter depends on whether this DKG is
	// configured for fresh sharing or re-sharing:
	//   - fresh sharing: |L| = f_D + 1, i.e., at least f_D + 1 valid initial dealings must be collected
	//   - re-sharing:    |L| = priorResult.t_R, i.e., at least priorResult.t_R valid initial dealings must be collected
	DealingsThreshold() int

	// Indicates how many decryption shares must be collected by the plugin before the inner dealings case be recovered.
	DecryptionThreshold() int

	// Executed by dealer D to (re-)share a secret s_D with the recipients of the DKG. If this DKG instance is
	// configured for re-sharing, s_D from the prior DKG's result is used. Otherwise s_D is initialized as a fresh
	// random secret. The result is composed of two parts:
	//   - the outer dealing OD_D, sharing a random secret z_D (used as encryption key) with the dealers D,
	//   - the encrypted inner dealing EID_D, i.e., ID_D ((re-)sharing s_D with the recipients R), encrypted with z_D.
	Deal(rand io.Reader) (VerifiedInitialDealing, error)

	// After the initial step of creating and broadcasting all initial dealings, each dealer D must verify the initial
	// dealing created by and received from each other dealer D'. This function implements the first verification step,
	// checking the outer dealing (received as part of the initial dealing from D').
	VerifyInitialDealing(initialDealing UnverifiedInitialDealing, Dꞌ int) (VerifiedInitialDealing, error)

	// Decrypts all outer dealings OD_Dꞌ the dealer D' (issuer) ∈ L created and broadcasted for dealer D (recipient).
	// For decryption, the stored reference to the keyring of dealer D is used. Returns the list of decryption key
	// shares z_{D', D} for all D' ∈ L. The result z_{D', D} is given as list of length n_D, with nil values for all
	// D' ∉ L.
	//
	// Executed when the dealer D successfully collected a list L of
	//   - f_D + 1 valid initial dealings (for a fresh DKG run) or
	//   - t_D     valid initial dealings (for a re-sharing DKG run).
	//
	// The initial dealings in L must be from different dealers Dꞌ, and must have been verified successfully. This list
	// of initial dealings L must be given as a list of length n_D, containing exactly f_D+1 / t_D non-nil values.
	DecryptDecryptionKeyShares(L []VerifiedInitialDealing) (VerifiedDecryptionKeySharesForInnerDealings, error)

	// Executed when some dealer D wants to verify the decryption key shares (z_{D', D*}) the dealer D* (=Dˣ below)
	// broadcasted. The dealers D' ∈ L are the original issuers of the shares for which D* provided decryption key
	// shares.
	VerifyDecryptionKeyShares(
		L []VerifiedInitialDealing, Z_Dˣ UnverifiedDecryptionKeySharesForInnerDealings, Dˣ int,
	) (VerifiedDecryptionKeySharesForInnerDealings, error)

	// Recover the inner dealings ID_Dꞌ for all Dꞌ ∈ Lꞌ from the given list of verified initial dealings L and the
	// decryption key shares z_{Dꞌ, Dˣ} for all Dˣ ∈ Lˣ (the dealers that provided decryption key shares).
	// Both L and z are given as lists, with nil values for missing entries (i.e., dealings not in L, or decryption key
	// shares not available).
	RecoverInnerDealings(
		L []VerifiedInitialDealing, z []VerifiedDecryptionKeySharesForInnerDealings,
	) (Lꞌ []VerifiedInnerDealing, B IndicesOfBadDealers, restartRequired bool, err error)

	// Derive the DKG's results from the given list of verified inner dealings (i.e., for all D ∈ L').
	NewResult(Lꞌ []VerifiedInnerDealing) (Result, error)
}

// Initial structure of a DKG instance, all fields are kept constant after initialization.
type dkg struct {
	iid           dkgtypes.InstanceID      // unique instance ID of this DKG instance, must commit to all parameters
	curve         math.Curve               // elliptic curve used for secret sharing
	vessInner     vess.VESS                // VESS instance for the inner dealings (shared among recipients)
	vessOuter     vess.VESS                // VESS instance for the outer dealings (shared among dealers)
	f_D           int                      // number of shares required to decrypt the inner dealings
	t_R           int                      // number of shares required to reconstruct the master secret
	dealers       []dkgtypes.P256PublicKey // public keys of the dealers
	recipients    []dkgtypes.P256PublicKey // public keys of the recipients
	dealerIndex   int                      // index of the local node within the list of dealers
	dealerKeyring dkgtypes.P256Keyring     // keyring of the local node, used for decrypting shares
	priorResult   *result                  // prior result, if this is a re-sharing DKG instance
}

// Initializes a new (stateless) DKG instance for the given instance ID, to share a new (randomly generated) master
// secret key. To re-share an existing master secret key, use NewResharingDKG(...) instead.
//
// Parameters:
//   - iid: the instance ID of the new DKG instance
//   - curve: the elliptic curve to use for the DKG protocol
//   - dealers: the public keys of the dealers (the nodes running the DKG protocol)
//   - recipients: the public keys of the recipients (the nodes receiving the shares of master secret key)
//   - f_D: the maximum number of faulty dealers to be tolerated while executing the DKG protocol
//   - t_R: the reconstruction threshold, i.e., the minimum number of new recipients' shares needed for deriving the
//     master secret
//
// Returns a new DKG instance for use with the DKG plugin.
// Initialization may fail, e.g., if a given public key cannot be unmarshaled correctly.
func NewInitialDKG(
	iid dkgtypes.InstanceID,
	curve math.Curve,
	dealers []dkgtypes.P256PublicKey,
	recipients []dkgtypes.P256PublicKey,
	f_D int,
	t_R int,
	keyring dkgtypes.P256Keyring,
) (DKG, error) {
	return newDKG(iid, curve, dealers, recipients, f_D, t_R, keyring, nil)
}

// Initializes a new (stateless) DKG instance for the given instance ID, to re-share the master secret key, previously
// set up via a (fresh or re-shared) DKG instance to a (potentially) different list of recipients.
//
// Parameters:
//   - iid: the instance ID of the new DKG instance
//   - dealers: the public keys of the dealers (the nodes running the DKG protocol, must match the prior result's recipients)
//   - recipients: the public keys of the new recipients
//   - f_D: the maximum number of faulty dealers to be tolerated while executing the DKG protocol
//   - t_R: the reconstruction threshold, i.e., the minimum number of new recipients' shares needed for deriving the
//     master secret
//   - keyring: the keyring is required to load a private key share of the master secret key for re-sharing
//   - priorResult: the result of the prior DKG instance, determines the underlying secrets to be re-shared
//
// Returns a new DKG instance for the use with the DKG plugin.
// Initialization may fail, e.g., if a given public key cannot be unmarshaled correctly.
func NewResharingDKG(
	iid dkgtypes.InstanceID,
	dealers []dkgtypes.P256PublicKey, // must match the prior result's recipients
	recipients []dkgtypes.P256PublicKey,
	f_D int,
	t_R int,
	keyring dkgtypes.P256Keyring,
	priorResult Result,
) (DKG, error) {
	return newDKG(iid, priorResult.Curve(), dealers, recipients, f_D, t_R, keyring, priorResult)
}

func newDKG(
	iid dkgtypes.InstanceID,
	curve math.Curve,
	dealers []dkgtypes.P256PublicKey,
	recipients []dkgtypes.P256PublicKey,
	f_D int,
	t_R int,
	keyring dkgtypes.P256Keyring,
	priorResult Result,
) (DKG, error) {
	vessInner, err1 := vess.NewVESS(curve, iid, "inner", len(recipients), t_R, recipients)
	vessOuter, err2 := vess.NewVESS(curve, iid, "outer", len(dealers), f_D+1, dealers)
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	dealerIndex := -1
	for i, pk := range dealers {
		if pk.Equal(keyring.PublicKey()) {
			dealerIndex = i
			break
		}
	}
	if dealerIndex == -1 {
		return nil, fmt.Errorf("dealer's public key (from keyring) not found in list of dealers")
	}

	var prior *result
	if priorResult != nil {
		prior = priorResult.internal()
	}

	return &dkg{iid, curve, vessInner, vessOuter, f_D, t_R, dealers, recipients, dealerIndex, keyring, prior}, nil
}

func (dkg *dkg) internal() *dkg {
	return dkg
}

func (dkg *dkg) Curve() math.Curve {
	return dkg.curve
}

func (dkg *dkg) Dealers() []dkgtypes.P256PublicKey {
	dealers := make([]dkgtypes.P256PublicKey, len(dkg.dealers))
	copy(dealers, dkg.dealers)
	return dealers
}

func (dkg *dkg) Recipients() []dkgtypes.P256PublicKey {
	recipients := make([]dkgtypes.P256PublicKey, len(dkg.recipients))
	copy(recipients, dkg.recipients)
	return recipients
}

func (dkg *dkg) DealingsThreshold() int {
	if dkg.priorResult == nil {
		return dkg.f_D + 1
	} else {
		return dkg.priorResult.t_R
	}
}

func (dkg *dkg) DecryptionThreshold() int {
	return dkg.f_D + 1
}

func (dkg *dkg) Deal(rand io.Reader) (VerifiedInitialDealing, error) {
	var s_D math.Scalar
	if dkg.priorResult == nil {
		// If no prior result is available, we generate a new random secret.
		var err error
		if s_D, err = dkg.curve.Scalar().SetRandom(rand); err != nil {
			return nil, fmt.Errorf("failed to generate random secret: %w", err)
		}
	} else {
		// Re-sharing an existing secret, we need to load the secret share by decrypting is from the prior result.
		var err error
		if s_D, err = dkg.priorResult.MasterSecretKeyShare(dkg.dealerIndex, dkg.dealerKeyring); err != nil {
			return nil, fmt.Errorf("failed to receive secret share: %w", err)
		}
	}

	// Create the inner dealing ID_D that t_R out of n_R secret-shares s_D to the recipients R.
	// ID_D <-- VESS.Deal(s_D, R, t_R, ek_R ad), where ad := H_ad(iid, "inner", D).
	ad := hAd(dkg.iid, "inner", dkg.dealerIndex)
	ID_D, err := dkg.vessInner.Deal(s_D, ad, rand)
	if err != nil {
		return nil, err
	}

	// Choose a second random secret z_D and create the outer dealing OD_D that (f_D + 1) out of n_D secret-shares
	// z_D to the dealers D. OD_D <-- VESS.Deal(z_D, D, f_D + 1, ek_D, ad), where ad := (iid, "outer", D).
	z_D, err := dkg.curve.Scalar().SetRandom(rand)
	if err != nil {
		return nil, err
	}
	ad = hAd(dkg.iid, "outer", dkg.dealerIndex)
	OD_D, err := dkg.vessOuter.Deal(z_D, ad, rand)
	if err != nil {
		return nil, err
	}

	// Encrypt the inner ID_D using the secret shared with the second dealing.
	// I.e., compute EID_D <-- H^l_deal(iid, D, z_D) ⊕ ID_D.
	EID_D, err := dkg.encryptInnerDealing(ID_D, z_D)
	if err != nil {
		return nil, err
	}

	return &verifiedInitialDealing{OD_D, EID_D}, nil
}

func (dkg *dkg) VerifyInitialDealing(initialDealing UnverifiedInitialDealing, Dꞌ int) (VerifiedInitialDealing, error) {
	if initialDealing == nil {
		return nil, fmt.Errorf("cannot verify nil initial dealing")
	}

	// Outer dealing, verified in this step.
	OD_Dꞌ := initialDealing.internal().OD
	ad := hAd(dkg.iid, "outer", Dꞌ)
	OD_Dꞌ_verified, err := dkg.vessOuter.VerifyDealing(OD_Dꞌ, ad)
	if err != nil {
		return nil, err
	}

	// Encrypted inner dealing, not verified at this stage, basic non-nil check only.
	EID_Dꞌ := initialDealing.internal().EID
	if EID_Dꞌ == nil {
		return nil, fmt.Errorf("cannot verify initial dealing with nil encrypted inner dealing")
	}

	return &verifiedInitialDealing{OD_Dꞌ_verified, EID_Dꞌ}, nil
}

func (dkg *dkg) DecryptDecryptionKeyShares(L []VerifiedInitialDealing) (VerifiedDecryptionKeySharesForInnerDealings, error) {
	n_D := len(dkg.dealers)
	if len(L) != n_D {
		return nil, fmt.Errorf("invalid dealings list length: expected %d, got %d", n_D, len(L))
	}

	// z_D will be filled with the decryption key shares z_{D', D} for all D' ∈ L.
	z_D := make([]math.Scalar, n_D)

	for Dꞌ, L_Dꞌ := range L {
		if L_Dꞌ == nil {
			continue
		}

		OD_Dꞌ := L_Dꞌ.internal().OD
		ad := hAd(dkg.iid, "outer", Dꞌ)
		z_Dꞌ_D, err := dkg.vessOuter.Decrypt(dkg.dealerIndex, dkg.dealerKeyring, OD_Dꞌ, ad)
		if err != nil {
			// This should not happen, as we only invoke the decryption on dealings which previously passed
			// verification. An error here indicates a bug in the implementation.
			return nil, err
		}
		z_D[Dꞌ] = z_Dꞌ_D
	}

	return &verifiedDecryptionKeySharesForInnerDealings{
		&decryptionKeySharesForInnerDealings{dkg.curve, z_D},
	}, nil
}

func (dkg *dkg) VerifyDecryptionKeyShares(
	L []VerifiedInitialDealing, Z_Dˣ UnverifiedDecryptionKeySharesForInnerDealings, Dˣ int,
) (VerifiedDecryptionKeySharesForInnerDealings, error) {
	n_D := len(dkg.dealers)
	curve := Z_Dˣ.internal().base.curve
	z_Dˣ := Z_Dˣ.internal().base.z_D

	if dkg.curve != curve {
		return nil, fmt.Errorf(
			"mismatching curves: DKG uses %s, decryption key shares use %s", dkg.curve.Name(), curve.Name(),
		)
	}
	if len(L) != n_D {
		return nil, fmt.Errorf("invalid dealings list length: expected %d, got %d", n_D, len(L))
	}
	if len(z_Dˣ) != n_D {
		return nil, fmt.Errorf("invalid decryption key shares length: expected %d, got %d", len(dkg.dealers), len(z_Dˣ))
	}

	for Dꞌ, L_Dꞌ := range L {
		if L_Dꞌ == nil {
			continue
		}

		z_Dꞌ_Dˣ := z_Dˣ[Dꞌ]
		OD_Dꞌ := L_Dꞌ.internal().OD
		if err := dkg.vessOuter.VerifyShare(z_Dꞌ_Dˣ, OD_Dꞌ, Dˣ); err != nil {
			return nil, err
		}
	}

	return &verifiedDecryptionKeySharesForInnerDealings{Z_Dˣ.internal().base}, nil
}

type IndicesOfBadDealers = []int

func (dkg *dkg) RecoverInnerDealings(L []VerifiedInitialDealing, z []VerifiedDecryptionKeySharesForInnerDealings) (
	Lꞌ []VerifiedInnerDealing, B IndicesOfBadDealers, restartRequired bool, err error,
) {
	n_D := len(dkg.dealers)
	if len(L) != n_D {
		return nil, nil, false, fmt.Errorf("invalid dealings list length: expected %d, got %d", n_D, len(L))
	}
	if len(z) != len(dkg.dealers) {
		return nil, nil, false, fmt.Errorf("invalid decryption key shares list length: expected %d, got %d", n_D, len(z))
	}

	// Collect the indices of all dealers Dˣ who provided valid decryption key shares z_Dˣ in the list of indices Lˣ.
	Lˣ := make([]int, 0)
	for Dˣ, z_Dˣ := range z {
		if z_Dˣ != nil {
			Lˣ = append(Lˣ, Dˣ)
		}
	}
	// Shares from at least f_D + 1 dealers are required to recover the inner dealings.
	if len(Lˣ) < dkg.DecryptionThreshold() {
		return nil, nil, false, fmt.Errorf(
			"insufficient number of decryption key shares: expected at least %d, got %d",
			dkg.DecryptionThreshold(), len(Lˣ),
		)
	}

	Lꞌ = make([]VerifiedInnerDealing, n_D) // Lꞌ will contain the successfully verified inner dealings
	B = make(IndicesOfBadDealers, 0)       // B will be filled with dealers to ban (where decryption/verification fails)

	// Interpolator for recovering the decryption keys z_Dꞌ for all Dꞌ ∈ Lꞌ.
	interpolate, err := math.NewInterpolator(dkg.curve, Lˣ)
	if err != nil {
		return nil, nil, false, err
	}

	// Keep track of the number of valid inner dealings to be determined in the loop below.
	numValidInnerDealings := 0

	for Dꞌ, L_Dꞌ := range L {
		if L_Dꞌ == nil {
			continue
		}
		EID_Dꞌ := L_Dꞌ.internal().EID

		// Collect all decryptions shares for the inner dealing of Dꞌ.
		shares := make([]math.Scalar, 0, len(Lˣ))
		for _, Dˣ := range Lˣ {
			z_Dꞌ_Dˣ := z[Dˣ].internal().base.z_D[Dꞌ]
			if z_Dꞌ_Dˣ == nil {
				return nil, nil, false, fmt.Errorf("missing decryption share for dealing %d from dealer %d", Dꞌ, Dˣ)
			}
			shares = append(shares, z_Dꞌ_Dˣ)
		}

		// Recover the decryption key z_Dꞌ from the collected shares.
		z_Dꞌ, err := interpolate.ScalarAtZero(shares)
		if err != nil {
			return nil, nil, false, err
		}

		// For re-sharing only, an additional check against the previous sharing is performed, for this purpose
		// y_Dꞌ is needed.
		var y_Dꞌ math.Point
		if dkg.priorResult != nil {
			y_Dꞌ = dkg.priorResult.y_R[Dꞌ]
		}

		// Reconstruct the inner dealing ID_D' from the encrypted inner dealings EID_Dꞌ.
		ID_Dꞌ, err := dkg.decryptAndVerifyInnerDealing(Dꞌ, EID_Dꞌ, z_Dꞌ, y_Dꞌ)
		if err != nil {
			// Dꞌ is added to the list of bad dealers, as the inner dealing could not be decrypted / verified.
			B = append(B, Dꞌ)
			restartRequired = dkg.priorResult != nil // re-sharing requires all dealings to be valid
			continue
		}

		Lꞌ[Dꞌ] = &verifiedInnerDealing{ID_Dꞌ}
		numValidInnerDealings++
	}

	if numValidInnerDealings == 0 {
		// No valid inner dealings could be recovered. This should only ever happen due to a threshold violation.
		return nil, B, restartRequired, fmt.Errorf("no valid inner dealings could be recovered")
	}
	return Lꞌ, B, restartRequired, nil
}

func (dkg *dkg) NewResult(Lꞌ []VerifiedInnerDealing) (Result, error) {
	if len(Lꞌ) != len(dkg.dealers) {
		return nil, fmt.Errorf("invalid inner dealings list length: expected %d, got %d", len(dkg.dealers), len(Lꞌ))
	}

	t_R := dkg.t_R
	C := make(math.PolynomialCommitment, t_R)
	C_Lꞌ := make([]math.PolynomialCommitment, 0) // commitments of all D ∈ L'
	i_Lꞌ := make([]int, 0)                       // indices     of all D ∈ L'

	for D, Lꞌ_D := range Lꞌ {
		if Lꞌ_D == nil {
			continue
		}
		i_Lꞌ = append(i_Lꞌ, D)

		C_D := Lꞌ_D.internal().base.Commitment()
		if len(C_D) != t_R {
			return nil, fmt.Errorf("invalid commitment length: expected %d, got %d", t_R, len(C_D))
		}
		C_Lꞌ = append(C_Lꞌ, C_D)
	}

	if len(C_Lꞌ) == 0 {
		return nil, fmt.Errorf("no valid inner dealings provided")
	}

	interpolate, err := math.NewInterpolator(dkg.curve, i_Lꞌ)
	if err != nil {
		return nil, err
	}

	for k := 0; k < t_R; k++ {
		Cₖ := make(math.Points, len(C_Lꞌ))
		for D, C_D := range C_Lꞌ {
			Cₖ[D] = C_D[k]
		}

		if dkg.priorResult == nil {
			// In the non-resharing case, compute [C] <-- Π_{D ∈ [L']} [C]_D.
			C[k] = Cₖ.Sum()
		} else {
			// In the resharing case, compute [C] via Lagrange interpolation.
			var err error
			if C[k], err = interpolate.PointAtZero(Cₖ); err != nil {
				return nil, fmt.Errorf("failed to interpolate commitment: %w", err)
			}
		}
	}

	y := C[0]                               // y   <-- [C]^(0)
	y_R := C.EvalRange(len(dkg.recipients)) // y_R <-- [C]^(R) for all R ∈ R

	return &result{dkg.iid, dkg.curve, t_R, Lꞌ, y, y_R, dkg.priorResult != nil}, nil
}

// Encrypt the inner dealing package ID_D using the encryption key z_D.
// Specifically, compute EID_D <-- H^l_deal(iid, D, z_D) ⊕ ID_D.
func (dkg *dkg) encryptInnerDealing(ID_D *vess.VerifiedDealing, z_D math.Scalar) ([]byte, error) {
	// The inner dealing package is serialized first.
	ID_D_bytes, err := codec.Marshal(ID_D.AsUnverifiedDealing())
	if err != nil {
		return nil, err
	}

	// Then, the bytes of the inner dealing package are encrypted applying an xor-operation with a one-time pad derived
	// from (iid, D, z_D).
	D := dkg.dealerIndex
	otp := hDeal(dkg.iid, D, z_D, len(ID_D_bytes))
	dst := otp // re-use the otp slice the dst buffer for the result
	if subtle.XORBytes(dst, ID_D_bytes, otp) != len(ID_D_bytes) {
		return nil, fmt.Errorf("failed to encrypt inner dealing package")
	}
	return dst, nil
}

// Decrypt the inner dealing package EID_Dꞌ using the decryption key z_Dꞌ. After (successful) decryption, the inner
// dealing ID_Dꞌ is verified against the recipients.
func (dkg *dkg) decryptAndVerifyInnerDealing(Dꞌ int, EID_Dꞌ []byte, z_Dꞌ math.Scalar, y_Dꞌ math.Point) (*vess.VerifiedDealing, error) {
	otp := hDeal(dkg.iid, Dꞌ, z_Dꞌ, len(EID_Dꞌ))
	dst := otp
	if subtle.XORBytes(dst, EID_Dꞌ, otp) != len(EID_Dꞌ) {
		return nil, fmt.Errorf("failed to decrypt inner dealing package")
	}

	ID_Dꞌ, err := codec.Unmarshal(dst, &vess.UnverifiedDealing{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner dealing package: %w", err)
	}

	ad := hAd(dkg.iid, "inner", Dꞌ)
	ID_Dꞌ_verified, err := dkg.vessInner.VerifyDealing(ID_Dꞌ, ad)
	if err != nil {
		return nil, err
	}

	// For resharing, y_Dꞌ is not nil and must match the prior result's commitment.
	if y_Dꞌ != nil {
		C_Dꞌ := ID_Dꞌ_verified.Commitment()
		if !C_Dꞌ[0].Equal(y_Dꞌ) {
			return nil, fmt.Errorf("resharing verification failure, inner dealing does not match prior dealing")
		}
	}
	return ID_Dꞌ_verified, nil
}

// Setup associated data for the use with VESS.
// Specifically, ad := (iid, tag, D), where tag ∈ { "inner", "outer" }.
func hAd(iid dkgtypes.InstanceID, tag string, D int) []byte {
	h := xof.New("smartcontract.com/dkg/hAd")
	h.WriteString(string(iid))
	h.WriteString(tag)
	h.WriteInt(D)
	return h.Digest()
}

// The hash is used to derive the one-time pad for encrypting the inner dealing package.
// Specifically, it computes H^l_deal(iid, D, z_D), where l is specified in bytes using digestLength.
func hDeal(iid dkgtypes.InstanceID, D int, z_D math.Scalar, digestLength int) []byte {
	h := xof.New("smartcontract.com/dkg/hDeal")
	h.WriteString(string(iid))
	h.WriteInt(D)
	h.WriteBytes(z_D.Bytes())

	result := make([]byte, digestLength)
	_, _ = h.Read(result)
	return result
}
