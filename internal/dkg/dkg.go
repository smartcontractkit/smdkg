package dkg

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/hash"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/smdkg/internal/serialization"
	"github.com/smartcontractkit/smdkg/internal/vess"
)

// Stateless DKG instance to be used with the DKG plugin. Abstracts all cryptographic operations required for the DKG
// protocol. Use NewInitialDKG(...) or NewResharingDKG(...) to create a new instance for a fresh or re-sharing DKG.
// All state transitions are handled by the DKG plugin, i.e., after initialization the DKG instance's variables are
// not modified anymore.
type DKG = *dkg

type dkg struct {
	iid         dkgtypes.InstanceID
	curve       math.Curve
	vessInner   vess.VESS
	vessOuter   vess.VESS
	f_D         int
	t_R         int
	dealers     []dkgtypes.PublicIdentity
	recipients  []dkgtypes.PublicIdentity
	priorResult *Result
	privID      dkgtypes.PrivateIdentity
}

func (dkg *dkg) Curve() math.Curve {
	return dkg.curve
}

func (dkg *dkg) Dealers() []dkgtypes.PublicIdentity {
	return dkg.dealers
}

func (dkg *dkg) Recipients() []dkgtypes.PublicIdentity {
	return dkg.recipients
}

type Dealing interface {
	internal()
	Bytes() ([]byte, error)
}

type InnerDealing struct {
	D  dkgtypes.PublicIdentity // D' is the dealer that created the inner dealing
	ID vess.Dealing            // ID_D': inner dealing, shares s_D to the recipients
}

type dealing struct {
	D   dkgtypes.PublicIdentity // D: dealer that created the dealing, not send over the network
	OD  vess.Dealing            // OD_D: outer dealing, shares z_D to the dealers D
	EID []byte                  // EID_D: encrypted inner dealing, shares ID_D to the recipients R, encrypted with z_D
}

func (d *dealing) internal() {}

func (d *dealing) Bytes() ([]byte, error) {
	encoder := serialization.NewEncoder()
	OD_bytes, err := d.OD.Bytes()
	if err != nil {
		return nil, err
	}
	encoder.WriteBytes(OD_bytes)
	encoder.WriteBytes(d.EID)
	return encoder.Bytes()
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
// Returns a new DKG instance for the use with the DKG plugin.
// Initialization may fail, e.g., if a given public key cannot be unmarshaled correctly.
func NewInitialDKG(
	iid dkgtypes.InstanceID,
	curve math.Curve,
	dealers []dkgtypes.ParticipantPublicKey,
	recipients []dkgtypes.ParticipantPublicKey,
	f_D int,
	t_R int,
	privID dkgtypes.PrivateIdentity,
) (DKG, error) {
	D, err1 := loadIdentities(curve, dealers)
	R, err2 := loadIdentities(curve, recipients)
	if err1 != nil {
		return nil, fmt.Errorf("failed to load dealer public keys: %w", err1)
	}
	if err2 != nil {
		return nil, fmt.Errorf("failed to load recipient public keys: %w", err2)
	}

	vessInner, err1 := vess.NewVESS(curve, iid, "inner", len(R), t_R)
	vessOuter, err2 := vess.NewVESS(curve, iid, "outer", len(D), f_D+1)
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	return &dkg{iid, curve, vessInner, vessOuter, f_D, t_R, D, R, nil, privID}, nil
}

// Initializes a new (stateless) DKG instance for the given instance ID, to re-share the master secret key, previously
// set up via a (fresh or re-shared) DKG instance to a (potentially) different list of recipients.
//
// Various parameters are determined by the prior instance's result:
//   - the use elliptic curve
//   - the dealer configuration and public keys, i.e., the new dealers are the old recipients.
//
// Parameters:
//   - iid: the instance ID of the new DKG instance
//   - recipients: the public keys of the new recipients
//   - t_R: the reconstruction threshold, i.e., the minimum number of new recipients' shares needed for deriving the
//     master secret
//   - priorResult: the result of the prior DKG instance, determines the underlying secrets to be re-shared
//   - keyring: the keyring is required to load a private key share of the master secret key for re-sharing
//
// Returns a new DKG instance for the use with the DKG plugin.
// Initialization may fail, e.g., if a given public key cannot be unmarshaled correctly.
func NewResharingDKG(
	iid dkgtypes.InstanceID,
	dealers []dkgtypes.ParticipantPublicKey, // must match the prior result's recipients
	recipients []dkgtypes.ParticipantPublicKey,
	f_D int,
	t_R int,
	prior *Result,
	privID dkgtypes.PrivateIdentity,
) (DKG, error) {
	curve := prior.curve

	D, err := loadIdentities(curve, dealers)
	if err != nil {
		return nil, fmt.Errorf("failed to load dealer public keys: %w", err)
	}

	R, err := loadIdentities(curve, recipients)
	if err != nil {
		return nil, fmt.Errorf("failed to load recipient public keys: %w", err)
	}

	vessInner, err1 := vess.NewVESS(curve, iid, "inner", len(R), t_R)
	vessOuter, err2 := vess.NewVESS(curve, iid, "outer", len(D), f_D+1)
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	return &dkg{iid, curve, vessInner, vessOuter, f_D, t_R, D, R, prior, privID}, nil
}

// Executed by dealer D to (re-)share a secret s_D with the recipients of the DKG. If this DKG instance is configured
// for re-sharing, s_D from the prior DKG's result is used. Otherwise s_D is initialized as a fresh random secret.
// The result is composed of two parts:
//   - the outer dealing OD_D, sharing a random secret z_D (used as encryption key) with the dealers D,
//   - the encrypted inner dealing EID_D, i.e., ID_D ((re-)sharing s_D with the recipients R), encrypted with z_D.'
func (dkg *dkg) Deal(rand io.Reader) (Dealing, error) {
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
		if s_D, err = dkg.priorResult.MasterSecretKeyShare(dkg.privID); err != nil {
			return nil, fmt.Errorf("failed to receive secret share: %w", err)
		}
	}

	// Create the inner dealing ID_D that t_R out of n_R secret-shares s_D to the recipients R.
	// ID_D <-- VESS.Deal(s_D, R, t_R, ek_R ad), where ad := (iid, "inner", D).
	ad, err := newAd(dkg.iid, "inner", dkg.privID)
	if err != nil {
		return nil, err
	}
	ID_D, err := dkg.vessInner.Deal(s_D, dkg.recipients, ad, rand)
	if err != nil {
		return nil, err
	}

	// Choose a second random secret z_D and create the outer dealing OD_D that (f_D + 1) out of n_D secret-shares
	// z_D to the dealers D. OD_D <-- VESS.Deal(z_D, D, f_D + 1, ek_D, ad), where ad := (iid, "outer", D).
	z_D, err := dkg.curve.Scalar().SetRandom(rand)
	if err != nil {
		return nil, err
	}
	ad, err = newAd(dkg.iid, "outer", dkg.privID)
	if err != nil {
		return nil, err
	}
	OD_D, err := dkg.vessOuter.Deal(z_D, dkg.dealers, ad, rand)
	if err != nil {
		return nil, err
	}

	// Encrypt the inner ID_D using the secret shared with the second dealing.
	// I.e., compute EID_D <-- H^l_deal(iid, D, z_D) ⊕ ID_D.
	EID_D, err := dkg.encryptInnerDealing(dkg.privID, ID_D, z_D)
	if err != nil {
		return nil, err
	}

	return &dealing{dkg.privID, OD_D, EID_D}, nil
}

// TODO: document
func (dkg *dkg) VerifyDealing(Dꞌ dkgtypes.PublicIdentity, OD_Dꞌ__EID_Dꞌ []byte) (Dealing, error) {
	decoder := serialization.NewDecoder(OD_Dꞌ__EID_Dꞌ)
	ODꞌ_bytes := decoder.ReadBytes()
	EID_Dꞌ := decoder.ReadBytes()
	if err := decoder.Finish(); err != nil {
		return nil, err
	}

	ad, err := newAd(dkg.iid, "outer", Dꞌ)
	if err != nil {
		return nil, err
	}

	// TODO: Here the variable names clash quite a bit, the first parameter of vess.Verify is called D, but is not our
	// identity D
	OD_Dꞌ, err := dkg.vessOuter.VerifyDealing(ODꞌ_bytes, dkg.dealers, ad)
	if err != nil {
		return nil, err
	}

	return &dealing{Dꞌ, OD_Dꞌ, EID_Dꞌ}, nil
}

// Indicates how many initial dealings must be collected and validated successfully by the plugin before nodes can start
// to decrypt their decryption shares, corresponds to |L|.
func (dkg *dkg) DealingsThreshold() int {
	if dkg.priorResult == nil {
		return dkg.f_D + 1
	} else {
		return dkg.priorResult.t_R
	}
}

// Indicates how many decryption shares must be collected by the plugin before the inner dealings case be recovered.
func (dkg *dkg) DecryptionThreshold() int {
	return dkg.f_D + 1
}

// Executed when the dealer D successfully collected a list L of f_D + 1 dealings (OD_Dꞌ, EID_Dꞌ) from different
// dealers Dꞌ. Decrypt the outer dealings OD_Dꞌ to obtain the decryption key shares using D' secret key sk_D.
// Returns z_{Dꞌ, D} for all dealers Dꞌ ∈ L:
//   - D acts as the recipient of the the decryption key shares
//   - which have D as the recipients, and all
func (dkg *dkg) DecryptDecryptionKeyShares(L []Dealing) (math.Scalars, error) {
	z_all_D := make(math.Scalars, 0)

	for _, L_Dꞌ := range L {
		OD_Dꞌ := L_Dꞌ.(*dealing).OD

		// Decrypt the outer dealing from D' to D.
		z_Dꞌ_D, err := dkg.vessOuter.Decrypt(dkg.privID, OD_Dꞌ)
		if err != nil {
			// This should not happen, as we only invoke the decryption on dealings which previously passed
			// verification. An error here indicates a bug in the implementation.
			return nil, err
		}
		z_all_D = append(z_all_D, z_Dꞌ_D)
	}

	return z_all_D, nil
}

// Executed when some dealer D wants to verify the decryption key shares (z_{D', D*}) the dealer D* (=Dˣ below)
// broadcasted. The dealers D' ∈ L are the original issuers of the shares. When the verification is successful, the
// function returns the parsed decryption key shares z_{D', Dˣ} for all D' ∈ L.
func (dkg *dkg) VerifyDecryptionKeyShares(z_Dꞌ_Dˣ_bytes []byte, L []Dealing, Dˣ dkgtypes.PublicIdentity) ([]math.Scalar, error) {
	decoder := serialization.NewDecoder(z_Dꞌ_Dˣ_bytes)
	z_Dꞌ_Dˣ := make([]math.Scalar, 0)

	for _, tuple := range L {
		OD_Dꞌ := tuple.(*dealing).OD

		// Convert the serialized value to a math.Scalar and verify it.
		z, err := dkg.curve.Scalar().SetBytes(decoder.ReadBytes())
		if err != nil {
			return nil, err
		}
		if err := dkg.vessOuter.VerifyShare(z, OD_Dꞌ, Dˣ); err != nil {
			return nil, err
		}
		z_Dꞌ_Dˣ = append(z_Dꞌ_Dˣ, z)
	}

	if err := decoder.Finish(); err != nil {
		return nil, err
	}

	if len(z_Dꞌ_Dˣ) != len(L) {
		return nil, fmt.Errorf("expected %d decryption key shares, got %d", len(L), len(z_Dꞌ_Dˣ))
	}
	return z_Dꞌ_Dˣ, nil
}

func (dkg *dkg) RecoverInnerDealings(L []Dealing, z map[dkgtypes.PublicIdentity]math.Scalars) ([]InnerDealing, []dkgtypes.PublicIdentity, bool, error) {
	Lꞌ := make([]InnerDealing, 0)           // Lꞌ will contain the successfully verified inner dealings
	B := make([]dkgtypes.PublicIdentity, 0) // B will be filled with dealers to ban (where decryption/verification fails)

	xs := make([]math.Scalar, 0)
	for _, Dˣ := range dkg.dealers {
		if _, ok := z[Dˣ]; ok {
			xs = append(xs, Dˣ.XCoord())
		}
	}

	startFromScratch := false
	for i, L_Dꞌ := range L {
		Dꞌ := L_Dꞌ.(*dealing).D
		EID_Dꞌ := L_Dꞌ.(*dealing).EID

		// 1. Reconstruct the decryption keys z_D'.
		// Prepare the points to reconstruct the decryption key z_Dꞌ from all dealers in Dˣ.
		ys := make([]math.Scalar, 0)

		// Iterate over all dealers Dˣ, ensuring a consistent order (which strictly speaking should not be necessary).
		for _, Dˣ := range dkg.dealers {
			if z_Dˣ, ok := z[Dˣ]; ok {
				z_Dˣ_Dꞌ := z_Dˣ[i]
				ys = append(ys, z_Dˣ_Dꞌ)
			}
		}

		// As the x coordinates do not change, we could optimize the following interpolation call, for simplicity we
		// do not do this here.
		z_Dꞌ, err := math.InterpolatePolynomialZero(xs, ys)
		if err != nil {
			return nil, nil, startFromScratch, err
		}

		// For re-sharing only, an additional check againt the previous sharing is performed.
		var y_Dꞌ math.Point
		if dkg.priorResult != nil {
			y_Dꞌ = dkg.priorResult.y_R[i]
		}

		// 2. Reconstruct the inner dealing ID_D' from the encrypted inner dealings EID_Dꞌ.
		ID_Dꞌ, err := dkg.decryptAndVerifyInnerDealing(Dꞌ, EID_Dꞌ, z_Dꞌ, y_Dꞌ)
		if err != nil {
			if dkg.priorResult != nil {
				// Dꞌ is banned, as the inner dealing could not be decrypted / verified
				B = append(B, Dꞌ)
				startFromScratch = true
			}
			continue
		}

		Lꞌ = append(Lꞌ, InnerDealing{Dꞌ, ID_Dꞌ})
	}

	return Lꞌ, B, startFromScratch, nil
}

// Derive the DKG's results from the given list of verified inner dealings (i.e., for all D' ∈ L').
func (dkg *dkg) NewResult(Lꞌ []InnerDealing) (*Result, error) {
	t_R := dkg.t_R
	C := make(math.PolynomialCommitment, t_R)

	if dkg.priorResult == nil {
		// In the non-resharing case, compute [C] <-- Π_{D ∈ [L']} [C]_D.
		for k := 0; k < len(C); k++ {
			C_Dₖ := make(math.Points, len(Lꞌ))
			for i, item := range Lꞌ {
				C_D := item.ID.Commitment()
				if len(C_D) != len(C) {
					return nil, fmt.Errorf("invalid commitment length: expected %d, got %d", len(C), len(C_D))
				}
				C_Dₖ[i] = C_D[k]
			}
			C[k] = C_Dₖ.Sum()
		}
	} else {
		// In the resharing case, compute [C] via langrange interpolation.
		xs := make([]math.Scalar, len(Lꞌ))
		for i, item := range Lꞌ {
			xs[i] = item.D.XCoord()
		}

		for k := 0; k < len(C); k++ {
			ys := make([]math.Point, len(Lꞌ))
			for i, item := range Lꞌ {
				C_D := item.ID.Commitment()
				if len(C_D) != len(C) {
					return nil, fmt.Errorf("invalid commitment length: expected %d, got %d", len(C), len(C_D))
				}
				ys[i] = C_D[k]
			}

			var err error
			if C[k], err = math.InterpolateCommitmentZero(xs, ys); err != nil {
				return nil, fmt.Errorf("failed to interpolate commitment: %w", err)
			}
		}
	}

	y, y_R := dkg.computeMasterPublicKeys(C)
	return &Result{dkg.iid, dkg.curve, t_R, Lꞌ, y, y_R, dkg.priorResult != nil}, nil
}

func (dkg *dkg) computeMasterPublicKeys(C math.PolynomialCommitment) (math.Point, []math.Point) {
	zero := dkg.curve.Scalar()
	y := C.Eval(zero)
	y_R := make([]math.Point, len(dkg.recipients))
	for i, R := range dkg.recipients {
		y_R[i] = C.Eval(R.XCoord())
	}
	return y, y_R
}

func loadIdentities(curve math.Curve, keys []dkgtypes.ParticipantPublicKey) ([]dkgtypes.PublicIdentity, error) {
	P := make([]dkgtypes.PublicIdentity, len(keys))
	for i, pk := range keys {
		pk, err := dkgtypes.NewP256PublicKey(pk)
		if err != nil {
			return nil, fmt.Errorf("invalid public key at index %d: %w", i, err)
		}
		P[i] = dkgtypes.NewPublicIdentity(i, pk, curve.Scalar().SetUint(uint(i+1)))
	}
	return P, nil
}

// Setup authenticated data for the use with VESS.
// Specifically, ad := (iid, tag, D), where tag ∈ { "inner", "outer" }.
func newAd(iid dkgtypes.InstanceID, tag string, D dkgtypes.PublicIdentity) ([]byte, error) {
	switch tag {
	case "inner":
	case "outer":
	default:
		return nil, fmt.Errorf("invalid authenticated data, tag must be from { \"inner\", \"outer\" }, given: %s", tag)
	}

	enc := serialization.NewEncoder()
	enc.WriteString(iid)
	enc.WriteString(tag)
	enc.WriteBytes(D.PublicKey().Bytes())
	return enc.Bytes()
}

// Encrypt the inner dealing package ID_D using the encryption key z_D.
// Specifically, compute EID_D <-- H^l_deal(iid, D, z_D) ⊕ ID_D.
func (dkg *dkg) encryptInnerDealing(D dkgtypes.PublicIdentity, ID_D vess.Dealing, z_D math.Scalar) ([]byte, error) {
	// The inner dealing package is serialized first.
	ID_D_bytes, err := ID_D.Bytes()
	if err != nil {
		return nil, err
	}

	// Then, the bytes of the inner dealing package are encrypted applying an xor-operation with a one-time pad derived
	// from (iid, D, z_D).
	otp, err := hDeal(dkg.iid, D, z_D, len(ID_D_bytes))
	if err != nil {
		return nil, err
	}
	dst := otp
	if subtle.XORBytes(dst, ID_D_bytes, otp) != len(ID_D_bytes) {
		return nil, fmt.Errorf("failed to encrypt inner dealing package")
	}
	return dst, nil
}

// Decrypt the inner dealing package EID_Dꞌ using the decryption key z_Dꞌ. After (successful) decryption, the inner
// dealing ID_Dꞌ is verified against the recipients.
func (dkg *dkg) decryptAndVerifyInnerDealing(Dꞌ dkgtypes.PublicIdentity, EID_Dꞌ []byte, z_Dꞌ math.Scalar, y_Dꞌ math.Point) (vess.Dealing, error) {
	otp, err := hDeal(dkg.iid, Dꞌ, z_Dꞌ, len(EID_Dꞌ))
	if err != nil {
		return nil, err
	}
	dst := otp
	if subtle.XORBytes(dst, EID_Dꞌ, otp) != len(EID_Dꞌ) {
		return nil, fmt.Errorf("failed to decrypt inner dealing package")
	}

	ad, err := newAd(dkg.iid, "inner", Dꞌ)
	if err != nil {
		return nil, err
	}

	ID_Dꞌ, err := dkg.vessInner.VerifyDealing(dst, dkg.recipients, ad)
	if err != nil {
		return nil, err
	}

	if y_Dꞌ != nil {
		C_Dꞌ := ID_Dꞌ.Commitment()
		if !C_Dꞌ.Eval(dkg.curve.Scalar()).Equal(y_Dꞌ) {
			return nil, fmt.Errorf("resharing verification failure, inner dealing does not match prior dealing")
		}
	}
	return ID_Dꞌ, nil
}

// The hash is used to derive the one-time pad for encrypting the inner dealing package.
// Specifically, it computes H^l_deal(iid, D, z_D), where l is specified in bytes using digestLength.
func hDeal(iid dkgtypes.InstanceID, D dkgtypes.PublicIdentity, z_D math.Scalar, digestLength int) ([]byte, error) {
	h := hash.NewHash("smartcontract.com/dkg/hDeal")
	h.WriteString(iid)
	h.WriteBytes(D.PublicKey().Bytes())
	h.WriteBytes(z_D.Bytes())
	return h.Digest(digestLength)
}
