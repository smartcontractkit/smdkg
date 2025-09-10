package dkg

import (
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/vess"
)

// High level data types returned by the DKG instance methods.
// For the implementations of marshaling and unmarshaling, see marshal.go.

// Represents result of the DKG protocol execution.
type Result interface {
	internal() *result
	codec.Codec[Result]

	// Returns the unique identifier for the DKG instance.
	InstanceID() dkgtypes.InstanceID

	// Return the curve underlying all DKG sharing computations.
	Curve() math.Curve

	// Master public key of the result of the DKG protocol.
	MasterPublicKey() math.Point

	// Shares of the master public key for all recipients.
	MasterPublicKeyShares() []math.Point

	// Function to retrieve the master secret key share with the given index (requires decryption).
	MasterSecretKeyShare(index int, keyring dkgtypes.P256Keyring) (math.Scalar, error)
}

// When sending/receiving an initial dealing over the network, an UnverifiedInitialDealing is used. A valid
// UnverifiedInitialDealing can be always be converted to a VerifiedInitialDealing by calling dkg.VerifyDealing(...).
//
// An UnverifiedInitialDealing contains two parts:
//   - the outer dealing OD_D, which contains shares z_D for all dealers D in the DKG instance, and
//   - the encrypted inner dealing EID_D, which contains shares ID_D for all recipients R in the DKG instance.
type UnverifiedInitialDealing interface {
	internal() *unverifiedInitialDealing
	codec.Codec[UnverifiedInitialDealing]
}

// In addition to the underlying fields of a UnverifiedInitialDealing a VerifiedInitialDealing may internally contain
// additional (cached) fields required by later DKG operations. For transmission purposes, a VerifiedInitialDealing can
// be converted back to an UnverifiedInitialDealing by calling AsUnverifiedDealing().
type VerifiedInitialDealing interface {
	internal() *verifiedInitialDealing
	codec.Codec[VerifiedInitialDealing]

	// Returns the underlying UnverifiedInitialDealing, dropping any internally cached fields not required for
	// transmission of a dealing to a third party.
	AsUnverifiedDealing() UnverifiedInitialDealing
}

// The UnverifiedDecryptionKeySharesForInnerDealings type represents a (received) dealer's contribution to the decryption
// of the inner dealings prior to verification.
type UnverifiedDecryptionKeySharesForInnerDealings interface {
	internal() *unverifiedDecryptionKeySharesForInnerDealings
	codec.Codec[UnverifiedDecryptionKeySharesForInnerDealings]
}

type VerifiedDecryptionKeySharesForInnerDealings interface {
	internal() *verifiedDecryptionKeySharesForInnerDealings
	codec.Codec[VerifiedDecryptionKeySharesForInnerDealings]

	// Returns the underlying UnverifiedDecryptionKeySharesForInnerDealings instance.
	AsUnverifiedShares() UnverifiedDecryptionKeySharesForInnerDealings
}

// In contract to the initial dealings types, the VerifiedInnerDealing types represent a correctly verified and
// decrypted data structure used in the later steps of the DKG protocol. Its raw data is contained in an encrypted form
// within an valid initial dealing.
type VerifiedInnerDealing interface {
	internal() *verifiedInnerDealing
	codec.Codec[VerifiedInnerDealing]
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ Result = &result{}
var _ UnverifiedInitialDealing = &unverifiedInitialDealing{}
var _ VerifiedInitialDealing = &verifiedInitialDealing{}
var _ UnverifiedDecryptionKeySharesForInnerDealings = &unverifiedDecryptionKeySharesForInnerDealings{}
var _ VerifiedDecryptionKeySharesForInnerDealings = &verifiedDecryptionKeySharesForInnerDealings{}
var _ VerifiedInnerDealing = &verifiedInnerDealing{}

type result struct {
	iid         dkgtypes.InstanceID
	curve       math.Curve
	t_R         int
	Lꞌ          []VerifiedInnerDealing
	y           math.Point   // master public key
	y_R         []math.Point // master public key shares
	wasReshared bool         // if true, this result was obtained from a re-sharing, otherwise from a fresh dealing
}

type encryptedInnerDealing = []byte

type unverifiedInitialDealing struct {
	OD  *vess.UnverifiedDealing // OD_D: outer dealing, shares z_D to the dealers D
	EID encryptedInnerDealing   // EID_D: encrypted inner dealing, shares ID_D to the recipients R, encrypted with z_D
}

type verifiedInitialDealing struct {
	OD  *vess.VerifiedDealing // OD_D: outer dealing, shares z_D to the dealers D
	EID encryptedInnerDealing // EID_D: encrypted inner dealing, shares ID_D to the recipients R, encrypted with z_D
}

// Holds the result of the process where dealer D decrypted all outer dealings OD_D' to obtain the decryption key
// shares z_{D', D} for all dealers D' in the DKG instance. The number of non-nil entries in z_D is either f_D + 1
// (fresh dealing) or t_D (re-sharing).
type decryptionKeySharesForInnerDealings struct {
	curve math.Curve
	z_D   []math.Scalar // len(z_D) == n_D; z_D[D'] == nil iff D' ∉ L
}

type unverifiedDecryptionKeySharesForInnerDealings struct {
	base *decryptionKeySharesForInnerDealings
}

type verifiedDecryptionKeySharesForInnerDealings struct {
	base *decryptionKeySharesForInnerDealings
}

type verifiedInnerDealing struct {
	base *vess.VerifiedDealing
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (r *result) internal() *result                                     { return r }
func (d *unverifiedInitialDealing) internal() *unverifiedInitialDealing { return d }
func (d *verifiedInitialDealing) internal() *verifiedInitialDealing     { return d }
func (s *unverifiedDecryptionKeySharesForInnerDealings) internal() *unverifiedDecryptionKeySharesForInnerDealings {
	return s
}
func (s *verifiedDecryptionKeySharesForInnerDealings) internal() *verifiedDecryptionKeySharesForInnerDealings {
	return s
}
func (d *verifiedInnerDealing) internal() *verifiedInnerDealing { return d }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (r *result) InstanceID() dkgtypes.InstanceID {
	return r.iid
}

func (r *result) Curve() math.Curve {
	return r.curve
}

func (r *result) MasterPublicKey() math.Point {
	return r.y.Clone()
}

func (r *result) MasterPublicKeyShares() []math.Point {
	y_R := make([]math.Point, len(r.y_R))
	for i, yᵢ := range r.y_R {
		y_R[i] = yᵢ.Clone()
	}
	return y_R
}

func (r *result) MasterSecretKeyShare(R int, dk_R dkgtypes.P256Keyring) (math.Scalar, error) {
	n_R := len(r.y_R)
	t_R := r.t_R

	vess, err := vess.NewVESS(r.curve, r.iid, "inner", n_R, t_R, nil)
	if err != nil {
		return nil, err
	}

	indices := make([]int, 0, t_R)       // index(D), where D ∈ L'
	shares := make(math.Scalars, 0, t_R) // S_{D, R}, where D ∈ L'

	for D, L_D := range r.Lꞌ {
		if L_D == nil {
			continue
		}

		ad := hAd(r.iid, "inner", D)
		share, err := vess.Decrypt(R, dk_R, L_D.internal().base, ad)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt inner share from inner dealing: %w", err)
		}

		indices = append(indices, D)
		shares = append(shares, share)
	}

	var S_R math.Scalar
	if !r.wasReshared {
		// If this result was obtained from a fresh dealing, the master secret key is given by the sum of all shares.
		S_R = shares.Sum()
	} else {
		// If this result was obtained from a re-sharing, interpolate the master secret key share.
		interpolate, err := math.NewInterpolator(r.curve, indices)
		if err != nil {
			return nil, err
		}
		S_R, err = interpolate.ScalarAtZero(shares)
		if err != nil {
			return nil, fmt.Errorf("failed to interpolate master secret key share: %w", err)
		}
	}
	return S_R, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (d *verifiedInitialDealing) AsUnverifiedDealing() UnverifiedInitialDealing {
	return &unverifiedInitialDealing{d.OD.AsUnverifiedDealing(), d.EID}
}

func (s *verifiedDecryptionKeySharesForInnerDealings) AsUnverifiedShares() UnverifiedDecryptionKeySharesForInnerDealings {
	return &unverifiedDecryptionKeySharesForInnerDealings{s.base}
}
