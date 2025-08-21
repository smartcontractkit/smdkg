package dkg

import (
	"encoding"
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/smdkg/internal/vess"
)

var _ encoding.BinaryMarshaler = &Result{}
var _ encoding.BinaryUnmarshaler = &Result{}

type Result struct {
	iid         dkgtypes.InstanceID
	curve       math.Curve
	t_R         int
	Lꞌ          []InnerDealing
	y           math.Point   // master public key
	y_R         []math.Point // master public key shares
	wasReshared bool         // if true, this result was obtained from a re-sharing, otherwise from a fresh dealing
}

// Returns the unique identifier for the DKG instance.
func (r *Result) InstanceID() dkgtypes.InstanceID {
	return r.iid
}

// Return the curve underlying all DKG sharing computations.
func (r *Result) Curve() math.Curve {
	return r.curve
}

// Master public key of the result of the DKG protocol.
func (r *Result) MasterPublicKey() math.Point {
	return r.y
}

// Shares of the master public key for all recipients.
func (r *Result) MasterPublicKeyShares() []math.Point {
	return r.y_R
}

// Function to retrieve the master secret key share (requires decryption).
func (r *Result) MasterSecretKeyShare(R dkgtypes.PrivateIdentity) (math.Scalar, error) {
	t_R := r.t_R
	n_R := len(r.y_R)

	vess, err := vess.NewVESS(r.curve, r.iid, "inner", n_R, t_R)
	if err != nil {
		return nil, err
	}

	shares := make(math.Scalars, len(r.Lꞌ)) // S_{D, R}, where D ∈ L'
	xs := make(math.Scalars, len(r.Lꞌ))     // D.XCoord(), where D ∈ L', required for interpolation

	for i, item := range r.Lꞌ {
		xs[i] = item.D.XCoord()
		ID_D := item.ID
		if shares[i], err = vess.Decrypt(R, ID_D); err != nil {
			return nil, fmt.Errorf("failed to decrypt inner share from inner dealing: %w", err)
		}
	}

	var S_R math.Scalar
	if !r.wasReshared {
		// If this result was obtained from a fresh dealing, the master secret key is given by the sum of all shares.
		S_R = shares.Sum()
	} else {
		// If this result was obtained from a re-sharing, interpolate the master secret key share.
		S_R, err = math.InterpolatePolynomialZero(xs, shares)
		if err != nil {
			return nil, fmt.Errorf("failed to interpolate master secret key share: %w", err)
		}
	}
	return S_R, nil
}

func (r *Result) MarshalBinary() ([]byte, error) {
	panic("not implemented")
}

func (r *Result) UnmarshalBinary(data []byte) error {
	panic("not implemented")
}
