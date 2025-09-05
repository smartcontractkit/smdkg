package crs

import (
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/xof"
)

// See https://www.rfc-editor.org/rfc/rfc9380.html#name-suites-for-nist-p-256
var p256FieldModulus = math.NewModulus("115792089210356248762697446949407573530086143415290314195533631308867097853951")
var p256ParamA = math.NewScalar(p256FieldModulus).Subtract(math.NewScalar(p256FieldModulus).SetUint(3)) // -3
var p256ParamB = math.NewScalarFromString(
	"41058363725152142129326129780047268409114441015993725554835256314039467401291",
	p256FieldModulus,
)
var p256ParamPNeg1Half = math.NewScalarFromString(
	"57896044605178124381348723474703786765043071707645157097766815654433548926975", // (p - 1) / 2
	p256FieldModulus,
)

// Deterministically derive a point on the P256 curve (as used, e.g. by MRE) based on the provided instance ID.
// The point is typically used as the common reference string (CRS) for the VESS protocol. Its discrete logarithm
// relative to the base point is not known. The implementation is NOT constant-time and therefore not suitable for a
// general-purpose hash-to-curve implementation.
func NewP256CRS(iid dkgtypes.InstanceID, tag string) (dkgtypes.P256PublicKey, error) {
	h := xof.New("smartcontract.com/dkg/crs")
	h.WriteString(string(iid))
	h.WriteString(tag)

	for {
		x, err := math.NewScalar(p256FieldModulus).SetRandom(h)
		if err != nil {
			return dkgtypes.P256PublicKey{}, err
		}

		x3 := x.Clone().Multiply(x).Multiply(x) // x^3
		Ax := p256ParamA.Clone().Multiply(x)
		y2 := x3.Add(Ax).Add(p256ParamB) // y^2 = x^3 + A*x + B

		// Check if y² is a quadratic residue modulo p. If it is not, we retry with a different x.
		// if y² ^ (([p-1) / 2) != 1
		if !y2.Exp(p256ParamPNeg1Half.Bytes()).IsOne() {
			continue
		}

		encodedPoint := make([]byte, 33)
		copy(encodedPoint[1:], x.Bytes())

		// Randomize the sign bit uniformly; result is 0x02 or 0x03.
		sign := []byte{0}
		_, _ = h.Read(sign)
		encodedPoint[0] = 0x02 | (sign[0] & 0x01)

		p, err := dkgtypes.NewP256PublicKey(encodedPoint)
		if err != nil {
			return dkgtypes.P256PublicKey{}, err
		}
		return p, nil
	}
}
