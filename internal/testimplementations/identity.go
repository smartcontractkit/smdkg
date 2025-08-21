package testimplementations

import (
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
)

var _ dkgtypes.PrivateIdentity = &privateIdentity{}

// Test implementation of dkgtypes.PrivateIdentity using a local secret key.
type privateIdentity struct {
	index   int
	keyPair dkgtypes.P256KeyPair
	xCoord  math.Scalar
}

func NewPrivateIdentity(index int, keyPair dkgtypes.P256KeyPair, xCoord math.Scalar) dkgtypes.PrivateIdentity {
	return &privateIdentity{
		index:   index,
		keyPair: keyPair,
		xCoord:  xCoord,
	}
}

func (i *privateIdentity) Index() int {
	return i.index
}

func (i *privateIdentity) PublicKey() dkgtypes.P256PublicKey {
	return i.keyPair.PublicKey
}

func (i *privateIdentity) XCoord() math.Scalar {
	return i.xCoord
}

func (i *privateIdentity) ECDH(pubKey dkgtypes.P256PublicKey) ([]byte, error) {
	return i.keyPair.SecretKey.ECDH(pubKey)
}
