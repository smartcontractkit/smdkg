package testimplementations

import (
	"io"

	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
)

var _ dkgtypes.P256Keyring = &p256Keyring{}

// Test implementation of dkgtypes.p256Keyring using a local secret key.
type p256Keyring struct {
	keyPair dkgtypes.P256KeyPair
}

func NewP256Keyring(keyPair dkgtypes.P256KeyPair) dkgtypes.P256Keyring {
	return &p256Keyring{keyPair}
}

func NewRandomP256Keyring(rand io.Reader) (dkgtypes.P256Keyring, error) {
	k, err := dkgtypes.NewP256KeyPair(rand)
	if err != nil {
		return nil, err
	}
	return &p256Keyring{k}, nil
}

func (i *p256Keyring) PublicKey() dkgtypes.P256PublicKey {
	return i.keyPair.PublicKey
}

func (i *p256Keyring) ECDH(pubKey dkgtypes.P256PublicKey) (dkgtypes.P256ECDHSharedSecret, error) {
	return i.keyPair.SecretKey.ECDH(pubKey)
}
