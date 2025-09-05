package p256keyringshim

import (
	"fmt"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
)

var _ dkgtypes.P256Keyring = &wrappedP256keyring{}

type wrappedP256keyring struct {
	keyring   dkgocrtypes.P256Keyring
	publicKey dkgtypes.P256PublicKey
}

func New(keyring dkgocrtypes.P256Keyring) (dkgtypes.P256Keyring, error) {
	pk, err := dkgtypes.NewP256PublicKey(keyring.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	return &wrappedP256keyring{keyring, pk}, nil
}

func (id *wrappedP256keyring) PublicKey() dkgtypes.P256PublicKey {
	return id.publicKey
}

func (id *wrappedP256keyring) ECDH(remotePublicKey dkgtypes.P256PublicKey) (dkgtypes.P256ECDHSharedSecret, error) {
	rpk := remotePublicKey.Bytes()

	if len(rpk) != dkgocrtypes.P256ParticipantPublicKeyLength {
		return nil, fmt.Errorf(
			"invalid public key length: %d, expected %d bytes",
			len(rpk), dkgocrtypes.P256ParticipantPublicKeyLength,
		)
	}

	sharedSecret, err := id.keyring.ECDH(rpk)
	if err != nil {
		return nil, fmt.Errorf("keyring ECDH operation failed: %w", err)
	}
	if len(sharedSecret) != dkgocrtypes.P256ECDHSharedSecretLength {
		return nil, fmt.Errorf(
			"keyring ECDH operation failed, call returned invalid shared secret length: %d, expected %d bytes",
			len(sharedSecret), dkgocrtypes.P256ECDHSharedSecretLength,
		)
	}
	return dkgtypes.P256ECDHSharedSecret(sharedSecret), nil
}
