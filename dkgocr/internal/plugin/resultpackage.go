package plugin

import (
	"bytes"
	"fmt"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkg"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
)

var _ dkgocrtypes.ResultPackage = &ResultPackage{}

type ResultPackage struct {
	inner  dkg.Result
	config *dkgocrtypes.ReportingPluginConfig
}

func (r *ResultPackage) MarshalBinary() ([]byte, error) {
	return codec.Marshal(r)
}

func (r *ResultPackage) UnmarshalBinary(data []byte) error {
	r, err := codec.Unmarshal(data, r)
	return err
}

func (r *ResultPackage) InstanceID() dkgocrtypes.InstanceID {
	return dkgocrtypes.InstanceID(r.inner.InstanceID())
}

func (r *ResultPackage) MasterPublicKey() dkgocrtypes.P256MasterPublicKey {
	return r.inner.MasterPublicKey().Bytes()
}

func (r *ResultPackage) MasterPublicKeyShares() []dkgocrtypes.P256MasterPublicKeyShare {
	shares := r.inner.MasterPublicKeyShares()
	result := make([]dkgocrtypes.P256MasterPublicKeyShare, len(shares))
	for i, share := range shares {
		result[i] = dkgocrtypes.P256MasterPublicKeyShare(share.Bytes())
	}
	return result
}

func (r *ResultPackage) MasterSecretKeyShare(keyring dkgocrtypes.P256Keyring) (dkgocrtypes.P256MasterSecretKeyShare, error) {
	// Find the recipient's public key index in the configuration.
	publicKey := keyring.PublicKey()
	index := -1
	for i, recipientPublicKey := range r.config.RecipientPublicKeys {
		if bytes.Equal(publicKey, recipientPublicKey) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("keyring public key not found in the recipient public keys from the configuration")
	}

	// Load the public key into its internal representation.
	parsedPublicKey, err := dkgtypes.NewP256PublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key read from keyring: %w", err)
	}

	// Create a recipient identity for the index / keyring's public key combination.
	wrappedKeyring := &wrappedP256keyring{keyring, parsedPublicKey}

	// Retrieve the master secret key share for the recipient (in its internal representation).
	keyShareScalar, err := r.inner.MasterSecretKeyShare(index, wrappedKeyring)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master secret key share: %w", err)
	}

	// Convert the scalar to a byte slice.
	keyShareBytes := keyShareScalar.Bytes()
	if len(keyShareBytes) != dkgocrtypes.P256ScalarLength {
		return nil, fmt.Errorf(
			"invalid master secret key share length: expected %d bytes, got %d bytes",
			dkgocrtypes.P256ScalarLength, len(keyShareBytes),
		)
	}

	return keyShareBytes, nil
}

func (r *ResultPackage) ReportingPluginConfig() dkgocrtypes.ReportingPluginConfig {
	return *r.config
}

// Wrapper implementation of the dkgtypes.PrivateIdentity interface using a provided P-256 keyring.
var _ dkgtypes.P256Keyring = &wrappedP256keyring{}

type wrappedP256keyring struct {
	keyring   dkgocrtypes.P256Keyring
	publicKey dkgtypes.P256PublicKey
}

func newWrappedP256Keyring(keyring dkgocrtypes.P256Keyring) (*wrappedP256keyring, error) {
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
