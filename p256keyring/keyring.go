package p256keyring

import (
	"bytes"
	"encoding"
	"fmt"
	"io"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
)

const SecretKeyLength = 32 // scalar (mod P256 group order), 32 bytes, big-endian encoded integer
const PublicKeyLength = 33 // compressed P256 point

// 32 bytes is the length of the X-coordinate of a P-256 point, as returned by the ECDH function.
const ECDHSharedSecretLength = 32

var _ dkgocrtypes.P256Keyring = &P256Keyring{}
var _ encoding.BinaryMarshaler = &P256Keyring{}
var _ encoding.BinaryUnmarshaler = &P256Keyring{}
var _ fmt.Stringer = &P256Keyring{}
var _ fmt.GoStringer = &P256Keyring{}

// Implements dkgocrtypes.P256Keyring with support for marshaling/unmarshaling.
type P256Keyring struct {
	sk dkgtypes.P256SecretKey
	pk dkgtypes.P256PublicKey
}

// Implement Stringer and GoStringer interfaces to ensure that secret key is never accidentally logged.
func (kr *P256Keyring) String() string {
	return kr.GoString()
}

// Implement Stringer and GoStringer interfaces to ensure that secret key is never accidentally logged.
func (kr *P256Keyring) GoString() string {
	return fmt.Sprintf("P256Keyring{pk: \"%x\"}", kr.pk.Bytes())
}

// Initialize a new P256Keyring with a randomly generated keypair. Typically applications should pass
// [crypto/rand.Reader] as argument.
func New(rand io.Reader) (*P256Keyring, error) {
	kp, err := dkgtypes.NewP256KeyPair(rand)
	if err != nil {
		return nil, err
	}
	return &P256Keyring{kp.SecretKey, kp.PublicKey}, nil
}

func (kr *P256Keyring) PublicKey() dkgocrtypes.P256ParticipantPublicKey {
	return kr.pk.Bytes()
}

func (kr *P256Keyring) ECDH(publicKey dkgocrtypes.P256ParticipantPublicKey) (dkgocrtypes.P256ECDHSharedSecret, error) {
	pk, err := dkgtypes.NewP256PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := kr.sk.ECDH(pk)
	if err != nil {
		return nil, err
	}
	return dkgocrtypes.P256ECDHSharedSecret(sharedSecret), nil
}

// MarshalBinary implements encoding.BinaryMarshaler by exporting the P256 key pair.
func (kr *P256Keyring) MarshalBinary() (data []byte, err error) {
	result := make([]byte, 0, SecretKeyLength+PublicKeyLength)
	result = append(result, kr.sk...)
	result = append(result, kr.pk.Bytes()...)
	return result, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler by importing the P256 key pair.
func (kr *P256Keyring) UnmarshalBinary(data []byte) error {
	if len(data) != SecretKeyLength+PublicKeyLength {
		return fmt.Errorf(
			"invalid data length: got %d, want %d", len(data), SecretKeyLength+PublicKeyLength,
		)
	}

	skScalar, err := math.P256.Scalar().SetBytes(data[:SecretKeyLength])
	if err != nil {
		return fmt.Errorf("failed to create secret key from bytes: %w", err)
	}
	sk := dkgtypes.P256SecretKey(skScalar.Bytes())

	pkPoint := math.P256.Point().ScalarBaseMult(skScalar)
	pk, err := dkgtypes.NewP256PublicKey(pkPoint.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create public key from secret key: %w", err)
	}

	if !bytes.Equal(data[SecretKeyLength:], pk.Bytes()) {
		return fmt.Errorf("public key mismatch, expected %x, got %x", data[SecretKeyLength:], pk.Bytes())
	}

	kr.sk = sk
	kr.pk = pk
	return nil
}
