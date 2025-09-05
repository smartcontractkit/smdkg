package dkgtypes

import (
	"crypto/subtle"
	"fmt"
	"io"

	"filippo.io/nistec"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
)

// Unique identifier for a DKG instance.
type InstanceID string

type P256Keyring interface {
	// Returns the public key associated with the keyring's internal P-256 secret key.
	PublicKey() P256PublicKey

	// Computes the shared secret between the keyring's internal secret key (corresponding to keyring.PublicKey())
	// and public key (publicKey) given as argument to this function. For guidance on how to implement this function,
	// see, e.g., the standard library crypto/internal/fips140/ecdh/ecdh.go, lines 240-271.
	ECDH(publicKey P256PublicKey) (sharedSecret P256ECDHSharedSecret, err error)
}

// For the implementation of MRE, we use the P256 curve at the 128-bit security level.
// Note that the curve choice is independent of the curve used for the DKG protocol.

// 33 bytes is the length of a compressed P-256 point. The length of 33 bytes is enforced, points at infinity are
// not-considered valid public keys. This matches the representation chosen by the filippo.io/nistec package suggested
// for implementing the keyring.
const P256CompressedPointLength = 33

// Type for representing an MRE public key, used for encryption.
// Must be initialized using New256PublicKey(...), or via NewP256Keypair(...).
// If the value is nil, the public key is considered invalid.
type P256PublicKey struct {
	value              *nistec.P256Point
	compressedEncoding []byte // 33 bytes, compressed encoding of the above *nistec.P256Point instance (cached)
}

// Scalar, 32 bytes, big-endian encoded integer representing a secret key.
const P256SecretKeyLength = 32

type P256SecretKey []byte

// P256KeyPair represents a secret key and its corresponding public key on the P256 curve. Use NewP256KeyPair(...), to
// generate a new key pair. For long lived secrets, consumers should implement the the PrivateIdentity interface via
// the use of a keyring.
type P256KeyPair struct {
	SecretKey P256SecretKey // 32 bytes, big-endian encoded integer representing the secret key
	PublicKey P256PublicKey // structure wrapping the internal *nistec.P256Point instance and its compressed encoding
}

// Represents the result of the ECDH operation between a participant's secret key (wrapped in a keyring) and another
// participant's public key. The 32 bytes value represents the x-coordinate of the ECDH result.
const P256ECDHSharedSecretLength = 32

type P256ECDHSharedSecret []byte

// The number of points on the P256 curve. See: NIST 800-186, Section3.2.1.3
// Equivalent to crypto/elliptic.P256().Params().N; however, we want to avoid using the elliptic package here, as most
// of its functions are deprecated.
var p256Order = math.NewModulus("115792089210356248762697446949407573529996955224135760342422259061068512044369")

// Generates a new random P256 key pair. Most applications should use [crypto/rand.Reader] as rand. If the randomness
// source is deterministic, the generated key pair will be derived deterministically as well.
func NewP256KeyPair(rand io.Reader) (P256KeyPair, error) {
	s, err := math.NewScalar(p256Order).SetRandom(rand)
	if err != nil {
		return P256KeyPair{}, fmt.Errorf("failed to generate random secret key: %w", err)
	}

	sk := s.Bytes()
	pk, err := nistec.NewP256Point().ScalarBaseMult(sk)
	if err != nil {
		return P256KeyPair{}, fmt.Errorf("failed to compute public key from secret key: %w", err)
	}

	return P256KeyPair{sk, P256PublicKey{pk, pk.BytesCompressed()}}, nil
}

// Initializes a new PublicKey instance from a byte slice (representing a compressed point on the P256 curve).
// The byte slice must be exactly 33 bytes long, which is the expected size for a compressed P256 public key.
// If the byte slice does not represent a valid point on the curve, an error is returned.
func NewP256PublicKey(value []byte) (P256PublicKey, error) {
	if len(value) != P256CompressedPointLength {
		return P256PublicKey{}, fmt.Errorf(
			"invalid public key length: %d, expected %d bytes", len(value), P256CompressedPointLength,
		)
	}
	p, err := nistec.NewP256Point().SetBytes(value)
	if err != nil {
		return P256PublicKey{}, fmt.Errorf("invalid public key: %w", err)
	}

	pkBytes := p.BytesCompressed()
	if subtle.ConstantTimeCompare(value, pkBytes) != 1 {
		// Defensive check, should not happen, but we want to guarantee a canonical encoding of the public keys for the
		// use in the hash functions.
		return P256PublicKey{}, fmt.Errorf("invalid public key: non-canonical encoding")
	}

	return P256PublicKey{p, pkBytes}, nil
}

// Compute the shared ECDH secret between the local secret key and a peer's public key. The implementation is based on
// the internal implementation from the stdlib, see crypto/internal/fips140/ecdh/ecdh.go, lines 240-271.
// Only valid public keys, as returned by calls to NewPublicKey(...) or Keygen(...) must be used as arguments here.
func (sk P256SecretKey) ECDH(pk P256PublicKey) (P256ECDHSharedSecret, error) {
	p, err := nistec.NewP256Point().ScalarMult(pk.value, sk)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH: %w", err)
	}
	s, err := p.BytesX()
	if err != nil {
		return nil, fmt.Errorf("failed to get x-coordinate of ECDH result: %w", err)
	}
	return s, nil
}

// Returns the internal byte representation of the public key (compressed point on the P256 curve, 33 bytes).
// The first byte encode the parity of the y-coordinate, the remaining 32 bytes encode the x-coordinate (big-endian).
func (pk P256PublicKey) Bytes() []byte {
	if pk.value == nil {
		return nil
	}

	var out [P256CompressedPointLength]byte
	copy(out[:], pk.compressedEncoding)
	return out[:]
}

// Check if the given PublicKey instance is a valid point on the curve.
// The point at infinity is considered invalid.
func (pk P256PublicKey) IsValid() bool {
	return pk.value != nil
}

// Checks if two PublicKey instances represent the same point on the curve.
func (pk P256PublicKey) Equal(other P256PublicKey) bool {
	return (pk.value == nil && other.value == nil) || subtle.ConstantTimeCompare(pk.compressedEncoding, other.compressedEncoding) == 1
}

func (pk P256PublicKey) MarshalTo(target codec.Target) {
	target.WriteBytes(pk.compressedEncoding)
}

func (P256PublicKey) UnmarshalFrom(source codec.Source) P256PublicKey {
	b := source.ReadBytes(P256CompressedPointLength)
	pk, err := NewP256PublicKey(b)
	if err != nil {
		panic(err)
	}
	return pk
}
