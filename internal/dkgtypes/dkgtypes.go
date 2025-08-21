package dkgtypes

import "github.com/smartcontractkit/smdkg/internal/math"

// Unique identifier for a DKG instance.
type InstanceID = string

// Represents a public key of a participant in the DKG protocol in its serialized (compressed) form.
// It is used to initialize a P256PublicKey instance.
type ParticipantPublicKey []byte

// TODO: Consider removing this types. Barely used anymore.
type ParticipantsConfig struct {
	F          int                    // Maximum number of faulty participants.
	T          int                    // Reconstruction threshold for secret sharing, the minimal number of shares needed to reconstruct the master secret.
	PublicKeys []ParticipantPublicKey // Public keys of the participants.
}

// An public identity represents a participant in the DKG protocol.
// It contains the participant's index, its P256 public key used for VESS/MRE, and X-coordinate.

type PublicIdentity interface {
	// Returns the index of the participant in the DKG protocol. It must match the position of the participant's
	// public key in the DKG configuration
	Index() int

	// Returns a (validdated) P256 public key of the participant. The public key is used for VESS/MRE.
	PublicKey() P256PublicKey

	// Returns the X-coordinate associated with a DKG participant. Used for computing secret shares.
	// Typically the XCoord == Scalar(index + 1). Must never be the zero scalar.
	XCoord() math.Scalar
}

// A private identity additionally allows for computing compute shared secrets with the ECDH operation. It is typically
// implemented via a keyring that guards the participant's P256 secret key.
type PrivateIdentity interface {
	PublicIdentity

	// Given a P256 public key, computes the shared secret with the internally managed participant's secret key.
	ECDH(P256PublicKey) ([]byte, error)
}

func NewPublicIdentity(index int, publicKey P256PublicKey, xCoord math.Scalar) PublicIdentity {
	return &publicIdentity{index, publicKey, xCoord}
}

type publicIdentity struct {
	index     int
	publicKey P256PublicKey
	xCoord    math.Scalar
}

func (i *publicIdentity) Index() int {
	return i.index
}

func (i *publicIdentity) PublicKey() P256PublicKey {
	return i.publicKey
}

func (i *publicIdentity) XCoord() math.Scalar {
	return i.xCoord
}
