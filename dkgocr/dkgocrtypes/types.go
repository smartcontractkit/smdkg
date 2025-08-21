package dkgocrtypes

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

// The InstanceID is a string that uniquely identifies a DKG instance.
// Use MakeInstanceID to create an InstanceID from a config contract address and a config digest.
type InstanceID string

func MakeInstanceID(configContract common.Address, configDigest types.ConfigDigest) InstanceID {
	// A single OCR instance produces at most one DealingPackage, so the configDigest suffices as an identifier.
	return InstanceID(fmt.Sprintf("sanmarinodkg/v1/%s/%s", configContract, configDigest))
}

// 33 bytes is the length of a compressed P-256 point (other than infinity), serialized according to SEC 1, Version 2.0,
// Section 2.3.3. This matches the representation chosen by the filippo.io/nistec package suggested for implementing the
// keyring. The length of 33 bytes is enforced, points at infinity are not considered valid public keys.
const (
	P256CompressedPointLength      = 33
	P256ParticipantPublicKeyLength = P256CompressedPointLength
	P256MasterPublicKeyLength      = P256CompressedPointLength
	P256MasterPublicKeyShareLength = P256CompressedPointLength
)

// 32 bytes is the length of a P-256 scalar, a big-endian encoded integer below the order of the P-256 curve.
const P256ScalarLength = 32
const P256MasterSecretKeyShareLength = P256ScalarLength

// 32 bytes is the length of the X-coordinate of a P-256 point, as returned by the ECDH function.
const P256ECDHSharedSecretLength = 32

type P256ParticipantPublicKey []byte
type P256MasterPublicKey []byte
type P256MasterPublicKeyShare []byte
type P256MasterSecretKeyShare []byte
type P256ECDHSharedSecret []byte

// DKG Reporting Plugin Config disseminated through the chain
type ReportingPluginConfig struct {
	// Public keys of the dealers. The i-th OCR oracle's dealer public key is DealerPublicKeys[i].
	DealerPublicKeys []P256ParticipantPublicKey

	// Public keys of the recipients. This list must have at least T elements.
	RecipientPublicKeys []P256ParticipantPublicKey

	// T recipients are needed to reconstruct the master secret. T must be at least 1.
	T int

	// If this is nil, the DKG will generate a new master secret.
	// Otherwise, the DKG will reshare the master secret from the previous DKG run with the given instanceID.
	PreviousInstanceID *InstanceID
}

type ResultPackage interface {
	encoding.BinaryMarshaler   // the implementation of this interface must yield a deterministic output (across different runs and machines)
	encoding.BinaryUnmarshaler // the implementation of this interface must correctly handle corrupted inputs

	ReportingPluginConfig() ReportingPluginConfig                       // the configuration used to run this DKG instance
	InstanceID() InstanceID                                             // unique identifier for the DKG instance
	MasterPublicKey() P256MasterPublicKey                               // resulting master public key of the DKG instance, the corresponding master secret key is shared among the recipients
	MasterPublicKeyShares() []P256MasterPublicKeyShare                  // public key shares of the master public key for all recipients
	MasterSecretKeyShare(P256Keyring) (P256MasterSecretKeyShare, error) // function to retrieve the master secret key share of a recipient; requires a keyring for decryption
}

// A result package with additional metadata to be stored in a database.
type ResultPackageDatabaseValue struct {
	ConfigDigest            types.ConfigDigest
	SeqNr                   uint64
	ReportWithResultPackage []byte
	Signatures              []types.AttributedOnchainSignature
}

// ResultPackageDatabase is a key-value database that maps InstanceIDs to ResultDatabaseValue.
// ResultPackageDatabase is ever-growing, i.e. there is no deletion from the database.
//
// All its functions should be thread-safe.
type ResultPackageDatabase interface {
	// ReadResultPackage reads the DKG result from the database. If no result with the given instanceID is found, it
	// returns (nil, nil).
	ReadResultPackage(ctx context.Context, iid InstanceID) (*ResultPackageDatabaseValue, error)

	// WriteReadDealingPackage writes a key-value pair consisting of an instanceID and a ResultPackageDatabaseValue.
	WriteResultPackage(ctx context.Context,
		instanceID InstanceID,
		value ResultPackageDatabaseValue,
	) error
}

// The P256Keyring interfaces guard a participant's a P-256 secret key and provides methods to access the public key and
// compute shared secrets.
type P256Keyring interface {
	// Returns the public key associated with the keyring's internal P-256 secret key.
	PublicKey() P256ParticipantPublicKey

	// Computes the shared secret between the keyring's internal secret key (corresponding to keyring.PublicKey())
	// and public key (publicKey) given as argument to this function. For guidance on how to implement this function,
	// see, e.g., the standard library crypto/internal/fips140/ecdh/ecdh.go, lines 240-271.
	ECDH(publicKey P256ParticipantPublicKey) (sharedSecret P256ECDHSharedSecret, err error)
}

// This struct exists to make it easier to add a V2 in the future.
type versionedReportingPluginConfig struct {
	V1 *ReportingPluginConfig
}

// MarshalBinary implements encoding.BinaryMarshaler using JSON as the underlying representation.
func (c ReportingPluginConfig) MarshalBinary() ([]byte, error) {
	return json.Marshal(versionedReportingPluginConfig{V1: &c})
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler using JSON as the underlying representation.
func (c *ReportingPluginConfig) UnmarshalBinary(data []byte) error {
	var versionedConfig versionedReportingPluginConfig
	if err := json.Unmarshal(data, &versionedConfig); err != nil {
		return err
	}
	if versionedConfig.V1 == nil {
		return fmt.Errorf("invalid versioned reporting plugin config: V1 is nil")
	}
	*c = *versionedConfig.V1
	return nil
}
