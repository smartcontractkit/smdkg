package plugintypes

import (
	"bytes"
	"context"
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
)

type BannedDealers []bool
type InitialDealings []dkg.VerifiedInitialDealing
type DecryptionKeyShares []dkg.VerifiedDecryptionKeySharesForInnerDealings
type InnerDealings []dkg.VerifiedInnerDealing

type PluginPhase interface {
	codec.Marshaler

	Observation(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueStateReader,
		blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
	) (types.Observation, error)

	ValidateObservation(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
	) error

	ObservationQuorum(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
	) (bool, error)

	StateTransition(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReadWriter ocr3_1types.KeyValueStateReadWriter, blobFetcher ocr3_1types.BlobFetcher,
	) (ocr3_1types.ReportsPlusPrecursor, error)
}

// ResultPackage implements the dkgocrtypes.ResultPackage interface.

var _ dkgocrtypes.ResultPackage = &ResultPackage{}

type ResultPackage struct {
	Inner  dkg.Result
	Config *dkgocrtypes.ReportingPluginConfig
}

func (r *ResultPackage) InstanceID() dkgocrtypes.InstanceID {
	return dkgocrtypes.InstanceID(r.Inner.InstanceID())
}

func (r *ResultPackage) MasterPublicKey() dkgocrtypes.P256MasterPublicKey {
	return r.Inner.MasterPublicKey().Bytes()
}

func (r *ResultPackage) MasterPublicKeyShares() []dkgocrtypes.P256MasterPublicKeyShare {
	shares := r.Inner.MasterPublicKeyShares()
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
	for i, recipientPublicKey := range r.Config.RecipientPublicKeys {
		if bytes.Equal(publicKey, recipientPublicKey) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("keyring public key not found in the recipient public keys from the configuration")
	}

	// Wrap the keyring into the internally supported format.
	keyringInternal, err := p256keyringshim.New(keyring)
	if err != nil {
		return nil, err
	}

	// Retrieve the master secret key share for the recipient (in its internal representation).
	keyShareScalar, err := r.Inner.MasterSecretKeyShare(index, keyringInternal)
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
	return *r.Config
}
