package plugin

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
)

// This implements OCR 3.1 integration for the SanMarino DKG.
// Each OCR instance runs exactly one DKG instance, which can be either:
//   - Fresh dealing: OCR nodes jointly generate a new master public key.
//   - Resharing: OCR nodes redistribute their existing key shares to a new
//     set of nodes (which may or may not overlap with the original set),
//     while preserving the same master public key.

// The defaultCurve for secret sharing is P256
var defaultCurve = math.P256

var _ ocr3_1types.ReportingPluginFactory[struct{}] = &DKGPluginFactory{}

type DKGPluginFactory struct {
	logger                commontypes.Logger
	configContractAddress common.Address
	keyring               dkgocrtypes.P256Keyring
	db                    dkgocrtypes.ResultPackageDatabase
}

func NewDKGPluginFactory(logger commontypes.Logger, keyring dkgocrtypes.P256Keyring, dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase, configContractAddress common.Address) ocr3_1types.ReportingPluginFactory[struct{}] {
	return &DKGPluginFactory{
		logger,
		configContractAddress,
		keyring,
		dealingResultPackageDatabase,
	}
}

// NewReportingPlugin creates a new instance of the DKG reporting plugin for a given OCR3.1 configuration.
// The error will be logged as ErrorLevel if not nil and the context was not canceled explicitly, so no need to log error within this function. Same for all plugin functions.
func (f *DKGPluginFactory) NewReportingPlugin(context context.Context,
	config ocr3types.ReportingPluginConfig,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocr3_1types.ReportingPlugin[struct{}], ocr3_1types.ReportingPluginInfo, error) {
	// Deterministically derive the instance ID of the current DKG from the config contract address and config digest
	iid := dkgtypes.InstanceID(dkgocrtypes.MakeInstanceID(f.configContractAddress, config.ConfigDigest))

	curve := defaultCurve

	// Transform the keyring from the dkgocrtypes.P256Keyring type to the dkgtypes.P256Keyring type
	keyring, err := p256keyringshim.New(f.keyring)
	if err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to transform DKG keyring: %w", err)
	}

	// Extract ReportingPluginConfig from the offchain config
	pluginConfig := &dkgocrtypes.ReportingPluginConfig{}
	if err := pluginConfig.UnmarshalBinary(config.OffchainConfig); err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to unmarshal DKG plugin config: %w", err)
	}

	// Transform the public keys of dealers from byte slices to dkgtypes.P256PublicKey
	dealers := make([]dkgtypes.P256PublicKey, len(pluginConfig.DealerPublicKeys))
	for i, pk := range pluginConfig.DealerPublicKeys {
		dealers[i], err = dkgtypes.NewP256PublicKey(pk)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive dealer %d public key: %w", i, err)
		}
	}

	// Transform the public keys of recipients from byte slices to dkgtypes.P256PublicKey
	recipients := make([]dkgtypes.P256PublicKey, len(pluginConfig.RecipientPublicKeys))
	for i, pk := range pluginConfig.RecipientPublicKeys {
		recipients[i], err = dkgtypes.NewP256PublicKey(pk)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive recipient %d public key: %w", i, err)
		}
	}

	// Initialize the cache with estimated limits, and potentially a DKG instance and prior result package if this is a resharing and is available in db
	cachedValues, err := newCachedValues(context, f.db, iid, curve, dealers, recipients, config.F, pluginConfig.T, keyring, pluginConfig.PreviousInstanceID, len(config.OffchainConfig))
	if err != nil {
		// Log that dkg instance was not created but do not return error, so that the plugin can still be instantiated and try again later.
		f.logger.Error("Failed to create DKG instance, will try later", commontypes.LogFields{
			"error": err,
		})
	}

	// Increase limits by 20% to allow some margin of error.
	loosenedLimits := cachedValues.limitEstimator.LoosenedLimitsByPercentage(20)

	return &DKGPlugin{
			f.logger,
			pluginConfig,
			f.db,
			iid,
			curve,
			dealers,
			recipients,
			config.F,
			pluginConfig.T,
			keyring,
			cachedValues,
			rand.Reader,
		}, ocr3_1types.ReportingPluginInfo{
			"DKGPlugin",
			loosenedLimits,
		}, nil
}

type DKGPlugin struct {
	logger       commontypes.Logger
	pluginConfig *dkgocrtypes.ReportingPluginConfig
	db           dkgocrtypes.ResultPackageDatabase
	iid          dkgtypes.InstanceID
	curve        math.Curve
	dealers      []dkgtypes.P256PublicKey
	recipients   []dkgtypes.P256PublicKey
	f_D          int
	t_R          int
	keyring      dkgtypes.P256Keyring
	cache        *cachedValues
	rand         io.Reader
}

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Query, error) {
	// Nothing needed to be sent in the query, all should be determined by the pluginState in the kvStore.
	return nil, nil
}

func (p *DKGPlugin) Observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	// Fetch the current plugin state from the kv store, and delegate to the state's observation function.
	state, err := p.readOrInitializePluginState(keyValueReader)
	if err != nil {
		return nil, err
	}
	return state.observation(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
}

func (p *DKGPlugin) ValidateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher,
) error {
	// Fetch the current plugin state from the kv store, and delegate to the state's validateObservation function.
	state, err := p.readOrInitializePluginState(keyValueReader)
	if err != nil {
		return err
	}
	return state.validateObservation(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	// Fetch the current plugin state from the kv store, and delegate to the state's observationQuorum function.
	state, err := p.readOrInitializePluginState(keyValueReader)
	if err != nil {
		return false, err
	}
	return state.observationQuorum(ctx, seqNr, aq, aos, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	// Fetch the current plugin state from the kv store, and delegate to the state's stateTransition function
	state, err := p.readOrInitializePluginState(keyValueReadWriter)
	if err != nil {
		return nil, err
	}
	return state.stateTransition(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
}

func (p *DKGPlugin) Committed(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader) error {
	// No operation needed after commit for dkg; not used in current OCR3.1.
	return nil
}

func (p *DKGPlugin) Reports(ctx context.Context, seqNr uint64, reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor) ([]ocr3types.ReportPlus[struct{}], error) {
	if reportsPlusPrecursor == nil {
		return nil, nil
	}

	// Only one report is created if a DKG instance is successfully finished
	// Send the serialized result package (reportsPlusPrecursor) as the report
	reports := make([]ocr3types.ReportPlus[struct{}], 1)
	reports[0] = ocr3types.ReportPlus[struct{}]{
		ocr3types.ReportWithInfo[struct{}]{
			[]byte(reportsPlusPrecursor),
			struct{}{},
		},
		nil,
	}

	p.logger.Info("🚀🚀🚀🚀🚀🚀🚀 DKGPlugin: created report", nil)
	return reports, nil
}

func (p *DKGPlugin) ShouldAcceptAttestedReport(context.Context, uint64, ocr3types.ReportWithInfo[struct{}]) (bool, error) {
	return true, nil
}

func (p *DKGPlugin) ShouldTransmitAcceptedReport(context.Context, uint64, ocr3types.ReportWithInfo[struct{}]) (bool, error) {
	return true, nil
}

func (p *DKGPlugin) Close() error {
	return nil
}
