package plugin

import (
	"bytes"
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
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/pluginstate"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
)

// This implements OCR 3.1 integration for the SanMarino DKG.
// Each OCR instance runs exactly one DKG instance, which can be either:
//   - Fresh dealing: OCR nodes jointly generate a new master public key.
//   - Resharing: OCR nodes redistribute their existing key shares to a new
//     set of nodes (which may or may not overlap with the original set),
//     while preserving the same master public key.

// The code in this file forwards the call to the appropriate implementation based on the current phase
// of the DKG protocol. See phases.go for the actual implementations of each phase.

// The defaultCurve for secret sharing is P256
var defaultCurve = math.P256

// Transmit DKG result to the db every 5 OCR rounds (seqNr)
const transmitFrequency = 5

var _ ocr3_1types.ReportingPluginFactory[struct{}] = &DKGPluginFactory{}

type DKGPluginFactory struct {
	logger                commontypes.Logger
	configContractAddress common.Address
	keyring               dkgocrtypes.P256Keyring
	db                    dkgocrtypes.ResultPackageDatabase
}

func NewDKGPluginFactory(
	logger commontypes.Logger, keyring dkgocrtypes.P256Keyring,
	dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase, configContractAddress common.Address,
) ocr3_1types.ReportingPluginFactory[struct{}] {
	return &DKGPluginFactory{
		logger,
		configContractAddress,
		keyring,
		dealingResultPackageDatabase,
	}
}

// NewReportingPlugin creates a new instance of the DKG reporting plugin for a given OCR3.1 configuration.
// The error will be logged as ErrorLevel if not nil and the context was not canceled explicitly, so no need to log
// error within this function. Same for all plugin functions.
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

	plugin := &DKGPlugin{
		f.logger,
		pluginConfig,
		f.db,
		config.OracleID,
		iid,
		curve,
		dealers,
		recipients,
		config.F,
		pluginConfig.T,
		keyring,
		rand.Reader,
		nil, // the plugin state indirectly references the plugin instance, so we can only set it below
	}

	// Initialize the plugin state, starting in the dealing phase. This holds all mutable state of the plugin.
	plugin.state = pluginstate.New(
		&phaseDealing{plugin, 0},                      // start in dealing phase, attempt 0
		make(plugintypes.BannedDealers, len(dealers)), // initially no banned dealers,
		plugin.initializeCryptoProvider,
		pluginPhaseUnmarshaler{plugin},
	)

	// Try to initialize the crypto provider (DKG instance), this may fail if we need to load a previous result
	// package that is not yet available. In this case it will be retried later when needed.
	isResharing := pluginConfig.PreviousInstanceID != nil
	cryptoProvider, err := plugin.state.MemoizedCryptoProvider(context)
	if err != nil && !isResharing {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf(
			"failed to initialize crypto provider for non-resharing DKG instance: %w", err,
		)
	}

	// The parameter t_D may be used to obtain tighter bandwidth estimates. Let's try to get it if possible.
	var t_D *int = nil
	if isResharing && cryptoProvider != nil {
		// Subsequent call returns priorResult.t_R for a resharing, which is t_D for the new instance.
		t := cryptoProvider.DealingsThreshold()
		t_D = &t
	}

	// Estimate bandwidth limits base on the DKG parameters. Increase limits by 20% to allow some margin of error.
	limitsEstimator := NewLimitsEstimator(
		iid, curve, len(dealers), config.F, len(recipients), pluginConfig.T, isResharing, t_D,
		len(config.OffchainConfig),
	)
	loosenedLimits := limitsEstimator.LoosenedLimitsByPercentage(20)

	pluginInfo := ocr3_1types.ReportingPluginInfo{"DKGPlugin", loosenedLimits}

	return plugin, pluginInfo, nil
}

type DKGPlugin struct {
	logger       commontypes.Logger
	pluginConfig *dkgocrtypes.ReportingPluginConfig
	db           dkgocrtypes.ResultPackageDatabase
	oracleID     commontypes.OracleID
	iid          dkgtypes.InstanceID
	curve        math.Curve
	dealers      []dkgtypes.P256PublicKey
	recipients   []dkgtypes.P256PublicKey
	f_D          int
	t_R          int
	keyring      dkgtypes.P256Keyring
	rand         io.Reader
	state        *pluginstate.PluginState
}

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(
	ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Query, error) {
	// Nothing needed to be sent in the query, all should be determined by the pluginState in the kvStore.
	return nil, nil
}

func (p *DKGPlugin) Observation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	phase, err := p.state.ReadPhase(keyValueReader)
	if err != nil {
		return nil, err
	}
	return phase.Observation(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
}

func (p *DKGPlugin) ValidateObservation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation,
	keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	phase, err := p.state.ReadPhase(keyValueReader)
	if err != nil {
		return err
	}
	return phase.ValidateObservation(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	phase, err := p.state.ReadPhase(keyValueReader)
	if err != nil {
		return false, err
	}
	return phase.ObservationQuorum(ctx, seqNr, aq, aos, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	phase, err := p.state.ReadPhase(keyValueReadWriter)
	if err != nil {
		return nil, err
	}
	return phase.StateTransition(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
}

func (p *DKGPlugin) Committed(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader) error {
	// No operation needed after commit for DKG; not used in current OCR3.1.
	return nil
}

func (p *DKGPlugin) Reports(
	ctx context.Context, seqNr uint64, reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor,
) ([]ocr3types.ReportPlus[struct{}], error) {
	if reportsPlusPrecursor == nil {
		return nil, nil
	}

	// Only one report is created if a DKG instance is successfully finished, send the serialized result package
	// (= reportsPlusPrecursor) as the report.
	reports := make([]ocr3types.ReportPlus[struct{}], 1)
	reports[0] = ocr3types.ReportPlus[struct{}]{
		ocr3types.ReportWithInfo[struct{}]{
			[]byte(reportsPlusPrecursor),
			struct{}{},
		},
		nil,
	}

	p.logger.Info("🚀🚀🚀🚀🚀🚀🚀 DKGPlugin: created report", commontypes.LogFields{
		"seqNr": seqNr,
	})

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

func (p *DKGPlugin) initializeCryptoProvider(ctx context.Context) (dkg.DKG, error) {
	previousInstanceID := p.pluginConfig.PreviousInstanceID

	// Fresh dealing case, no nead to load any previous result package.
	if previousInstanceID == nil {
		return dkg.NewInitialDKG(
			p.iid,
			p.curve,
			p.dealers,
			p.recipients,
			p.f_D,
			p.t_R,
			p.keyring,
		)
	}

	// Read the previous result package from the database.
	previousResultPackage, err := p.loadPreviousResultPackage(ctx)
	if err != nil {
		return nil, err
	}

	// Check that the curve in the prior result matches the curve in config.
	if p.curve.Name() != previousResultPackage.Inner.Curve().Name() {
		return nil, fmt.Errorf(
			"curve in config (%s) does not match curve in previous  result package (%s)",
			p.curve.Name(), previousResultPackage.Inner.Curve().Name(),
		)
	}

	// Check that t_R in the prior result is greater than f_D in the new config.
	// Otherwise, the DKG security property is violated.
	if previousResultPackage.Config.T <= p.f_D {
		return nil, fmt.Errorf(
			"t_R (%d) in prior result package is not greater than f_D (%d) in new config",
			previousResultPackage.Config.T, p.f_D,
		)
	}

	// Check that the dealers' public keys in config match the recipients' public keys in the prior result.
	if len(p.dealers) != len(previousResultPackage.Config.RecipientPublicKeys) {
		return nil, fmt.Errorf(
			"mismatch in number of dealers and prior recipients: %d vs %d",
			len(p.dealers), len(previousResultPackage.Config.RecipientPublicKeys),
		)
	}
	for i, dealer := range p.dealers {
		if !bytes.Equal(dealer.Bytes(), previousResultPackage.Config.RecipientPublicKeys[i]) {
			return nil, fmt.Errorf("dealer public key at index %d does not match prior recipient public key", i)
		}
	}

	// Create a resharing DKG instance.
	return dkg.NewResharingDKG(
		p.iid,
		p.dealers,
		p.recipients,
		p.f_D,
		p.t_R,
		p.keyring, previousResultPackage.Inner,
	)
}

func (p *DKGPlugin) loadPreviousResultPackage(ctx context.Context) (*plugintypes.ResultPackage, error) {
	previousInstanceID := *p.pluginConfig.PreviousInstanceID
	dbReadResult, err := p.db.ReadResultPackage(ctx, previousInstanceID)
	if err != nil {
		return nil, err
	}
	if dbReadResult == nil {
		return nil, fmt.Errorf("loading previous result package from database failed (not available yet?)")
	}

	previousResultPackage := &plugintypes.ResultPackage{}
	if err := previousResultPackage.UnmarshalBinary(dbReadResult.ReportWithResultPackage); err != nil {
		return nil, fmt.Errorf(
			"failed to unmarshal prior result package with instance ID %s: %w", previousInstanceID, err,
		)
	}
	return previousResultPackage, nil
}
