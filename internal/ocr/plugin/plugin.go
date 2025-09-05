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
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
)

// This is implementation for OCR3.1 integration with SanMarino DKG.
// Only runs one DKG instance per OCR instance.
// ...

var _ ocr3_1types.ReportingPluginFactory[struct{}] = &DKGPluginFactory{}

type DKGPluginFactory struct {
	logger                       commontypes.Logger
	configContractAddress        common.Address
	keyring                      dkgocrtypes.P256Keyring
	dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase
}

func NewDKGPluginFactory(logger commontypes.Logger, keyring dkgocrtypes.P256Keyring, dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase, configContractAddress common.Address) ocr3_1types.ReportingPluginFactory[struct{}] {
	return &DKGPluginFactory{
		logger,
		configContractAddress,
		keyring,
		dealingResultPackageDatabase,
	}
}

func (f *DKGPluginFactory) NewReportingPlugin(context context.Context,
	config ocr3types.ReportingPluginConfig,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocr3_1types.ReportingPlugin[struct{}], ocr3_1types.ReportingPluginInfo, error) {
	iid := dkgocrtypes.MakeInstanceID(f.configContractAddress, config.ConfigDigest)

	keyring, err := p256keyringshim.New(f.keyring)
	if err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to create DKG keyring: %w", err)
	}

	pluginConfig := &dkgocrtypes.ReportingPluginConfig{}
	if err := pluginConfig.UnmarshalBinary(config.OffchainConfig); err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to unmarshal DKG plugin config: %w", err)
	}

	dealersPublicKeys := make([]dkgtypes.P256PublicKey, len(pluginConfig.DealerPublicKeys))
	for i, k := range pluginConfig.DealerPublicKeys {
		dealersPublicKeys[i], err = dkgtypes.NewP256PublicKey(k)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive dealer public key: %w", err)
		}
	}

	recipientsPublicKeys := make([]dkgtypes.P256PublicKey, len(pluginConfig.RecipientPublicKeys))
	for i, k := range pluginConfig.RecipientPublicKeys {
		recipientsPublicKeys[i], err = dkgtypes.NewP256PublicKey(k)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive recipient public key: %w", err)
		}
	}

	dkgConfig := &dkgInstanceConfig{
		iid,
		dealersPublicKeys,
		recipientsPublicKeys,
		config.F,
		pluginConfig.T,
		pluginConfig.PreviousInstanceID,
		keyring,
		f.dealingResultPackageDatabase,
	}

	cachedValues := &cachedValues{
		nil,
		nil,
		make([]*initialDealingCache, config.N),
		make([]*decryptionKeySharesCache, config.N),
		nil,
	}

	dkgInstance, err := dkgConfig.newDKG(context)
	if err == nil { // Should still instantiate the plugin even if the dkg instance doesn't successfully initialize
		cachedValues.dkg = dkgInstance
	}

	return &DKGPlugin{
			f.logger,
			pluginConfig,
			dkgConfig,
			cachedValues,
			rand.Reader, // [TODO] Need to confirm the use of rng here
		}, ocr3_1types.ReportingPluginInfo{
			"DKGPlugin",
			ocr3_1types.ReportingPluginLimits{ // [TODO] These limits need to be revisited
				0,
				10 * 1024,
				1,
				80 * 1024,
				1,
				150 * 1024,
				10 * 1024,
			},
		}, nil
}

type DKGPlugin struct {
	logger       commontypes.Logger
	pluginConfig *dkgocrtypes.ReportingPluginConfig
	dkgConfig    *dkgInstanceConfig
	cache        *cachedValues
	rand         io.Reader
}

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Query, error) {
	// Nothing needed to be sent in the query, all should be determined by the pluginState in the kvStore
	return nil, nil
}

func (p *DKGPlugin) Observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return nil, err
	}
	return state.observation(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
}

func (p *DKGPlugin) ValidateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher,
) error {
	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return err
	}
	return state.validateObservation(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return false, err
	}
	return state.observationQuorum(ctx, seqNr, aq, aos, keyValueReader, blobFetcher)
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	state, err := p.readPluginState(keyValueReadWriter)
	if err != nil {
		return nil, err
	}
	return state.stateTransition(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
}

func (p *DKGPlugin) Committed(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader) error {
	// Not used in current OCR3.1; no operation needed after commit either
	return nil
}

func (p *DKGPlugin) Reports(ctx context.Context, seqNr uint64, reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor) ([]ocr3types.ReportPlus[struct{}], error) {
	if reportsPlusPrecursor == nil {
		return nil, nil
	}

	// Only one report is created for the DKG instance
	reports := make([]ocr3types.ReportPlus[struct{}], 1)
	reports[0] = ocr3types.ReportPlus[struct{}]{
		ocr3types.ReportWithInfo[struct{}]{
			[]byte(reportsPlusPrecursor),
			struct{}{},
		},
		nil,
	}
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

var curve = math.P256

type dkgInstanceConfig struct {
	instanceID         dkgocrtypes.InstanceID
	dealers            []dkgtypes.P256PublicKey
	recipients         []dkgtypes.P256PublicKey
	f_D                int
	t_R                int
	previousInstanceID *dkgocrtypes.InstanceID
	keyring            dkgtypes.P256Keyring
	db                 dkgocrtypes.ResultPackageDatabase
}

func (c *dkgInstanceConfig) newDKG(ctx context.Context) (dkg.DKG, error) {
	var newDKG dkg.DKG
	if c.previousInstanceID == nil {
		var err error
		newDKG, err = dkg.NewInitialDKG(dkgtypes.InstanceID(c.instanceID), curve, c.dealers, c.recipients, c.f_D, c.t_R, c.keyring)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKG instance for fresh dealing: %w", err)
		}
	} else {
		priorResult, err := c.db.ReadResultPackage(ctx, *c.previousInstanceID)
		if err != nil {
			return nil, fmt.Errorf("failed to read prior result package: %w", err)
		}

		if priorResult == nil {
			return nil, fmt.Errorf("no prior result package found for instance ID %s", *c.previousInstanceID)
		}

		resultPackage := &ResultPackage{}
		if err := resultPackage.UnmarshalBinary(priorResult.ReportWithResultPackage); err != nil {
			return nil, fmt.Errorf("failed to unmarshal prior result package: %w", err)
		}

		newDKG, err = dkg.NewResharingDKG(dkgtypes.InstanceID(c.instanceID), c.dealers, c.recipients, c.f_D, c.t_R, c.keyring, resultPackage.Inner)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKG instance for resharing: %w", err)
		}
	}

	return newDKG, nil
}
