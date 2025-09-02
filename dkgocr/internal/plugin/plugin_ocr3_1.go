// [TODO]
// Use blob dissemination for broadcasting dealings to avoid overwhelming the bandwidth of the leader
// Currently not optimized when the network is not synchronized, may allowing gradually increasing the set of dealings and decryption shares
// Transmit dkg results periodically (not to a blockchain but other offchain nodes)

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
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkg"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/hash"
	"github.com/smartcontractkit/smdkg/internal/math"
)

var _ = &DKGPluginFactory{}

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

	keyring, err := newWrappedP256Keyring(f.keyring)
	if err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to create DKG keyring: %w", err)
	}

	dkgConfig := &dkgocrtypes.ReportingPluginConfig{}
	if err := dkgConfig.UnmarshalBinary(config.OffchainConfig); err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to unmarshal DKG plugin config: %w", err)
	}

	dealersPublicKeys := make([]dkgtypes.P256PublicKey, len(dkgConfig.DealerPublicKeys))
	for i, k := range dkgConfig.DealerPublicKeys {
		dealersPublicKeys[i], err = dkgtypes.NewP256PublicKey(k)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive dealer public key: %w", err)
		}
	}

	recipientsPublicKeys := make([]dkgtypes.P256PublicKey, len(dkgConfig.RecipientPublicKeys))
	for i, k := range dkgConfig.RecipientPublicKeys {
		recipientsPublicKeys[i], err = dkgtypes.NewP256PublicKey(k)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to derive recipient public key: %w", err)
		}
	}

	verifiedInitialDealings := make([]map[hashOfUnverifiedObject]dkg.VerifiedInitialDealing, config.N)
	for i := 0; i < config.N; i++ {
		verifiedInitialDealings[i] = make(map[hashOfUnverifiedObject]dkg.VerifiedInitialDealing)
	}
	verifiedDecryptionKeyShares := make([]map[hashOfUnverifiedObject]dkg.VerifiedDecryptionKeySharesForInnerDealing, config.N)
	for i := 0; i < config.N; i++ {
		verifiedDecryptionKeyShares[i] = make(map[hashOfUnverifiedObject]dkg.VerifiedDecryptionKeySharesForInnerDealing)
	}
	cachedValues := &cachedValues{
		nil,
		verifiedInitialDealings,
		verifiedDecryptionKeyShares,
	}

	return &DKGPlugin{
			f.logger,
			dkgConfig,
			iid,
			dealersPublicKeys,
			recipientsPublicKeys,
			config.F,
			dkgConfig.T,
			keyring,
			f.dealingResultPackageDatabase,
			cachedValues,
			rand.Reader, // [TODO] Need to confirm the use of rng here
		}, ocr3_1types.ReportingPluginInfo{
			"DKGPlugin",
			ocr3_1types.ReportingPluginLimits{ // [TODO] These limits need to be revisited
				1024,
				30 * 1024,
				1024,
				70 * 1024,
				128,
				90 * 1024,
				1024,
			},
		}, nil
}

type DKGPlugin struct {
	logger                       commontypes.Logger
	config                       *dkgocrtypes.ReportingPluginConfig
	iid                          dkgocrtypes.InstanceID
	dealersPublicKeys            []dkgtypes.P256PublicKey
	recipientsPublicKeys         []dkgtypes.P256PublicKey
	f_D                          int
	t_R                          int
	keyring                      dkgtypes.P256Keyring
	dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase
	cachedValues                 *cachedValues
	rand                         io.Reader
}

type hashOfUnverifiedObject = [32]byte

// Contains all the in-memory cached state for a DKGPlugin, shouldn't be accessed directly
type cachedValues struct {
	dkg                         dkg.DKG
	verifiedInitialDealings     []map[hashOfUnverifiedObject]dkg.VerifiedInitialDealing // [TODO] Any spamming protection? E.g., renew after the counter increases or when the size his a threshold?
	verifiedDecryptionKeyShares []map[hashOfUnverifiedObject]dkg.VerifiedDecryptionKeySharesForInnerDealing
}

type stateMachineState int

const (
	Started                 stateMachineState = iota // the initial state of a dkg round
	ReceivedInitialDealings                          // received enough valid initial dealings and written to kv store
	GatheredInnerDealings                            // gathered enough valid inner dealings and written to kv store
)

type pluginState struct {
	stateMachineState stateMachineState
	countRestart      int
}

type bannedDealers []bool
type initialDealings []dkg.VerifiedInitialDealing
type decryptionKeyShares []dkg.VerifiedDecryptionKeySharesForInnerDealing
type innerDealings []dkg.VerifiedInnerDealing

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Query, error) {
	return make([]byte, 0), nil // Nothing needed in the query
}

func (p *DKGPlugin) observationStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return nil, err
	}

	dealing, err := dkgInstance.Deal(p.rand)
	if err != nil {
		return nil, err
	}

	ob, err := codec.Marshal(dealing.AsUnverifiedDealing())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unverified initial dealing: %w", err)
	}
	return ob, nil
}

func (p *DKGPlugin) observationReceivedInitialDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher, state *pluginState) (types.Observation, error) {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return nil, err
	}

	dealings, err := p.readReceivedInitialDealings(keyValueReader, state.countRestart)
	if err != nil {
		return nil, err
	}

	shares, err := dkgInstance.DecryptDecryptionKeyShares(dealings)
	if err != nil {
		return nil, err
	}

	ob, err := codec.Marshal(shares.AsUnverifiedShares())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unverified decryption key shares: %w", err)
	}
	return ob, nil
}

func (p *DKGPlugin) observationGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher, state *pluginState) (types.Observation, error) {
	// [TODO] Periodically transmit the DKG result
	return make([]byte, 0), nil
}

func (p *DKGPlugin) Observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return nil, err
	}

	switch state.stateMachineState {
	case Started:
		return p.observationStarted(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
	case ReceivedInitialDealings:
		return p.observationReceivedInitialDealings(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher, state)
	case GatheredInnerDealings:
		return p.observationGatheredInnerDealings(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher, state)
	default:
		return nil, fmt.Errorf("unknown state machine state: %v", state.stateMachineState)
	}
}

func (p *DKGPlugin) validateObservationStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher, state *pluginState) error {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return err
	}

	if state.countRestart > 0 {
		bannedDealers, err := p.readBannedDealers(keyValueReader)
		if err != nil {
			return err
		}

		// Should reject observations from banned dealers
		if bannedDealers[ao.Observer] {
			return fmt.Errorf("banned dealer %d attempted to submit observation", ao.Observer)
		}
	}

	initialDealing, err := codec.Unmarshal(ao.Observation, dkg.NewUnverifiedInitialDealing())
	if err != nil {
		return err
	}

	verifiedInitialDealing, err := dkgInstance.VerifyInitialDealing(initialDealing, int(ao.Observer))
	if err != nil {
		return fmt.Errorf("failed to verify initial dealing from dealer %d: %w", ao.Observer, err)
	}

	p.cacheVerifiedInitialDealing(int(ao.Observer), ao.Observation, verifiedInitialDealing)
	return nil
}

func (p *DKGPlugin) validateObservationReceivedInitialDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher, state *pluginState) error {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return err
	}

	dealings, err := p.readReceivedInitialDealings(keyValueReader, state.countRestart)
	if err != nil {
		return err
	}

	decryptionKeyShares, err := codec.Unmarshal(ao.Observation, dkg.NewUnverifiedDecryptionKeySharesForInnerDealing())
	if err != nil {
		return err
	}

	verifiedDecryptionKeyShares, err := dkgInstance.VerifyDecryptionKeyShares(dealings, decryptionKeyShares, int(ao.Observer))
	if err != nil {
		return fmt.Errorf("failed to verify decryption key shares from dealer %d: %w", ao.Observer, err)
	}

	p.cacheVerifiedDecryptionKeyShares(int(ao.Observer), ao.Observation, verifiedDecryptionKeyShares)
	return nil
}

func (p *DKGPlugin) validateObservationGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher, state *pluginState) error {
	// [TODO] Periodically transmit the DKG result
	return nil
}

func (p *DKGPlugin) ValidateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) error {
	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return err
	}

	switch state.stateMachineState {
	case Started:
		return p.validateObservationStarted(ctx, seqNr, aq, ao, keyValueReader, blobFetcher, state)
	case ReceivedInitialDealings:
		return p.validateObservationReceivedInitialDealings(ctx, seqNr, aq, ao, keyValueReader, blobFetcher, state)
	case GatheredInnerDealings:
		return p.validateObservationGatheredInnerDealings(ctx, seqNr, aq, ao, keyValueReader, blobFetcher, state)
	default:
		return fmt.Errorf("unknown state machine state: %v", state.stateMachineState)
	}
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) (bool, error) {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return false, err
	}

	state, err := p.readPluginState(keyValueReader)
	if err != nil {
		return false, err
	}

	switch state.stateMachineState {
	case Started:
		return len(aos) >= dkgInstance.DealingsThreshold(), nil
	case ReceivedInitialDealings:
		return len(aos) >= dkgInstance.DecryptionThreshold(), nil
	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
		return false, nil
	default:
		return false, fmt.Errorf("unknown state machine state: %v", state.stateMachineState)
	}
}

func (p *DKGPlugin) stateTransitionStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher, state *pluginState) (ocr3_1types.ReportsPlusPrecursor, error) {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return nil, err
	}

	dealings := make([]dkg.VerifiedInitialDealing, len(p.dealersPublicKeys))
	for _, ao := range aos {
		var err error
		dealings[ao.Observer], err = p.recoverVerifiedInitialDealing(dkgInstance, int(ao.Observer), ao.Observation)
		if err != nil {
			return nil, err
		}
	}

	// Only keep the first dkg.DealingsThreshold() dealings, in a deterministic manner
	// [TODO] Should be determined by the time instead of index, need to revisit
	cnt := len(aos) - dkgInstance.DealingsThreshold()
	for i := 0; i < len(dealings); i++ {
		if dealings[i] != nil {
			if cnt == 0 {
				break
			}
			dealings[i] = nil
			cnt--
		}
	}

	if err := p.writeReceivedInitialDealings(keyValueReadWriter, state.countRestart, dealings); err != nil {
		return nil, err
	}

	newState := pluginState{ReceivedInitialDealings, state.countRestart}
	if err := p.writePluginState(keyValueReadWriter, &newState); err != nil {
		return nil, err
	}

	p.logger.Info("🚀🚀🚀 DKGPlugin: received enough initial dealings", commontypes.LogFields{})

	return nil, nil
}

func (p *DKGPlugin) stateTransitionReceivedInitialDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher, state *pluginState) (ocr3_1types.ReportsPlusPrecursor, error) {
	dkgInstance, err := p.dkgInstance(ctx)
	if err != nil {
		return nil, err
	}

	dealings, err := p.readReceivedInitialDealings(keyValueReadWriter, state.countRestart)
	if err != nil {
		return nil, fmt.Errorf("failed to read received initial dealings: %w", err)
	}

	decryptionKeyShares := make(decryptionKeyShares, len(p.dealersPublicKeys))
	for i, ao := range aos {
		var err error
		decryptionKeyShares[ao.Observer], err = p.recoverVerifiedDecryptionKeyShares(dkgInstance, dealings, int(ao.Observer), ao.Observation)
		if err != nil {
			return nil, err
		}

		// Keep only dkg.DecryptionThreshold() decryption key shares, any subset should be sufficient for recovery deterministically
		if i+1 == dkgInstance.DecryptionThreshold() {
			break
		}
	}

	innerDealings, bannedList, restart, err := dkgInstance.RecoverInnerDealings(dealings, decryptionKeyShares)
	if err != nil {
		return nil, fmt.Errorf("failed to recover inner dealings: %w", err)
	}

	bannedDealers, err := p.readBannedDealers(keyValueReadWriter)
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers: %w", err)
	}
	for _, bannedDealer := range bannedList {
		bannedDealers[bannedDealer] = true
	}

	if err := p.writeGatheredInnerDealings(keyValueReadWriter, state.countRestart, decryptionKeyShares, innerDealings, bannedDealers); err != nil {
		return nil, err
	}

	if restart {
		newState := pluginState{Started, state.countRestart + 1}
		if err := p.writePluginState(keyValueReadWriter, &newState); err != nil {
			return nil, err
		}

		p.logger.Info("🚀 DKGPlugin: restart from scratch", commontypes.LogFields{})
		return nil, nil
	} else {
		newState := pluginState{GatheredInnerDealings, state.countRestart}
		if err := p.writePluginState(keyValueReadWriter, &newState); err != nil {
			return nil, err
		}

		result, err := dkgInstance.NewResult(innerDealings)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKG result: %w", err)
		}

		resultPackage := ResultPackage{result, p.config}
		reportsPlusPrecursor, err := resultPackage.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DKG result package: %w", err)
		}

		p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", commontypes.LogFields{})
		return reportsPlusPrecursor, nil
	}
}

func (p *DKGPlugin) stateTransitionGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher, state *pluginState) (ocr3_1types.ReportsPlusPrecursor, error) {
	// [TODO] Periodically transmit the DKG result
	return nil, nil
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	state, err := p.readPluginState(keyValueReadWriter)
	if err != nil {
		return nil, err
	}

	switch state.stateMachineState {
	case Started:
		return p.stateTransitionStarted(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher, state)
	case ReceivedInitialDealings:
		return p.stateTransitionReceivedInitialDealings(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher, state)
	case GatheredInnerDealings:
		return p.stateTransitionGatheredInnerDealings(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher, state)
	default:
		return nil, fmt.Errorf("unknown state machine state: %v", state.stateMachineState)
	}
}

func (p *DKGPlugin) Committed(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader) error {
	return nil
}

func (p *DKGPlugin) Reports(ctx context.Context, seqNr uint64, reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor) ([]ocr3types.ReportPlus[struct{}], error) {
	if reportsPlusPrecursor == nil {
		return nil, nil
	}

	reports := make([]ocr3types.ReportPlus[struct{}], 1)
	reports[0] = ocr3types.ReportPlus[struct{}]{
		ocr3types.ReportWithInfo[struct{}]{
			[]byte(reportsPlusPrecursor),
			struct{}{},
		},
		nil, // [TODO] Override Transmission schedule?
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

func (p *DKGPlugin) dkgInstance(ctx context.Context) (dkg.DKG, error) {
	if p.cachedValues.dkg == nil {
		if err := p.newDKG(ctx); err != nil {
			return nil, err
		}
	}
	return p.cachedValues.dkg, nil
}

func (p *DKGPlugin) newDKG(ctx context.Context) error {
	var newDKG dkg.DKG
	if p.config.PreviousInstanceID == nil {
		var err error
		newDKG, err = dkg.NewInitialDKG(dkgtypes.InstanceID(p.iid), math.P256, p.dealersPublicKeys, p.recipientsPublicKeys, p.f_D, p.t_R, p.keyring)
		if err != nil {
			return fmt.Errorf("failed to create DKG instance for fresh dealing: %w", err)
		}
	} else {
		priorResult, err := p.dealingResultPackageDatabase.ReadResultPackage(ctx, *p.config.PreviousInstanceID)
		if err != nil {
			return fmt.Errorf("failed to read prior result package: %w", err)
		}

		var resultPackage ResultPackage
		if err := resultPackage.UnmarshalBinary(priorResult.ReportWithResultPackage); err != nil {
			return fmt.Errorf("failed to unmarshal prior result package: %w", err)
		}

		newDKG, err = dkg.NewResharingDKG(dkgtypes.InstanceID(p.iid), p.dealersPublicKeys, p.recipientsPublicKeys, p.f_D, p.t_R, p.keyring, resultPackage.inner)
		if err != nil {
			return fmt.Errorf("failed to create DKG instance for resharing: %w", err)
		}
	}

	p.cachedValues.dkg = newDKG
	return nil
}

const dstHashUnverifiedInitialDealing = "smartcontract.com/dkgocr/plugin/hashUnverifiedInitialDealing"
const dstHashUnverifiedDecryptionKeyShares = "smartcontract.com/dkgocr/plugin/hashUnverifiedDecryptionKeyShares"

func hashUnverifiedObject(dst string, raw []byte) hashOfUnverifiedObject {
	hash := hash.NewHash(dst)
	hash.WriteBytes(raw)
	digest := hash.Digest()

	var res [32]byte
	copy(res[:], digest)
	return res
}

func (p *DKGPlugin) cacheVerifiedInitialDealing(observer int, raw []byte, dealing dkg.VerifiedInitialDealing) {
	hash := hashUnverifiedObject(dstHashUnverifiedInitialDealing, raw)
	if p.cachedValues.verifiedInitialDealings[observer][hash] == nil {
		p.cachedValues.verifiedInitialDealings[observer][hash] = dealing
	}
}

func (p *DKGPlugin) recoverVerifiedInitialDealing(dkgInstance dkg.DKG, observer int, raw []byte) (dkg.VerifiedInitialDealing, error) {
	hash := hashUnverifiedObject(dstHashUnverifiedInitialDealing, raw)
	if dealing, ok := p.cachedValues.verifiedInitialDealings[observer][hash]; ok {
		return dealing, nil
	} else {
		unverifiedDealing, err := codec.Unmarshal(raw, dkg.NewUnverifiedInitialDealing())
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal unverified initial dealing: %w", err)
		}
		return dkgInstance.VerifyInitialDealing(unverifiedDealing, observer)
	}
}

func (p *DKGPlugin) cacheVerifiedDecryptionKeyShares(observer int, raw []byte, shares dkg.VerifiedDecryptionKeySharesForInnerDealing) {
	hash := hashUnverifiedObject(dstHashUnverifiedDecryptionKeyShares, raw)
	if p.cachedValues.verifiedDecryptionKeyShares[observer][hash] == nil {
		p.cachedValues.verifiedDecryptionKeyShares[observer][hash] = shares
	}
}

func (p *DKGPlugin) recoverVerifiedDecryptionKeyShares(dkgInstance dkg.DKG, dealings initialDealings, observer int, raw []byte) (dkg.VerifiedDecryptionKeySharesForInnerDealing, error) {
	hash := hashUnverifiedObject(dstHashUnverifiedDecryptionKeyShares, raw)
	if shares, ok := p.cachedValues.verifiedDecryptionKeyShares[observer][hash]; ok {
		return shares, nil
	} else {
		unverifiedShares, err := codec.Unmarshal(raw, dkg.NewUnverifiedDecryptionKeySharesForInnerDealing())
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal unverified decryption key shares: %w", err)
		}
		return dkgInstance.VerifyDecryptionKeyShares(dealings, unverifiedShares, observer)
	}
}

const pluginStateKey = "PluginState"
const bannedDealersKey = "BannedDealers"
const initialDealingsKey = "InitialDealings"
const decryptionKeySharesKey = "DecryptionKeyShares"
const innerDealingsKey = "InnerDealings"

func (p *DKGPlugin) getPluginStateKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.iid, pluginStateKey))
}

func (p *DKGPlugin) getBannedDealersKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.iid, bannedDealersKey))
}

func (p *DKGPlugin) getInitialDealingsKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.iid, initialDealingsKey, countRestart))
}

func (p *DKGPlugin) getDecryptionKeySharesKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.iid, decryptionKeySharesKey, countRestart))
}

func (p *DKGPlugin) getInnerDealingsKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.iid, innerDealingsKey, countRestart))
}

func (p *DKGPlugin) readPluginState(keyValueReader ocr3_1types.KeyValueReader) (*pluginState, error) {
	data, err := keyValueReader.Read(p.getPluginStateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin state from key-value store: %w", err)
	}

	if len(data) > 0 {
		state, err := codec.Unmarshal(data, &pluginState{})
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal plugin state: %w", err)
		}
		return state, nil
	} else {
		return &pluginState{Started, 0}, nil
	}
}

func (p *DKGPlugin) writePluginState(keyValueReadWriter ocr3_1types.KeyValueReadWriter, state *pluginState) error {
	data, err := codec.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal plugin state: %w", err)
	}

	err = keyValueReadWriter.Write(p.getPluginStateKey(), data)
	if err != nil {
		return fmt.Errorf("failed to write plugin state to key-value store: %w", err)
	}
	return nil
}

func (p *DKGPlugin) readBannedDealers(keyValueReader ocr3_1types.KeyValueReader) (bannedDealers, error) {
	data, err := keyValueReader.Read(p.getBannedDealersKey())
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers from key-value store: %w", err)
	}

	bannedDealers := make(bannedDealers, len(p.dealersPublicKeys))
	for i := range bannedDealers {
		bannedDealers[i] = false
	}

	if len(data) > 0 {
		bannedDealers, err = codec.Unmarshal(data, &bannedDealers)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal banned dealers: %w", err)
		}
	}
	return bannedDealers, nil
}

func (p *DKGPlugin) readReceivedInitialDealings(keyValueReader ocr3_1types.KeyValueReader, countRestart int) (initialDealings, error) {
	raw, err := keyValueReader.Read(p.getInitialDealingsKey(countRestart))
	if err != nil {
		return nil, fmt.Errorf("failed to read initial dealings from key-value store: %w", err)
	}

	initialDealings, err := codec.Unmarshal(raw, &initialDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial dealings: %w", err)
	}
	return initialDealings, nil
}

func (p *DKGPlugin) writeReceivedInitialDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, countRestart int, dealings initialDealings) error {
	data, err := codec.Marshal(dealings)
	if err != nil {
		return fmt.Errorf("failed to marshal initial dealings: %w", err)
	}

	err = keyValueReadWriter.Write(p.getInitialDealingsKey(countRestart), data)
	if err != nil {
		return fmt.Errorf("failed to write initial dealings to key-value store: %w", err)
	}
	return nil
}

func (p *DKGPlugin) readGatheredInnerDealings(keyValueReader ocr3_1types.KeyValueReader, countRestart int) (*decryptionKeyShares, innerDealings, error) {
	raw, err := keyValueReader.Read(p.getDecryptionKeySharesKey(countRestart))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read decryption key shares from key-value store: %w", err)
	}
	decryptionKeyShares, err := codec.Unmarshal(raw, &decryptionKeyShares{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal decryption key shares: %w", err)
	}

	raw, err = keyValueReader.Read(p.getInnerDealingsKey(countRestart))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read inner dealings from key-value store: %w", err)
	}
	innerDealings, err := codec.Unmarshal(raw, &innerDealings{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal inner dealings: %w", err)
	}

	return &decryptionKeyShares, innerDealings, nil
}

func (p *DKGPlugin) writeGatheredInnerDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, countRestart int, decryptionKeyShares decryptionKeyShares, innerDealings innerDealings, bannedDealers bannedDealers) error {
	data, err := codec.Marshal(decryptionKeyShares)
	if err != nil {
		return fmt.Errorf("failed to marshal decryption key shares: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getDecryptionKeySharesKey(countRestart), data); err != nil {
		return fmt.Errorf("failed to write decryption key shares to key-value store: %w", err)
	}

	data, err = codec.Marshal(innerDealings)
	if err != nil {
		return fmt.Errorf("failed to marshal inner dealings: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getInnerDealingsKey(countRestart), data); err != nil {
		return fmt.Errorf("failed to write inner dealings to key-value store: %w", err)
	}

	data, err = codec.Marshal(bannedDealers)
	if err != nil {
		return fmt.Errorf("failed to marshal banned dealers: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getBannedDealersKey(), data); err != nil {
		return fmt.Errorf("failed to write banned dealers to key-value store: %w", err)
	}

	return nil
}
