// [TODO]
// How to properly retrieve secret keys?
// Use blob dissemination for broadcasting dealings to avoid overwhelming the bandwidth of the leader
// Currently not optimized when the network is not synchronized, may allowing gradually increasing the set of dealings and decryption shares
// Transmit dkg results periodically (not to a blockchain but other offchain nodes)
// What happens if an OCR node crashes during a DKG instance and restarts at any state of the protocol? Should it generate the same dealing as before crashing?

package plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/dkg"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/smdkg/internal/serialization"
)

type StateMachineState int

const (
	Started StateMachineState = iota
	ReceivedOuterDealings
	GatheredInnerDealings
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

	dkgConfig := &dkgocrtypes.ReportingPluginConfig{}
	if err := dkgConfig.UnmarshalBinary(config.OffchainConfig); err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to unmarshal DKG plugin config: %w", err)
	}

	var privID *recipientIdentity
	pk, err := dkgtypes.NewP256PublicKey(f.keyring.PublicKey())
	if err != nil {
		return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to create public key: %w", err)
	}

	dealersPublicKeys := make([]dkgtypes.ParticipantPublicKey, len(dkgConfig.DealerPublicKeys))
	for i, k := range dkgConfig.DealerPublicKeys {
		dealersPublicKeys[i] = dkgtypes.ParticipantPublicKey(k)
		if bytes.Equal(dealersPublicKeys[i], f.keyring.PublicKey()) {
			privID = &recipientIdentity{
				f.keyring,
				pk,
				i,
				math.P256.Scalar().SetUint(uint(i + 1)),
			}
		}
	}

	recipientsPublicKeys := make([]dkgtypes.ParticipantPublicKey, len(dkgConfig.RecipientPublicKeys))
	for i, k := range dkgConfig.RecipientPublicKeys {
		recipientsPublicKeys[i] = dkgtypes.ParticipantPublicKey(k)
	}

	var newDKG dkg.DKG
	if dkgConfig.PreviousInstanceID == nil {
		newDKG, err = dkg.NewInitialDKG(string(iid), math.P256, dealersPublicKeys, recipientsPublicKeys, config.F, dkgConfig.T, privID)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to create DKG instance: %w", err)
		}
	} else {
		priorResult, err := f.dealingResultPackageDatabase.ReadResultPackage(context, *dkgConfig.PreviousInstanceID)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to read prior result package: %w", err)
		}

		var resultPackage ResultPackage
		if err := resultPackage.UnmarshalBinary(priorResult.ReportWithResultPackage); err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to unmarshal prior result package: %w", err)
		}

		newDKG, err = dkg.NewResharingDKG(string(iid), dealersPublicKeys, recipientsPublicKeys, config.F, dkgConfig.T, &resultPackage.inner, privID)
		if err != nil {
			return nil, ocr3_1types.ReportingPluginInfo{}, fmt.Errorf("failed to create DKG instance: %w", err)
		}
	}

	return &DKGPlugin{
			f.logger,
			newDKG,
			rand.Reader, // [TODO] Need to confirm the use of rng here
			nil,
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
		},
		nil
}

type DKGPlugin struct {
	logger commontypes.Logger
	dkg    dkg.DKG
	rand   io.Reader
	state  *dkgState
}

type dkgState struct {
	stateMachineState   StateMachineState
	cntStartFromScratch int
	bannedDealers       []bool
	dealings            []dkg.Dealing
	decryptionShares    DecryptionKeyShares
	innerDealings       []dkg.InnerDealing
}

type DecryptionKeyShares map[dkgtypes.PublicIdentity]math.Scalars

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Query, error) {
	return make([]byte, 0), nil // Nothing needed in the query
}

func (p *DKGPlugin) observationStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	dealing, err := p.dkg.Deal(p.rand)
	if err != nil {
		return nil, err
	}
	ob, err := dealing.Bytes()
	if err != nil {
		return nil, err
	}
	return ob, nil
}

func (p *DKGPlugin) observationReceivedOuterDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	shares, err := p.dkg.DecryptDecryptionKeyShares(p.state.dealings)
	if err != nil {
		return nil, err
	}
	return shares.Bytes()
}

func (p *DKGPlugin) observationGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	// [TODO] Periodically transmit the DKG result
	return make([]byte, 0), nil
}

func (p *DKGPlugin) Observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	if err := p.readDKGState(keyValueReader); err != nil {
		return nil, err
	}

	switch p.state.stateMachineState {
	case Started:
		return p.observationStarted(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
	case ReceivedOuterDealings:
		return p.observationReceivedOuterDealings(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
	case GatheredInnerDealings:
		return p.observationGatheredInnerDealings(ctx, seqNr, aq, keyValueReader, blobBroadcastFetcher)
	default:
		return nil, fmt.Errorf("unknown state machine state: %v", p.state.stateMachineState)
	}
}

func (p *DKGPlugin) validateObservationStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher) error {
	_, err := p.dkg.VerifyDealing(p.dkg.Dealers()[ao.Observer], ao.Observation)
	return err
}

func (p *DKGPlugin) validateObservationReceivedOuterDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher) error {
	_, err := p.dkg.VerifyDecryptionKeyShares(ao.Observation, p.state.dealings, p.dkg.Dealers()[ao.Observer])
	return err
}

func (p *DKGPlugin) validateObservationGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher) error {
	// [TODO] Periodically transmit the DKG result
	return nil
}

func (p *DKGPlugin) ValidateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) error {
	if err := p.readDKGState(keyValueReader); err != nil {
		return err
	}

	if p.state.bannedDealers[ao.Observer] {
		return fmt.Errorf("banned dealer %d attempted to submit observation", ao.Observer)
	}

	switch p.state.stateMachineState {
	case Started:
		return p.validateObservationStarted(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
	case ReceivedOuterDealings:
		return p.validateObservationReceivedOuterDealings(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
	case GatheredInnerDealings:
		return p.validateObservationGatheredInnerDealings(ctx, seqNr, aq, ao, keyValueReader, blobFetcher)
	default:
		return fmt.Errorf("unknown state machine state: %v", p.state.stateMachineState)
	}
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) (bool, error) {
	if err := p.readDKGState(keyValueReader); err != nil {
		return false, err
	}

	switch p.state.stateMachineState {
	case Started:
		return len(aos) >= p.dkg.DealingsThreshold(), nil
	case ReceivedOuterDealings:
		return len(aos) >= p.dkg.DecryptionThreshold(), nil
	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
		return false, nil
	default:
		return false, fmt.Errorf("unknown state machine state: %v", p.state.stateMachineState)
	}
}

func (p *DKGPlugin) stateTransitionStarted(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	dealings := make([]dkg.Dealing, p.dkg.DealingsThreshold())
	for i := 0; i < p.dkg.DealingsThreshold(); i++ {
		var err error
		dealings[i], err = p.dkg.VerifyDealing(p.dkg.Dealers()[aos[i].Observer], aos[i].Observation) // [TODO] Would be nice if a deserialization function is available, since ao is already verified
		if err != nil {
			return nil, err
		}
	}

	if err := p.writeStateMachineState(keyValueReadWriter, ReceivedOuterDealings); err != nil {
		return nil, err
	}

	if err := p.writeReceivedOuterDealings(keyValueReadWriter, p.state.cntStartFromScratch, p.state.dealings); err != nil {
		return nil, err
	}

	// [TODO] Should plugin state be changed before or after writing to kvStore? When would writing fail when the outer dealings are valid?
	p.state.stateMachineState = ReceivedOuterDealings
	p.state.dealings = dealings

	p.logger.Info("🚀🚀🚀 DKGPlugin: received enough outer dealings", commontypes.LogFields{})

	return nil, nil
}

func (p *DKGPlugin) stateTransitionReceivedOuterDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	decryptionShares := make(DecryptionKeyShares)
	for _, ao := range aos {
		decryptionShare, err := p.dkg.VerifyDecryptionKeyShares(ao.Observation, p.state.dealings, p.dkg.Dealers()[ao.Observer]) // [TODO] Would be nice if a deserialization function is available, since ao is already verified
		if err != nil {
			return nil, err
		}
		dealer := p.dkg.Dealers()[ao.Observer]
		decryptionShares[dealer] = decryptionShare
	}

	innerDealings, bannedDealers, startFromScratch, err := p.dkg.RecoverInnerDealings(p.state.dealings, decryptionShares)
	if err != nil {
		return nil, err
	}

	bannedList := make([]bool, len(p.dkg.Dealers()))
	for i := range bannedList {
		bannedList[i] = p.state.bannedDealers[i]
	}
	for i := range bannedDealers {
		bannedList[bannedDealers[i].Index()] = true
	}

	// [TODO] Should this be checked before err?
	if startFromScratch {
		if err := p.writeStateMachineState(keyValueReadWriter, Started); err != nil {
			return nil, err
		}

		if err := p.writeCntStartFromScratch(keyValueReadWriter, p.state.cntStartFromScratch+1); err != nil {
			return nil, err
		}

		if err := p.writeGatheredInnerDealings(keyValueReadWriter, p.state.cntStartFromScratch, decryptionShares, innerDealings, bannedList); err != nil {
			return nil, err
		}

		p.state.stateMachineState = Started
		p.state.cntStartFromScratch++
		p.state.decryptionShares = decryptionShares
		p.state.innerDealings = innerDealings
		p.state.bannedDealers = bannedList

		p.logger.Info("🚀 DKGPlugin: restart from scratch", commontypes.LogFields{})

		return nil, nil
	} else {
		if err := p.writeStateMachineState(keyValueReadWriter, GatheredInnerDealings); err != nil {
			return nil, err
		}

		if err := p.writeGatheredInnerDealings(keyValueReadWriter, p.state.cntStartFromScratch, decryptionShares, innerDealings, bannedList); err != nil {
			return nil, err
		}

		// TODO!!!
		reportsPlusPrecursor, err := serializeInnerDealings(innerDealings) // [TODO] Add DKG instanceID and digest?
		if err != nil {
			return nil, err
		}

		p.state.stateMachineState = GatheredInnerDealings
		p.state.decryptionShares = decryptionShares
		p.state.innerDealings = innerDealings
		p.state.bannedDealers = bannedList

		p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", commontypes.LogFields{})

		return reportsPlusPrecursor, nil
	}
}

func (p *DKGPlugin) stateTransitionGatheredInnerDealings(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	// [TODO] Periodically transmit the DKG result
	return nil, nil
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	if err := p.readDKGState(keyValueReadWriter); err != nil {
		return nil, err
	}

	switch p.state.stateMachineState {
	case Started:
		return p.stateTransitionStarted(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
	case ReceivedOuterDealings:
		return p.stateTransitionReceivedOuterDealings(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
	case GatheredInnerDealings:
		return p.stateTransitionGatheredInnerDealings(ctx, seqNr, aq, aos, keyValueReadWriter, blobFetcher)
	default:
		return nil, fmt.Errorf("unknown state machine state: %v", p.state.stateMachineState)
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
	return true, nil // [TODO] Periodically transmit the DKG result
}

func (p *DKGPlugin) Close() error {
	return nil
}

func (p *DKGPlugin) readDKGState(keyValueReader ocr3_1types.KeyValueReader) error {
	// [TODO] State read from kvStore whenever a plugin function is called to make sure the state is up-to-date. May consider optimize this.
	// Fetch the State Machine State
	stateMachineState, cntStartFromScratch, bannedDealers, err := p.readStateCntBannedDealers(keyValueReader)
	if err != nil {
		return err
	}

	if stateMachineState == Started {
		p.state = &dkgState{
			stateMachineState,
			cntStartFromScratch,
			bannedDealers,
			make([]dkg.Dealing, 0),
			make(DecryptionKeyShares),
			make([]dkg.InnerDealing, 0),
		}
		return nil
	}

	outerDealingsRaw, err := keyValueReader.Read(p.getOuterDealingsKey(cntStartFromScratch))
	if err != nil {
		return err
	}

	outerDealings, err := deserializeOuterDealings(outerDealingsRaw)
	if err != nil {
		return err
	}

	if stateMachineState == ReceivedOuterDealings {
		p.state = &dkgState{
			stateMachineState,
			cntStartFromScratch,
			bannedDealers,
			outerDealings,
			make(DecryptionKeyShares),
			make([]dkg.InnerDealing, 0),
		}
		return nil
	}

	decryptionKeySharesRaw, err := keyValueReader.Read(p.getDecryptionKeySharesKey(cntStartFromScratch))
	if err != nil {
		return err
	}

	decryptionKeyShares, err := p.deserializeDecryptionKeyShares(decryptionKeySharesRaw)
	if err != nil {
		return err
	}

	innerDealingsRaw, err := keyValueReader.Read(p.getInnerDealingsKey(cntStartFromScratch))
	if err != nil {
		return err
	}

	innerDealings, err := deserializeInnerDealings(innerDealingsRaw)
	if err != nil {
		return err
	}

	p.state = &dkgState{
		stateMachineState,
		cntStartFromScratch,
		bannedDealers,
		outerDealings,
		decryptionKeyShares,
		innerDealings,
	}
	return nil
}

const stateMachineStateKey = "StateMachineState"
const cntStartFromScratchKey = "CntStartFromScratch"
const bannedDealersKey = "BannedDealers"
const outerDealingsKey = "OuterDealings"
const decryptionKeySharesKey = "DecryptionKeyShares"
const innerDealingsKey = "InnerDealings"

func (p *DKGPlugin) getStateMachineStateKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.dkg.InstanceID(), stateMachineStateKey))
}

func (p *DKGPlugin) getCntStartFromScratchKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.dkg.InstanceID(), cntStartFromScratchKey))
}

func (p *DKGPlugin) getBannedDealersKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.dkg.InstanceID(), bannedDealersKey))
}

func (p *DKGPlugin) getOuterDealingsKey(cntStartFromScratch int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkg.InstanceID(), outerDealingsKey, cntStartFromScratch))
}

func (p *DKGPlugin) getDecryptionKeySharesKey(cntStartFromScratch int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkg.InstanceID(), decryptionKeySharesKey, cntStartFromScratch))
}

func (p *DKGPlugin) getInnerDealingsKey(cntStartFromScratch int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkg.InstanceID(), innerDealingsKey, cntStartFromScratch))
}

func (p *DKGPlugin) readStateCntBannedDealers(keyValueReader ocr3_1types.KeyValueReader) (StateMachineState, int, []bool, error) {
	var state StateMachineState = Started
	var cntStartFromScratch = 0
	bannedDealers := make([]bool, len(p.dkg.Dealers()))
	for i := range p.dkg.Dealers() {
		bannedDealers[i] = false
	}

	stateRaw, err := keyValueReader.Read(p.getStateMachineStateKey())
	if err != nil {
		return state, cntStartFromScratch, bannedDealers, err
	}

	if len(stateRaw) > 0 {
		state, err = deserializeStateInStateMachine(stateRaw)
		if err != nil {
			return state, cntStartFromScratch, bannedDealers, err
		}

		raw, err := keyValueReader.Read(p.getCntStartFromScratchKey())
		if err != nil {
			return state, cntStartFromScratch, bannedDealers, err
		}

		if len(raw) > 0 {
			cntStartFromScratch, err = deserializeCntStartFromScratch(raw)
			if err != nil {
				return state, cntStartFromScratch, bannedDealers, err

			}

			raw, err = keyValueReader.Read(p.getBannedDealersKey())
			if err != nil {
				return state, cntStartFromScratch, bannedDealers, err
			}

			bannedDealers, err = deserializeBannedDealers(raw, len(p.dkg.Dealers()))
			if err != nil {
				return state, cntStartFromScratch, bannedDealers, err
			}
		}
	}

	return state, cntStartFromScratch, bannedDealers, nil
}

func (p *DKGPlugin) writeStateMachineState(keyValueReadWriter ocr3_1types.KeyValueReadWriter, state StateMachineState) error {
	data, err := serializeStateMachineState(state)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getStateMachineStateKey(), data)
}

func (p *DKGPlugin) writeReceivedOuterDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, cnt int, dealings []dkg.Dealing) error {
	data, err := serializeOuterDealings(dealings)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getOuterDealingsKey(cnt), data)
}

func (p *DKGPlugin) writeCntStartFromScratch(keyValueReadWriter ocr3_1types.KeyValueReadWriter, cnt int) error {
	data, err := serializeCntStartFromScratch(cnt)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getCntStartFromScratchKey(), data)
}

func (p *DKGPlugin) writeGatheredInnerDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, cnt int, decryptionKeyShares DecryptionKeyShares, innerDealings []dkg.InnerDealing, bannedDealers []bool) error {
	data, err := p.serializeDecryptionKeyShares(decryptionKeyShares)
	if err != nil {
		return err
	}
	if err := keyValueReadWriter.Write(p.getDecryptionKeySharesKey(cnt), data); err != nil {
		return err
	}

	data, err = serializeInnerDealings(innerDealings)
	if err != nil {
		return err
	}
	if err := keyValueReadWriter.Write(p.getInnerDealingsKey(cnt), data); err != nil {
		return err
	}

	data, err = serializeBannedDealers(bannedDealers)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getBannedDealersKey(), data)
}

func serializeStateMachineState(state StateMachineState) ([]byte, error) {
	encoder := serialization.NewEncoder()
	encoder.WriteInt(int(state))
	return encoder.Bytes()
}

func deserializeStateInStateMachine(raw []byte) (StateMachineState, error) {
	decoder := serialization.NewDecoder(raw)
	state := decoder.ReadInt()
	if err := decoder.Finish(); err != nil {
		return 0, err
	}
	return StateMachineState(state), nil
}

func serializeCntStartFromScratch(cnt int) ([]byte, error) {
	encoder := serialization.NewEncoder()
	encoder.WriteInt(cnt)
	return encoder.Bytes()
}

func deserializeCntStartFromScratch(raw []byte) (int, error) {
	decoder := serialization.NewDecoder(raw)
	cnt := decoder.ReadInt()
	if err := decoder.Finish(); err != nil {
		return 0, err
	}
	return cnt, nil
}

func serializeBannedDealers(bannedDealers []bool) ([]byte, error) {
	encoder := serialization.NewEncoder()
	for _, banned := range bannedDealers {
		encoder.WriteBool(banned)
	}
	return encoder.Bytes()
}

func deserializeBannedDealers(raw []byte, dealerCount int) ([]bool, error) {
	bannedDealers := make([]bool, dealerCount)

	decoder := serialization.NewDecoder(raw)
	for i := 0; i < dealerCount; i++ {
		bannedDealers[i] = decoder.ReadBool()
	}
	if err := decoder.Finish(); err != nil {
		return bannedDealers, err
	}
	return bannedDealers, nil
}

// [TODO] All serialization using json.Marshal to be optimized!!!
func serializeOuterDealings(dealings []dkg.Dealing) ([]byte, error) {
	return json.Marshal(dealings)
}

func deserializeOuterDealings(raw []byte) ([]dkg.Dealing, error) {
	var dealings []dkg.Dealing
	if err := json.Unmarshal(raw, &dealings); err != nil {
		return nil, err
	}
	return dealings, nil
}

func (p *DKGPlugin) serializeDecryptionKeyShares(dks DecryptionKeyShares) ([]byte, error) {
	encoder := serialization.NewEncoder()
	for _, dealer := range p.dkg.Dealers() {
		if shares, ok := dks[dealer]; ok {
			encoder.WriteInt(len(shares))
			for _, share := range shares {
				encoder.WriteBytes(share.Bytes())
			}
		} else {
			encoder.WriteInt(0)
		}
	}
	return encoder.Bytes()
}

func (p *DKGPlugin) deserializeDecryptionKeyShares(data []byte) (DecryptionKeyShares, error) {
	dks := make(DecryptionKeyShares)
	decoder := serialization.NewDecoder(data)

	for _, dealer := range p.dkg.Dealers() {
		numShares := decoder.ReadInt()
		if numShares <= 0 {
			return nil, fmt.Errorf("deserialization failed, invalid number of shares (%d)", numShares)
		}
		if numShares == 0 {
			continue
		}

		shares := make(math.Scalars, numShares)
		for i := 0; i < numShares; i++ {
			share, err := p.dkg.Curve().Scalar().SetBytes(decoder.ReadBytes())
			if err != nil {
				return nil, err
			}
			shares[i] = share
		}
		dks[dealer] = shares
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	return dks, nil
}

func serializeInnerDealings(ids []dkg.InnerDealing) ([]byte, error) {
	return json.Marshal(ids)
}

func deserializeInnerDealings(raw []byte) ([]dkg.InnerDealing, error) {
	var ids []dkg.InnerDealing
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}
