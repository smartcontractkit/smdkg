// [TODO]
// How to properly retrieve secret keys?
// Use blob dissemination for broadcasting dealings to avoid overwhelming the bandwidth of the leader
// Currently not optimized when the network is not synchronized, may allowing gradually increasing the set of dealings and decryption shares
// Transmit dkg results periodically (not to a blockchain but other offchain nodes)
// What happens if an OCR node crashes during a DKG instance and restarts at any state of the protocol? Should it generate the same dealing as before crashing?

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
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

type DKGPluginFactory struct {
	Logger commontypes.Logger
	iid    dkgtypes.InstanceID
	dkg    dkg.DKG
	priv   dkgtypes.PrivateIdentity
	rand   io.Reader
}

var _ ocr3_1types.ReportingPluginFactory[struct{}] = &DKGPluginFactory{}

func (f *DKGPluginFactory) NewReportingPlugin(_ context.Context,
	config ocr3types.ReportingPluginConfig,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocr3_1types.ReportingPlugin[struct{}], ocr3_1types.ReportingPluginInfo, error) {
	return &DKGPlugin{
			config,
			f.Logger,
			f.iid,
			f.dkg,
			f.priv,
			f.dkg.Dealers(),
			f.rand,
			nil,
		}, ocr3_1types.ReportingPluginInfo{
			"DKGPlugin",
			ocr3_1types.ReportingPluginLimits{ // [TODO] These limits need to be revisited
				1024,
				20 * 1024,
				1024,
				70 * 1024,
				128,
				70 * 1024,
				1024,
			},
		},
		nil
}

type DKGPlugin struct {
	config  ocr3types.ReportingPluginConfig
	logger  commontypes.Logger
	iid     dkgtypes.InstanceID
	dkg     dkg.DKG
	priv    dkgtypes.PrivateIdentity
	dealers []dkgtypes.PublicIdentity
	rand    io.Reader
	state   *dkgState
}

type dkgState struct {
	stateMachineState StateMachineState
	dealings          []dkg.Dealing
	decryptionShares  DecryptionKeyShares
	innerDealings     []dkg.InnerDealing
}

type DecryptionKeyShares map[dkgtypes.PublicIdentity]math.Scalars

var _ ocr3_1types.ReportingPlugin[struct{}] = &DKGPlugin{}

func (p *DKGPlugin) Query(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Query, error) {
	return make([]byte, 0), nil // Nothing needed in the query
}

func (p *DKGPlugin) Observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher) (types.Observation, error) {
	if p.state == nil {
		state, err := p.readDKGState(keyValueReader)
		if err != nil {
			return nil, err
		}
		p.state = state
	}

	switch p.state.stateMachineState {
	case Started:
		dealing, err := p.dkg.Deal(p.rand)
		if err != nil {
			return nil, err
		}
		ob, err := dealing.Bytes()
		if err != nil {
			return nil, err
		}
		return ob, nil

	case ReceivedOuterDealings:
		shares, err := p.dkg.DecryptDecryptionKeyShares(p.state.dealings)
		if err != nil {
			return nil, err
		}
		return shares.Bytes()

	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
	}
	return make([]byte, 0), nil
}

func (p *DKGPlugin) ValidateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) error {
	if p.state == nil {
		state, err := p.readDKGState(keyValueReader)
		if err != nil {
			return err
		}
		p.state = state
	}

	switch p.state.stateMachineState {
	case Started:
		_, err := p.dkg.VerifyDealing(p.dealers[ao.Observer], ao.Observation)
		return err

	case ReceivedOuterDealings:
		_, err := p.dkg.VerifyDecryptionKeyShares(ao.Observation, p.state.dealings, p.dealers[ao.Observer])
		return err

	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
	}

	return nil
}

func (p *DKGPlugin) ObservationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader,
	blobFetcher ocr3_1types.BlobFetcher) (bool, error) {
	if p.state == nil {
		state, err := p.readDKGState(keyValueReader)
		if err != nil {
			return false, err
		}
		p.state = state
	}

	switch p.state.stateMachineState {
	case Started:
		return len(aos) >= p.dkg.DealingsThreshold(), nil

	case ReceivedOuterDealings:
		return len(aos) >= p.dkg.DecryptionThreshold(), nil

	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
		return false, nil
	}

	return true, nil
}

func (p *DKGPlugin) StateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher) (ocr3_1types.ReportsPlusPrecursor, error) {
	if p.state == nil {
		state, err := p.readDKGState(keyValueReadWriter)
		if err != nil {
			return nil, err
		}
		p.state = state
	}

	switch p.state.stateMachineState {
	case Started:
		p.state.dealings = make([]dkg.Dealing, p.dkg.DealingsThreshold())
		for i := 0; i < p.dkg.DealingsThreshold(); i++ {
			dealing, err := p.dkg.VerifyDealing(p.dealers[aos[i].Observer], aos[i].Observation) // [TODO] Would be nice if a deserialization function is available, since ao is already verified
			if err != nil {
				return nil, err
			}
			p.state.dealings[i] = dealing // [TODO] Need to confirm that the order of aos is consistent at all followers
		}

		if err := p.writeReceivedOuterDealings(keyValueReadWriter, p.state.dealings); err != nil {
			return nil, err
		}

		p.state.stateMachineState = ReceivedOuterDealings

		p.logger.Info("🚀🚀🚀 DKGPlugin: received enough outer dealings", commontypes.LogFields{})

		return nil, nil

	case ReceivedOuterDealings:
		p.state.decryptionShares = make(DecryptionKeyShares)
		for _, ao := range aos {
			decryptionShare, err := p.dkg.VerifyDecryptionKeyShares(ao.Observation, p.state.dealings, p.dealers[ao.Observer])
			if err != nil {
				return nil, err
			}
			dealer := p.dealers[ao.Observer]
			p.state.decryptionShares[dealer] = decryptionShare
		}

		// TODO
		var err error
		p.state.innerDealings, _, _, err = p.dkg.RecoverInnerDealings(p.state.dealings, p.state.decryptionShares)
		if err != nil {
			return nil, err
		}

		if err := p.writeGatheredInnerDealings(keyValueReadWriter, p.state.decryptionShares, p.state.innerDealings); err != nil {
			return nil, err
		}

		reportsPlusPrecursor, err := serializeInnerDealings(p.state.innerDealings) // [TODO] Add DKG instanceID and digest?
		if err != nil {
			return nil, err
		}

		p.state.stateMachineState = GatheredInnerDealings

		p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", commontypes.LogFields{})

		return reportsPlusPrecursor, nil

	case GatheredInnerDealings:
		// [TODO] Periodically transmit the DKG result
	}

	return nil, nil
}

func (p *DKGPlugin) Committed(ctx context.Context, seqNr uint64, keyValueReader ocr3_1types.KeyValueReader) error {
	return nil
}

func (p *DKGPlugin) Reports(ctx context.Context, seqNr uint64, reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor) ([]ocr3types.ReportPlus[struct{}], error) {
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
	return false, nil // [TODO: We don't transmit to blockchain but other nodes, what to do here?]
}

func (p *DKGPlugin) Close() error {
	return nil
}

func (p *DKGPlugin) readDKGState(keyValueReader ocr3_1types.KeyValueReader) (*dkgState, error) {
	// Fetch the State Machine State
	stateMachineState, err := p.readStatemachineState(keyValueReader)
	if err != nil {
		return nil, err
	}

	if stateMachineState == Started {
		return &dkgState{
			stateMachineState,
			make([]dkg.Dealing, 0),
			make(DecryptionKeyShares),
			make([]dkg.InnerDealing, 0),
		}, nil
	}

	outerDealingsRaw, err := keyValueReader.Read(p.getStateKey(outerDealingsKey))
	if err != nil {
		return nil, err
	}

	outerDealings, err := deserializeOuterDealings(outerDealingsRaw)
	if err != nil {
		return nil, err
	}

	if stateMachineState == ReceivedOuterDealings {
		return &dkgState{
			stateMachineState,
			outerDealings,
			make(DecryptionKeyShares),
			make([]dkg.InnerDealing, 0),
		}, nil
	}

	decryptionKeySharesRaw, err := keyValueReader.Read(p.getStateKey(decryptionKeySharesKey))
	if err != nil {
		return nil, err
	}

	decryptionKeyShares, err := p.deserializeDecryptionKeyShares(decryptionKeySharesRaw)
	if err != nil {
		return nil, err
	}

	innerDealingsRaw, err := keyValueReader.Read(p.getStateKey(innerDealingsKey))
	if err != nil {
		return nil, err
	}

	innerDealings, err := deserializeInnerDealings(innerDealingsRaw)
	if err != nil {
		return nil, err
	}

	return &dkgState{
		stateMachineState,
		outerDealings,
		decryptionKeyShares,
		innerDealings,
	}, nil
}

const stateMachineStateKey = "StateMachineState"
const outerDealingsKey = "OuterDealings"
const decryptionKeySharesKey = "DecryptionKeyShares"
const innerDealingsKey = "InnerDealings"

func (p *DKGPlugin) getStateKey(key string) []byte {
	return []byte(string(p.iid) + "_" + key)
}

func (p *DKGPlugin) readStatemachineState(keyValueReader ocr3_1types.KeyValueReader) (StateMachineState, error) {
	stateRaw, err := keyValueReader.Read([]byte(p.iid + stateMachineStateKey))
	if err != nil {
		return Started, err
	}

	var state StateMachineState = Started
	if len(stateRaw) > 0 {
		state, err = deserializeStateInStateMachine(stateRaw)
		if err != nil {
			return Started, err
		}
	}

	return state, nil
}

func (p *DKGPlugin) writeReceivedOuterDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, dealings []dkg.Dealing) error {
	data, err := serializeStateMachineState(ReceivedOuterDealings)
	if err != nil {
		return err
	}
	if err := keyValueReadWriter.Write(p.getStateKey(stateMachineStateKey), data); err != nil {
		return err
	}

	data, err = serializeOuterDealings(dealings)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getStateKey(outerDealingsKey), data)
}

func (p *DKGPlugin) writeGatheredInnerDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, decryptionKeyShares DecryptionKeyShares, innerDealings []dkg.InnerDealing) error {
	data, err := serializeStateMachineState(GatheredInnerDealings)
	if err != nil {
		return err
	}
	if err := keyValueReadWriter.Write(p.getStateKey(stateMachineStateKey), data); err != nil {
		return err
	}

	data, err = p.serializeDecryptionKeyShares(decryptionKeyShares)
	if err != nil {
		return err
	}
	if err := keyValueReadWriter.Write(p.getStateKey(decryptionKeySharesKey), data); err != nil {
		return err
	}

	data, err = serializeInnerDealings(innerDealings)
	if err != nil {
		return err
	}
	return keyValueReadWriter.Write(p.getStateKey(innerDealingsKey), data)
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
		return Started, err
	}
	return StateMachineState(state), nil
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
	for _, dealer := range p.dealers {
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

	for _, dealer := range p.dealers {
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
