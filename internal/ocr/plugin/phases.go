package plugin

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	ocrtypes "github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/libocr/quorumhelper"
	"github.com/smartcontractkit/smdkg/internal/codec"

	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
)

// Implementation of Observation, ValidateObservation, ObservationQuorum, StateTransition for each phase of the DKG
// plugin.

// For length of the following slices always match the number of dealers. Some values may be nil, meaning we do not have
// data for that particular dealer.
type pluginPhaseType int

const (
	_ pluginPhaseType = iota

	// The initial state of a DKG round. In this state, the initial dealings are sent out.
	pluginPhaseTypeDealing

	// The protocol has gathered enough valid initial dealings (and has written them to the key/value store). It
	// proceeds to send out decryption key shares in this state.
	pluginPhaseTypeDecrypting

	// The protocol has gathered enough valid inner dealings (and has written them to key/value store). In this state,
	// the DKG's result is ready and the DKG is finished.
	pluginPhaseTypeFinished
)

var _ codec.Unmarshaler[plugintypes.PluginPhase] = pluginPhaseUnmarshaler{nil}

var _ plugintypes.PluginPhase = &phaseDealing{}
var _ plugintypes.PluginPhase = &phaseDecrypting{}
var _ plugintypes.PluginPhase = &phaseFinished{}

type phaseDealing struct {
	*DKGPlugin
	attempt int
}

type phaseDecrypting struct {
	*DKGPlugin
	attempt int
}

type phaseFinished struct {
	*DKGPlugin
	attempt int
}

func (p *phaseDealing) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginPhaseTypeDealing))
	target.WriteInt(p.attempt)
}

func (p *phaseDecrypting) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginPhaseTypeDecrypting))
	target.WriteInt(p.attempt)
}

func (s *phaseFinished) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginPhaseTypeFinished))
	target.WriteInt(s.attempt)
}

// Implements unmarshaling for a pluginState.
// If provided, the plugin field of the unmarshaled state to the given value from the unmarshaler.
type pluginPhaseUnmarshaler struct {
	plugin *DKGPlugin
}

func (u pluginPhaseUnmarshaler) UnmarshalFrom(source codec.Source) plugintypes.PluginPhase {
	pluginStateType := pluginPhaseType(source.ReadInt())
	attempt := source.ReadInt()

	switch pluginStateType {
	case pluginPhaseTypeDealing:
		return &phaseDealing{u.plugin, attempt}
	case pluginPhaseTypeDecrypting:
		return &phaseDecrypting{u.plugin, attempt}
	case pluginPhaseTypeFinished:
		return &phaseFinished{u.plugin, attempt}
	default:
		panic(fmt.Sprintf("unknown pluginStateType: %v", pluginStateType))
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: DEALING

// Create a fresh initial dealing and disseminate it as a blob if haven't done yet for the current attempt,
// otherwise reuse the existing one.
func (p *phaseDealing) Observation(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	kvReader ocr3_1types.KeyValueStateReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocrtypes.Observation, error) {
	blobHandle, err := p.state.MemoizedOutboundInitialDealingBlobHandle(ctx, seqNr, p.attempt, blobBroadcastFetcher, p.rand)
	if err != nil {
		return nil, err
	}

	observation, err := blobHandle.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal blob handle to binary: %w", err)
	}
	return observation, nil
}

// Validate the initial dealing from an unbanned dealer, and cache the verified initial dealing for state transition.
func (p *phaseDealing) ValidateObservation(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	ao ocrtypes.AttributedObservation, kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	bannedDealers, err := p.state.ReadBannedDealers(kvReader)
	if err != nil {
		return err
	}

	// Should reject observations from banned dealers.
	if bannedDealers[ao.Observer] {
		return fmt.Errorf("banned dealer %d attempted to submit observation", ao.Observer)
	}

	// Fetch the blob unverifiedInitialDealingBytes by the blob handle in the observation.
	blobHandle := ocr3_1types.BlobHandle{}
	if err := blobHandle.UnmarshalBinary(ao.Observation); err != nil {
		return fmt.Errorf("failed to unmarshal blob handle: %w", err)
	}
	unverifiedInitialDealingBytes, err := blobFetcher.FetchBlob(ctx, blobHandle)
	if err != nil {
		return fmt.Errorf("failed to fetch initial dealing blob: %w", err)
	}

	// The observer is the dealer who sent out the initial dealing.
	dealer := int(ao.Observer)

	// Check if we have already cached the verified initial dealing from this dealer for the current attempt, otherwise
	// unmarshal and verify it and cache it.
	_, err = p.state.MemoizedInboundVerifiedInitialDealing(ctx, p.attempt, dealer, unverifiedInitialDealingBytes)
	return err
}

// Require at least dkg.DealingsThreshold() valid initial dealings to move to the next state.
func (p *phaseDealing) ObservationQuorum(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	aos []ocrtypes.AttributedObservation, kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	cryptoProvider, err := p.state.MemoizedCryptoProvider(ctx, p.attempt)
	if err != nil {
		return false, err
	}
	return len(aos) >= cryptoProvider.DealingsThreshold(), nil
}

// Prepares the state transition that writes the initial dealings to the kv store and moves to the next state of
// decrypting.
func (p *phaseDealing) StateTransition(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery, aos []ocrtypes.AttributedObservation,
	kvWriter ocr3_1types.KeyValueStateReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	cryptoProvider, err := p.state.MemoizedCryptoProvider(ctx, p.attempt)
	if err != nil {
		return nil, err
	}

	dealings := make(plugintypes.InitialDealings, len(p.dealers))

	// Only keep the first dkg.DealingsThreshold() dealings selected in the proposal by the leader.
	// The ordering of aos is consistent guaranteed by OCR.
	for i := 0; i < cryptoProvider.DealingsThreshold(); i++ {
		blobHandle := ocr3_1types.BlobHandle{}
		if err := blobHandle.UnmarshalBinary(aos[i].Observation); err != nil {
			return nil, fmt.Errorf("failed to unmarshal blob handle: %w", err)
		}
		unverifiedInitialDealingBytes, err := blobFetcher.FetchBlob(ctx, blobHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch initial dealing blob: %w", err)
		}

		// Recover the verified initial dealing from cache if exists, otherwise unmarshal and verify it and cache it.
		dealer := int(aos[i].Observer)
		dealings[int(dealer)], err = p.state.MemoizedInboundVerifiedInitialDealing(
			ctx, p.attempt, dealer, unverifiedInitialDealingBytes,
		)
		if err != nil {
			return nil, err
		}
	}

	// Write the initial dealings to the key/value store.
	if _, err := p.state.WriteInitialDealings(kvWriter, p.attempt, dealings); err != nil {
		return nil, err
	}

	// Move to the next state of decrypting by writing to the kv store.
	newPhase := &phaseDecrypting{p.DKGPlugin, p.attempt}
	if _, err := p.state.WritePhase(kvWriter, newPhase); err != nil {
		return nil, err
	}

	p.logger.Info("🚀🚀🚀 DKGPlugin: received enough initial dealings", nil)
	return nil, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: DECRYPTING

// Generate decryption key shares for the committed initial dealings, and disseminate them as observations.
func (p *phaseDecrypting) Observation(ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	kvReader ocr3_1types.KeyValueStateReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocrtypes.Observation, error) {
	cryptoProvider, err := p.state.MemoizedCryptoProvider(ctx, p.attempt)
	if err != nil {
		return nil, err
	}

	dealings, err := p.state.ReadInitialDealings(kvReader, p.attempt)
	if err != nil {
		return nil, err
	}

	// Generate the decryption key shares for the initial dealings as observation.
	shares, err := cryptoProvider.DecryptDecryptionKeyShares(dealings)
	if err != nil {
		return nil, err
	}

	sharesMarshaled, err := codec.Marshal(shares.AsUnverifiedShares())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decryption key shares: %w", err)
	}

	observation := sharesMarshaled
	return observation, nil
}

// Validate the decryption key shares from a dealer, and cache the verified version for state transition.
func (p *phaseDecrypting) ValidateObservation(ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	ao ocrtypes.AttributedObservation, kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	initialDealings, err := p.state.ReadInitialDealings(kvReader, p.attempt)
	if err != nil {
		return fmt.Errorf("expected to have a list of verified initial dealing ready at this phase: %w", err)
	}

	dealer := int(ao.Observer)
	_, err = p.state.MemoizedInboundVerifiedDecryptionKeyShares(ctx, p.attempt, initialDealings, ao.Observation, dealer)
	return err
}

// Require at least dkg.DecryptionThreshold() valid decryption key shares to decrypt inner dealings and move to the next
// state.
func (p *phaseDecrypting) ObservationQuorum(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery, aos []ocrtypes.AttributedObservation,
	kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	cryptoProvider, err := p.state.MemoizedCryptoProvider(ctx, p.attempt)
	if err != nil {
		return false, err
	}
	return len(aos) >= cryptoProvider.DecryptionThreshold(), nil
}

// Recovers the inner dealings by the valid decryption key shares, writes them to kv store, and move to the next state.
func (p *phaseDecrypting) StateTransition(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery, aos []ocrtypes.AttributedObservation,
	kvWriter ocr3_1types.KeyValueStateReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	cryptoProvider, err := p.state.MemoizedCryptoProvider(ctx, p.attempt)
	if err != nil {
		return nil, err
	}

	initialDealings, err := p.state.ReadInitialDealings(kvWriter, p.attempt)
	if err != nil {
		return nil, fmt.Errorf("expected to have a list of verified initial dealing ready at this phase: %w", err)
	}

	// Populate the decryption key shares, but only keep the first dkg.DecryptionThreshold() values select in the
	// proposal by the leader, which will be sufficient for decryption.
	decryptionKeySharesForRecovery := make(plugintypes.DecryptionKeyShares, len(p.dealers))

	for i := 0; i < cryptoProvider.DecryptionThreshold(); i++ {
		ao := aos[i]
		dealer := int(ao.Observer)
		verifiedShares, err := p.state.MemoizedInboundVerifiedDecryptionKeyShares(
			ctx, p.attempt, initialDealings, ao.Observation, dealer,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get verified decryption key shares %w, this should never happen", err,
			)
		}
		decryptionKeySharesForRecovery[dealer] = verifiedShares
	}

	// Recover the inner dealings from the list of valid decryption key shares.
	innerDealings, freshlyBannedDealersIndices, restart, err := cryptoProvider.RecoverInnerDealings(
		initialDealings, decryptionKeySharesForRecovery,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to recover inner dealings: %w", err)
	}

	// Retrieve the old banned dealers list and merge it with the freshly banned dealers.
	oldBannedDealers, err := p.state.ReadBannedDealers(kvWriter)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve banned dealers list: %w", err)
	}
	newBannedDealers := append(plugintypes.BannedDealers{}, oldBannedDealers...)
	for _, freshlyBannedDealerIndex := range freshlyBannedDealersIndices {
		newBannedDealers[freshlyBannedDealerIndex] = true
	}

	numBannedDealers := 0
	for _, isBanned := range newBannedDealers {
		if isBanned {
			numBannedDealers++
		}
	}

	if numBannedDealers > p.f_D {
		return nil, fmt.Errorf("number of banned dealers %d exceeds tolerated f_D %d", numBannedDealers, p.f_D)
	}

	// Write the inner dealings, the decryption key shares and the updated banned dealers list to the kv store.
	if _, err := p.state.WriteDecryptionKeyShares(kvWriter, p.attempt, decryptionKeySharesForRecovery); err != nil {
		return nil, err
	}
	if _, err := p.state.WriteInnerDealings(kvWriter, p.attempt, innerDealings); err != nil {
		return nil, err
	}
	if _, err := p.state.WriteBannedDealers(kvWriter, newBannedDealers); err != nil {
		return nil, err
	}

	if restart {
		// There exists an invalid inner dealing, need to restart the DKG from scratch. Move to the initial state of
		// dealing by writing to the key/value store. Increase the attempt number by 1.
		newPhase := &phaseDealing{p.DKGPlugin, p.attempt + 1}
		if _, err := p.state.WritePhase(kvWriter, newPhase); err != nil {
			return nil, err
		}
		p.logger.Info("🚀 DKGPlugin: restart from scratch", nil)
		return nil, nil
	}

	// All good, the inner dealings are recovered successfully. Let's finish the DKG.
	reportsPlusPrecursor, err := p.state.MemoizedReportsPlusPrecursor(ctx, p.attempt, innerDealings, p.pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DKG result package: %w", err)
	}

	// All the inner dealings are valid, move to the finished state by writing to the kv store.
	newState := &phaseFinished{p.DKGPlugin, p.attempt}
	if _, err = p.state.WritePhase(kvWriter, newState); err != nil {
		return nil, err
	}

	p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", commontypes.LogFields{
		"seqNr": seqNr,
	})
	return reportsPlusPrecursor, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: FINISHED

// Nothing needed to be sent via observation after DKG result is committed.
func (p *phaseFinished) Observation(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery, kvReader ocr3_1types.KeyValueStateReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (ocrtypes.Observation, error) {
	return nil, nil
}

// Nothing needed to be validated after DKG result is committed.
func (p *phaseFinished) ValidateObservation(
	ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery, ao ocrtypes.AttributedObservation,
	kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	return nil
}

// Any amount of observations not exceeding n-f should be good enough to retransmit the DKG result.
// Require a Byzantine quorum of observations just to avoid the OCR from proceeding too fast.
func (p *phaseFinished) ObservationQuorum(ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	aos []ocrtypes.AttributedObservation, kvReader ocr3_1types.KeyValueStateReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	return quorumhelper.ObservationCountReachesObservationQuorum(
		quorumhelper.QuorumByzQuorum, len(p.dealers), p.f_D, aos,
	), nil
}

// Retransmit the cached result package every 5 OCR rounds (seqNr).
func (p *phaseFinished) StateTransition(ctx context.Context, seqNr uint64, aq ocrtypes.AttributedQuery,
	aos []ocrtypes.AttributedObservation, kvWriter ocr3_1types.KeyValueStateReadWriter,
	blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	innerDealings, err := p.state.ReadInnerDealings(kvWriter, p.attempt)
	if err != nil {
		return nil, fmt.Errorf("expected to have a list of verified inner dealings ready at this phase: %w", err)
	}

	if seqNr%transmitFrequency == 0 {
		return p.state.MemoizedReportsPlusPrecursor(ctx, p.attempt, innerDealings, p.pluginConfig)
	}
	return nil, nil
}
