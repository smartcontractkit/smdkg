package plugin

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/libocr/quorumhelper"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
)

type stateMachineState int

const (
	stateDealing    stateMachineState = iota // the initial state of a dkg round, to send out initial dealings
	stateDecrypting                          // received enough valid initial dealings and written to kv store, to send out decryption key shares in this state
	stateFinished                            // gathered enough valid inner dealings and written to kv store, the dkg instance should have the result ready in this state and conclude
)

type state interface {
	observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader,
		blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
	) (types.Observation, error)

	validateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
	) error

	observationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
	) (bool, error)

	stateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
	) (ocr3_1types.ReportsPlusPrecursor, error)
}

type (
	stateMachineDealing struct {
		p       *DKGPlugin
		attempt int
	}

	stateMachineDecrypting struct {
		p       *DKGPlugin
		attempt int
	}

	stateMachineFinished struct {
		p       *DKGPlugin
		attempt int
	}
)

var (
	_ state = &stateMachineDealing{}
	_ state = &stateMachineDecrypting{}
	_ state = &stateMachineFinished{}
)

func (s *stateMachineDealing) observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return nil, err
	}

	return s.p.cache.getInitialDealingBlobHandleBytes(ctx, seqNr, blobBroadcastFetcher, dkgInstance, s.p.rand)
}

func (s *stateMachineDealing) validateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return err
	}

	if s.attempt > 0 {
		bannedDealers, err := s.p.readBannedDealers(keyValueReader)
		if err != nil {
			return err
		}

		// Should reject observations from banned dealers
		if bannedDealers[ao.Observer] {
			return fmt.Errorf("banned dealer %d attempted to submit observation", ao.Observer)
		}
	}

	blobHandle := &ocr3_1types.BlobHandle{}
	err = blobHandle.UnmarshalBinary(ao.Observation)
	if err != nil {
		return fmt.Errorf("failed to unmarshal blob handle: %w", err)
	}

	payload, err := blobFetcher.FetchBlob(ctx, *blobHandle)
	if err != nil {
		return fmt.Errorf("failed to fetch initial dealing blob: %w", err)
	}

	initialDealing, err := codec.Unmarshal(payload, dkg.NewUnverifiedInitialDealing())
	if err != nil {
		return fmt.Errorf("failed to unmarshal initial dealing: %w", err)
	}

	verifiedInitialDealing, err := dkgInstance.VerifyInitialDealing(initialDealing, int(ao.Observer))
	if err != nil {
		return fmt.Errorf("failed to verify initial dealing from dealer %d: %w", ao.Observer, err)
	}

	s.p.cache.cacheVerifiedInitialDealing(int(ao.Observer), ao.Observation, verifiedInitialDealing)
	return nil
}

func (s *stateMachineDealing) observationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return false, err
	}
	return len(aos) >= dkgInstance.DealingsThreshold(), nil
}

// Prepares the state transition of writing the received initial dealings to kv store, and moving to the next state;
// prepares the report
func (s *stateMachineDealing) stateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return nil, err
	}

	dealings := make([]dkg.VerifiedInitialDealing, len(s.p.dkgConfig.dealers))

	// Only keep the first dkg.DealingsThreshold() dealings selected in the proposal by the leader
	// The ordering of aos is consistent guaranteed by OCR
	for i := 0; i < dkgInstance.DealingsThreshold(); i++ {
		var err error

		blobHandle := &ocr3_1types.BlobHandle{}
		err = blobHandle.UnmarshalBinary(aos[i].Observation)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal blob handle: %w", err)
		}

		payload, err := blobFetcher.FetchBlob(ctx, *blobHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch initial dealing blob: %w", err)
		}

		dealings[aos[i].Observer], err = s.p.cache.recoverVerifiedInitialDealing(dkgInstance, int(aos[i].Observer), payload)
		if err != nil {
			return nil, err
		}
	}

	if err := s.p.writeInitialDealings(keyValueReadWriter, s.attempt, dealings); err != nil {
		return nil, err
	}

	newState := pluginState{stateDecrypting, s.attempt}
	if err := s.p.writePluginState(keyValueReadWriter, &newState); err != nil {
		return nil, err
	}

	s.p.logger.Info("🚀🚀🚀 DKGPlugin: received enough initial dealings", commontypes.LogFields{})

	return nil, nil
}

func (s *stateMachineDecrypting) observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return nil, err
	}

	dealings, err := s.p.readInitialDealings(keyValueReader, s.attempt)
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

func (s *stateMachineDecrypting) validateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return err
	}

	dealings, err := s.p.readInitialDealings(keyValueReader, s.attempt)
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

	s.p.cache.cacheVerifiedDecryptionKeyShares(int(ao.Observer), ao.Observation, verifiedDecryptionKeyShares)
	return nil
}

func (s *stateMachineDecrypting) observationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return false, err
	}
	return len(aos) >= dkgInstance.DecryptionThreshold(), nil
}

func (s *stateMachineDecrypting) stateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
	if err != nil {
		return nil, err
	}

	dealings, err := s.p.readInitialDealings(keyValueReadWriter, s.attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to read received initial dealings: %w", err)
	}

	decryptionKeyShares := make(decryptionKeyShares, len(s.p.dkgConfig.dealers))
	for i, ao := range aos {
		var err error
		decryptionKeyShares[ao.Observer], err = s.p.cache.recoverVerifiedDecryptionKeyShares(dkgInstance, dealings, int(ao.Observer), ao.Observation)
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

	bannedDealers, err := s.p.readBannedDealers(keyValueReadWriter)
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers: %w", err)
	}
	for _, bannedDealer := range bannedList {
		bannedDealers[bannedDealer] = true
	}

	if err := s.p.writeRecoveredInnerDealings(keyValueReadWriter, s.attempt, decryptionKeyShares, innerDealings, bannedDealers); err != nil {
		return nil, err
	}

	if restart {
		newState := pluginState{stateDealing, s.attempt + 1}
		if err := s.p.writePluginState(keyValueReadWriter, &newState); err != nil {
			return nil, err
		}

		s.p.cache.clearCaches()

		s.p.logger.Info("🚀 DKGPlugin: restart from scratch", commontypes.LogFields{})
		return nil, nil
	} else {
		newState := pluginState{stateFinished, s.attempt}
		if err := s.p.writePluginState(keyValueReadWriter, &newState); err != nil {
			return nil, err
		}

		reportsPlusPrecursor, err := s.p.cache.getReportsPlusPrecursor(ctx, dkgInstance, innerDealings, s.p.pluginConfig)
		if err != nil {
			return nil, err
		}

		s.p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", commontypes.LogFields{})
		return reportsPlusPrecursor, nil
	}
}

func (s *stateMachineFinished) observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	// Nothing needed to be sent via observation after DKG result is committed
	return nil, nil
}

func (s *stateMachineFinished) validateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	return nil
}

func (s *stateMachineFinished) observationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	// Any amount of observations not exceeding n-f should be good.
	// Require a Byzantine quorum of observations just to avoid the OCR from proceeding too fast.
	return quorumhelper.ObservationCountReachesObservationQuorum(quorumhelper.QuorumByzQuorum, len(s.p.dkgConfig.dealers), s.p.dkgConfig.f_D, aos), nil
}

// Transmit DKG result to the db every 5 OCR rounds (seqNr)
const transmitFrequency = 5

func (s *stateMachineFinished) stateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	if seqNr%transmitFrequency == 0 {
		dkgInstance, err := s.p.cache.getDKGInstance(ctx, s.p.dkgConfig)
		if err != nil {
			return nil, err
		}

		dealings, err := s.p.readInnerDealings(keyValueReadWriter, s.attempt)
		if err != nil {
			return nil, fmt.Errorf("failed to read received initial dealings: %w", err)
		}

		return s.p.cache.getReportsPlusPrecursor(ctx, dkgInstance, dealings, s.p.pluginConfig)
	}
	return nil, nil
}
