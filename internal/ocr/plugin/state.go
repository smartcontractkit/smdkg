package plugin

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/libocr/quorumhelper"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
)

// Implementation of observation, validateObservation, observationQuorum, stateTransition for each state of the DKG
// plugin.

// For length of the following slices always match the number of dealers. Some values may be nil, meaning we do not have
// data for that particular dealer.
type bannedDealers []bool
type initialDealings []dkg.VerifiedInitialDealing
type decryptionKeyShares []dkg.VerifiedDecryptionKeySharesForInnerDealings
type innerDealings []dkg.VerifiedInnerDealing

type pluginStateType int

const (
	_ pluginStateType = iota

	// The initial state of a DKG round. In this state, the initial dealings are sent out.
	pluginStateTypeDealing

	// The protocol has gathered enough valid initial dealings (and has written them to the key/value store). It
	// proceeds to send out decryption key shares in this state.
	pluginStateTypeDecrypting

	// The protocol has gathered enough valid inner dealings (and has written them to key/value store). In this state,
	// the DKG's result is ready and the DKG is finished.
	pluginStateTypeFinished
)

var _ codec.Unmarshaler[pluginState] = pluginStateUnmarshaler{nil}

var _ pluginState = &pluginStateDealing{}
var _ pluginState = &pluginStateDecrypting{}
var _ pluginState = &pluginStateFinished{}

type pluginState interface {
	codec.Marshaler

	observation(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader,
		blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
	) (types.Observation, error)

	validateObservation(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
	) error

	observationQuorum(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
	) (bool, error)

	stateTransition(
		ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
		keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
	) (ocr3_1types.ReportsPlusPrecursor, error)
}

type pluginStateDealing struct {
	*DKGPlugin
	attempt int
}

type pluginStateDecrypting struct {
	*DKGPlugin
	attempt int
}

type pluginStateFinished struct {
	*DKGPlugin
	attempt int
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: DEALING

// Create a fresh initial dealing and disseminate it as a blob if haven't done yet for the current attempt,
// otherwise reuse the existing one.
func (p *pluginStateDealing) observation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	// Try to reuse existing initial dealing if any.
	ob := p.cache.getInitialDealingBlobHandleBytes(p.attempt)

	if ob == nil {
		// Get the dkg instance.
		dkgInstance, err := p.getDKG(ctx)
		if err != nil {
			return nil, err
		}

		// Create and broadcast one if not exists yet. Shall not send the same blob for different attempts, otherwise
		// the DKG result could be biased by the adversary.
		payload, err := deal(dkgInstance, p.rand)
		if err != nil {
			return nil, fmt.Errorf("failed to generate initial dealing: %w", err)
		}

		// Broadcast the initial dealing as a blob and get the marshalled blob handle as observation.
		ob, err = disseminateBlob(ctx, seqNr, blobBroadcastFetcher, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to disseminate payload by blob: %w", err)
		}

		// Cache the blob handle for this attempt, just in case the nodes don't gather enough valid initial dealings in
		// this round.
		p.cache.putInitialDealingBlobHandleBytes(p.attempt, ob)
	}

	return ob, nil
}

// Validate the initial dealing from an unbanned dealer, and cache the verified initial dealing for state transition.
func (p *pluginStateDealing) validateObservation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	// Read the committed banned dealers list from cache if any.
	bannedDealers := p.cache.getCommittedBannedDealers(p.attempt)
	if bannedDealers == nil {
		// Not in cache, read from the kv store.
		var err error
		bannedDealers, err = p.readOrInitializeBannedDealers(keyValueReader)
		if err != nil {
			return err
		}
		// Cache it for future use.
		p.cache.putCommittedBannedDealers(p.attempt, bannedDealers)
	}

	// Should reject observations from banned dealers.
	if bannedDealers[ao.Observer] {
		return fmt.Errorf("banned dealer %d attempted to submit observation", ao.Observer)
	}

	// Fetch the blob payload by the blob handle in the observation.
	payload, err := fetchBlobPayload(ctx, blobFetcher, ao.Observation)
	if err != nil {
		return fmt.Errorf("failed to get payload from blob handle: %w", err)
	}

	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return err
	}

	// Verify the initial dealing and cache it for avoiding redundant verification.
	_, err = p.recoverVerifiedInitialDealing(dkgInstance, payload, int(ao.Observer))
	if err != nil {
		return fmt.Errorf("failed to recover verified initial dealing from dealer %d: %w", ao.Observer, err)
	}

	return nil
}

// Require at least dkg.DealingsThreshold() valid initial dealings to move to the next state.
func (p *pluginStateDealing) observationQuorum(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return false, err
	}

	return len(aos) >= dkgInstance.DealingsThreshold(), nil
}

// Recover a verified initial dealing from cache if exists.
// Otherwise unmarshal and verify the dealing, and cache it.
func (p *pluginStateDealing) recoverVerifiedInitialDealing(
	dkgInstance dkg.DKG, marshaled []byte, dealer int,
) (dkg.VerifiedInitialDealing, error) {
	dealing := p.cache.getVerifiedInitialDealing(p.attempt, len(p.dealers), dealer, marshaled)
	if dealing == nil {
		dealing, err := verifyInitialDealing(dkgInstance, marshaled, dealer)
		if err != nil {
			return nil, fmt.Errorf("failed to verify initial dealing from dealer %d: %w", dealer, err)
		}
		p.cache.putVerifiedInitialDealing(p.attempt, len(p.dealers), dealer, marshaled, dealing)
	}
	return dealing, nil
}

// Prepares the state transition that writes the initial dealings to the kv store and moves to the next state of
// decrypting.
func (p *pluginStateDealing) stateTransition(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
	keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return nil, err
	}

	dealings := make(initialDealings, len(p.dealers))

	// Only keep the first dkg.DealingsThreshold() dealings selected in the proposal by the leader.
	// The ordering of aos is consistent guaranteed by OCR.
	for i := 0; i < dkgInstance.DealingsThreshold(); i++ {
		var err error

		// Fetch the blob payload by the blob handle in the observation.
		payload, err := fetchBlobPayload(ctx, blobFetcher, aos[i].Observation)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch initial dealing blob: %w", err)
		}

		// Recover the verified initial dealing from cache if exists, otherwise unmarshal and verify it and cache it.
		observer := aos[i].Observer
		dealings[int(observer)], err = p.recoverVerifiedInitialDealing(dkgInstance, payload, int(observer))
		if err != nil {
			return nil, fmt.Errorf("failed to recover verified initial dealing from dealer %d: %w", observer, err)
		}
	}

	// Write the received initial dealings to the kv store.
	if _, err := p.writeInitialDealings(keyValueReadWriter, p.attempt, dealings); err != nil {
		return nil, err
	}

	// Move to the next state of decrypting by writing to the kv store.
	newState := &pluginStateDecrypting{p.DKGPlugin, p.attempt}
	if _, err := p.writePluginState(keyValueReadWriter, newState); err != nil {
		return nil, err
	}

	p.logger.Info("🚀🚀🚀 DKGPlugin: received enough initial dealings", nil)

	return nil, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: DECRYPTING

// Generate decryption key shares for the committed initial dealings, and disseminate them as observations.
func (p *pluginStateDecrypting) observation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	keyValueReader ocr3_1types.KeyValueReader, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	// Get the committed initial dealings.
	dealings, err := p.getCommittedInitialDealings(keyValueReader)
	if err != nil {
		return nil, err
	}

	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return nil, err
	}

	// Generate the decryption key shares for the initial dealings as observation.
	ob, err := decryptDecryptionKeyShares(dkgInstance, dealings)
	if err != nil {
		return nil, err
	}

	return ob, nil
}

// Validate the decryption key shares from a dealer, and cache the verified version for state transition.
func (p *pluginStateDecrypting) validateObservation(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	ao types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	// Get the committed initial dealings.
	dealings, err := p.getCommittedInitialDealings(keyValueReader)
	if err != nil {
		return err
	}

	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return err
	}

	// Verify the decryption key shares and cache the verified version.
	_, err = p.recoverVerifiedDecryptionKeySharesForInnerDealings(
		dkgInstance, dealings, ao.Observation, int(ao.Observer),
	)
	if err != nil {
		return fmt.Errorf("failed to verify decryption key shares from dealer %d: %w", ao.Observer, err)
	}

	return nil
}

// Require at least dkg.DecryptionThreshold() valid decryption key shares to decrypt inner dealings and move to the next
// state.
func (p *pluginStateDecrypting) observationQuorum(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
	keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return false, err
	}

	return len(aos) >= dkgInstance.DecryptionThreshold(), nil
}

func (p *pluginStateDecrypting) getCommittedInitialDealings(
	keyValueReader ocr3_1types.KeyValueReader,
) (initialDealings, error) {
	// Read the committed initial dealings from cache if any.
	dealings := p.cache.getCommittedInitialDealings(p.attempt)
	if dealings == nil {
		// Not in cache, read from the kv store.
		var err error
		dealings, err = p.readInitialDealings(keyValueReader, p.attempt)
		if err != nil {
			return nil, err
		}
		// Cache it for future use.
		p.cache.putCommittedInitialDealings(p.attempt, dealings)
	}
	return dealings, nil
}

// Recover a verified decryption key shares from cache if exists.
// Otherwise unmarshal and verify the shares, and cache it.
func (p *pluginStateDecrypting) recoverVerifiedDecryptionKeySharesForInnerDealings(
	dkgInstance dkg.DKG, dealings initialDealings, raw []byte, dealer int,
) (dkg.VerifiedDecryptionKeySharesForInnerDealings, error) {
	decryptionShares := p.cache.getVerifiedDecryptionKeyShares(p.attempt, len(p.dealers), dealer, raw)

	if decryptionShares == nil {
		decryptionShares, err := verifyDecryptionKeyShares(dkgInstance, dealings, raw, dealer)
		if err != nil {
			return nil, err
		}

		p.cache.putVerifiedDecryptionKeyShares(p.attempt, len(p.dealers), dealer, raw, decryptionShares)
	}
	return decryptionShares, nil
}

// Recovers the inner dealings by the valid decryption key shares, writes them to kv store, and move to the next state.
func (p *pluginStateDecrypting) stateTransition(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, aos []types.AttributedObservation,
	keyValueReadWriter ocr3_1types.KeyValueReadWriter, blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	// Get the committed initial dealings.
	dealings, err := p.getCommittedInitialDealings(keyValueReadWriter)
	if err != nil {
		return nil, err
	}

	// Get the dkg instance.
	dkgInstance, err := p.getDKG(ctx)
	if err != nil {
		return nil, err
	}

	decryptionKeyShares := make(decryptionKeyShares, len(p.dealers))

	// Only keep the first dkg.DecryptionThreshold() decryption key shares selected in the proposal by the leader, which
	// will be sufficient for decryption.
	for i := 0; i < dkgInstance.DecryptionThreshold(); i++ {
		decryptionKeyShares[int(aos[i].Observer)], err = p.recoverVerifiedDecryptionKeySharesForInnerDealings(
			dkgInstance, dealings, aos[i].Observation, int(aos[i].Observer),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to recover verified decryption key shares from dealer %d: %w", aos[i].Observer, err,
			)
		}
	}

	// Recover the inner dealings by the valid decryption key shares.
	innerDealings, bannedList, restart, err := dkgInstance.RecoverInnerDealings(dealings, decryptionKeyShares)
	if err != nil {
		return nil, fmt.Errorf("failed to recover inner dealings: %w", err)
	}

	// Read the committed banned dealers list from cache if any.
	bannedDealers := p.cache.getCommittedBannedDealers(p.attempt)
	if bannedDealers == nil {
		// Not in cache, read from the kv store.
		var err error
		bannedDealers, err = p.readOrInitializeBannedDealers(keyValueReadWriter)
		if err != nil {
			return nil, err
		}
		// Cache it for future use.
		p.cache.putCommittedBannedDealers(p.attempt, bannedDealers)
	}

	// Update the banned dealers list.
	for _, bannedDealer := range bannedList {
		bannedDealers[bannedDealer] = true
	}

	// Write the decryption key shares, the recovered inner dealings and the updated banned dealers list to the
	// key/value store.
	if _, err = p.writeDecryptionKeyShares(keyValueReadWriter, p.attempt, decryptionKeyShares); err != nil {
		return nil, fmt.Errorf("failed to write decryption key shares: %w", err)
	}
	if _, err = p.writeInnerDealings(keyValueReadWriter, p.attempt, innerDealings); err != nil {
		return nil, fmt.Errorf("failed to write inner dealings: %w", err)
	}
	if _, err = p.writeBannedDealers(keyValueReadWriter, bannedDealers); err != nil {
		return nil, fmt.Errorf("failed to write banned dealers: %w", err)
	}

	if restart {
		// There exists invalid inner dealing, need to restart the DKG from scratch. Move to the initial state of
		// dealing by writing to the key/value store. Increase the attempt number by 1.
		newState := &pluginStateDealing{p.DKGPlugin, p.attempt + 1}
		if _, err = p.writePluginState(keyValueReadWriter, newState); err != nil {
			return nil, err
		}

		p.logger.Info("🚀 DKGPlugin: restart from scratch", nil)
		return nil, nil
	}

	// All the inner dealings are valid, move to the finished state by writing to the kv store.
	newState := &pluginStateFinished{p.DKGPlugin, p.attempt}
	if _, err = p.writePluginState(keyValueReadWriter, newState); err != nil {
		return nil, err
	}

	// Create the result package as reportsPlusPrecursor.
	reportsPlusPrecursor, err := newResultPackage(dkgInstance, innerDealings, p.pluginConfig)
	if err != nil {
		return nil, err
	}

	// Cache the result package just in case the OCR needs to retransmit it later.
	p.cache.putReportsPlusPrecursor(reportsPlusPrecursor)

	p.logger.Info("🚀🚀🚀🚀🚀 DKGPlugin: gathered enough inner dealings", nil)
	return reportsPlusPrecursor, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Plugin state: FINISHED

// Nothing needed to be sent via observation after DKG result is committed.
func (p *pluginStateFinished) observation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, keyValueReader ocr3_1types.KeyValueReader,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
) (types.Observation, error) {
	return nil, nil
}

// Nothing needed to be validated after DKG result is committed.
func (p *pluginStateFinished) validateObservation(
	ctx context.Context, seqNr uint64, aq types.AttributedQuery, ao types.AttributedObservation,
	keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) error {
	return nil
}

// Any amount of observations not exceeding n-f should be good enough to retransmit the DKG result.
// Require a Byzantine quorum of observations just to avoid the OCR from proceeding too fast.
func (p *pluginStateFinished) observationQuorum(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReader ocr3_1types.KeyValueReader, blobFetcher ocr3_1types.BlobFetcher,
) (bool, error) {
	return quorumhelper.ObservationCountReachesObservationQuorum(
		quorumhelper.QuorumByzQuorum, len(p.dealers), p.f_D, aos,
	), nil
}

// Transmit DKG result to the db every 5 OCR rounds (seqNr)
const transmitFrequency = 5

// Retransmit the cached result package every 5 OCR rounds (seqNr).
func (p *pluginStateFinished) stateTransition(ctx context.Context, seqNr uint64, aq types.AttributedQuery,
	aos []types.AttributedObservation, keyValueReadWriter ocr3_1types.KeyValueReadWriter,
	blobFetcher ocr3_1types.BlobFetcher,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	if seqNr%transmitFrequency == 0 {
		// Try to reuse the cached result package if any.
		reportsPlusPrecursor := p.cache.getReportsPlusPrecursor()

		if reportsPlusPrecursor == nil {
			// If not in cache, read the inner dealings from the kv store and create the result package.
			innerDealings, err := p.readInnerDealings(keyValueReadWriter, p.attempt)
			if err != nil {
				return nil, fmt.Errorf("failed to read received initial dealings: %w", err)
			}

			// Get the dkg instance.
			dkgInstance, err := p.getDKG(ctx)
			if err != nil {
				return nil, err
			}

			// Create the result package as reportsPlusPrecursor.
			reportsPlusPrecursor, err = newResultPackage(dkgInstance, innerDealings, p.pluginConfig)
			if err != nil {
				return nil, err
			}

			// Cache the result package just in case the OCR needs to retransmit it later.
			p.cache.putReportsPlusPrecursor(reportsPlusPrecursor)
		}

		return reportsPlusPrecursor, nil
	}
	return nil, nil
}
