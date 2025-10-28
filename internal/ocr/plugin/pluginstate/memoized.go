package pluginstate

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
)

// Returns the crypto provider (DKG instance) if already set, otherwise tries to initialize it using the provided
// initCryptoProviderFunc (referring to plugin.initCryptoProvider).
func (s *PluginState) MemoizedCryptoProvider(ctx context.Context, attempt int) (dkg.DKG, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cryptoProvider != nil && attempt == s.cryptoProvider.Attempt() {
		return s.cryptoProvider, nil
	}

	// Crypto provider was not yet set. Lets try to initialize it.
	var err error
	s.cryptoProvider, err = s.initCryptoProviderFunc(ctx, attempt)
	if err != nil {
		return nil, fmt.Errorf("crypto provider not set, and not retrievable yet: %w", err)
	}
	return s.cryptoProvider, nil
}

// Retrieves an outbound initial dealing from cache if exists. Note that individual outbound initial dealings are not
// persisted to the key/value store, only cached in memory.
func (s *PluginState) MemoizedOutboundInitialDealingBlobHandle(
	ctx context.Context, seqNr uint64, attempt int, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher,
	rand io.Reader,
) (ocr3_1types.BlobHandle, error) {
	key := outboundInitialDealingsCacheKey{attempt}
	s.mu.RLock()
	val, ok := s.outboundInitialDealingsCache[key]
	s.mu.RUnlock()
	if ok {
		return val, nil
	}

	// We haven't created and broadcasted an initial dealing for this attempt yet.
	// Let's create a fresh initial dealing now.
	cryptoProvider, err := s.MemoizedCryptoProvider(ctx, attempt)
	if err != nil {
		return ocr3_1types.BlobHandle{}, err
	}

	dealing, err := cryptoProvider.Deal(rand)
	if err != nil {
		return ocr3_1types.BlobHandle{}, fmt.Errorf("failed to generate initial dealing: %w", err)
	}

	// Serialize the dealing as an unverified dealing for broadcasting as a blob.
	dealingBytes, err := codec.Marshal(dealing.AsUnverifiedDealing())
	if err != nil {
		return ocr3_1types.BlobHandle{}, fmt.Errorf("failed to marshal unverified initial dealing: %w", err)
	}

	blobExpirationHint := ocr3_1types.BlobExpirationHintSequenceNumber{seqNr}
	blobHandle, err := blobBroadcastFetcher.BroadcastBlob(ctx, dealingBytes, blobExpirationHint)
	if err != nil {
		return ocr3_1types.BlobHandle{}, fmt.Errorf(
			"failed to disseminate initial dealing via blob broadcast: %w", err,
		)
	}

	s.mu.Lock()
	s.outboundInitialDealingsCache[key] = blobHandle
	s.mu.Unlock()

	return blobHandle, nil
}

// Retrieve a verified initial dealing from cache if exists. Note that individual verified dealings are not persisted to
// the key/value store, only cached in memory.
func (s *PluginState) MemoizedInboundVerifiedInitialDealing(
	ctx context.Context, attempt int, dealer int, unverifiedInitialDealingBytes []byte,
) (dkg.VerifiedInitialDealing, error) {
	key := inboundInitialDealingsCacheKey{attempt, dealer}
	s.mu.RLock()
	entry, exists := s.inboundDealingCache[key]
	s.mu.RUnlock()
	if exists && bytes.Equal(entry.raw, unverifiedInitialDealingBytes) {
		return entry.verified, nil
	}

	cryptoProvider, err := s.MemoizedCryptoProvider(ctx, attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto provider: %w", err)
	}

	// Value not found in cache.
	unverifiedInitialDealing, err := codec.Unmarshal(unverifiedInitialDealingBytes, dkg.NewUnverifiedInitialDealing())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial dealing: %w", err)
	}

	verifiedInitialDealing, err := cryptoProvider.VerifyInitialDealing(unverifiedInitialDealing, dealer)
	if err != nil {
		// TODO: Think about extended banning techniques (in the plugin logic).
		return nil, fmt.Errorf("failed to verify initial dealing from dealer %d: %w", dealer, err)
	}

	s.mu.Lock()
	s.inboundDealingCache[key] = inboundInitialDealingsCacheValue{unverifiedInitialDealingBytes, verifiedInitialDealing}
	s.mu.Unlock()

	return verifiedInitialDealing, nil
}

func (s *PluginState) MemoizedInboundVerifiedDecryptionKeyShares(
	ctx context.Context, attempt int, initialDealings plugintypes.InitialDealings,
	unverifiedDecryptionKeySharesBytes []byte, dealer int,
) (dkg.VerifiedDecryptionKeySharesForInnerDealings, error) {
	key := inboundDecryptionKeySharesCacheKey{attempt, dealer}
	s.mu.RLock()
	entry, exists := s.inboundDecryptionKeySharesCache[key]
	s.mu.RUnlock()

	if exists && bytes.Equal(entry.raw, unverifiedDecryptionKeySharesBytes) {
		return entry.verified, nil
	}

	unverifiedDecryptionKeyShares, err := codec.Unmarshal(
		unverifiedDecryptionKeySharesBytes, dkg.NewUnverifiedDecryptionKeySharesForInnerDealings(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal decryption key shares: %w", err)
	}

	cryptoProvider, err := s.MemoizedCryptoProvider(ctx, attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto provider: %w", err)
	}

	verifiedDecryptionKeyShares, err := cryptoProvider.VerifyDecryptionKeyShares(
		initialDealings, unverifiedDecryptionKeyShares, dealer,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify decryption key shares from dealer %d: %w", dealer, err)
	}

	s.mu.Lock()
	s.inboundDecryptionKeySharesCache[key] = inboundDecryptionKeySharesCacheValue{
		unverifiedDecryptionKeySharesBytes, verifiedDecryptionKeyShares,
	}
	s.mu.Unlock()

	return verifiedDecryptionKeyShares, nil
}

func (s *PluginState) MemoizedReportsPlusPrecursor(
	ctx context.Context, attempt int, innerDealings plugintypes.InnerDealings,
	config *dkgocrtypes.ReportingPluginConfig,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	s.mu.RLock()
	value := s.cachedReportsPlusPrecursor
	s.mu.RUnlock()
	if value != nil {
		return value, nil
	}

	cryptoProvider, err := s.MemoizedCryptoProvider(ctx, attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto provider: %w", err)
	}

	result, err := cryptoProvider.NewResult(innerDealings)
	if err != nil {
		return nil, fmt.Errorf("failed to compute DKG result: %w", err)
	}

	resultPackage := plugintypes.ResultPackage{result, config}

	// Make a report out of the result package.
	reportsPlusPrecursor, err := resultPackage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DKG result package: %w", err)
	}

	s.mu.Lock()
	s.cachedReportsPlusPrecursor = reportsPlusPrecursor
	s.mu.Unlock()

	return reportsPlusPrecursor, nil
}
