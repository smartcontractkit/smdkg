package plugin

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkg"
)

// Contains all the in-memory cached state for a DKGPlugin, shouldn't be read directly
type cachedValues struct {
	// The DKG instance used for this plugin
	dkg dkg.DKG

	// The blob handle for the initial dealing broadcast
	initialDealingBlobHandleBytes []byte

	// For each dealer (by index), cache the most recently received and verified initial dealing to avoid redundant verification; should be cleared after each dkg round.
	initialDealings []*initialDealingCache

	// For each dealer (by index), cache the most recently received and verified decryption key shares to avoid redundant verification; should be cleared after each dkg round.
	decryptionKeyShares []*decryptionKeySharesCache

	// The reports plus precursor generated for this dkg instance once a dkg instance is finished
	reportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor
}

// Store the unverified bytes received on the network as unverifiedBytes, and the unmarshaled+verified object as verified
type initialDealingCache struct {
	unverifiedBytes []byte
	verified        dkg.VerifiedInitialDealing
}

// Store the unverified bytes received on the network as unverifiedBytes, and the unmarshaled+verified object as verified
type decryptionKeySharesCache struct {
	unverifiedBytes []byte
	verified        dkg.VerifiedDecryptionKeySharesForInnerDealing
}

func (c *cachedValues) cacheVerifiedInitialDealing(observer int, raw []byte, dealing dkg.VerifiedInitialDealing) {
	if c.initialDealings[observer] == nil || !bytes.Equal(c.initialDealings[observer].unverifiedBytes, raw) {
		c.initialDealings[observer] = &initialDealingCache{raw, dealing}
	}
}

func (c *cachedValues) recoverVerifiedInitialDealing(dkgInstance dkg.DKG, observer int, raw []byte) (dkg.VerifiedInitialDealing, error) {
	if c.initialDealings[observer] != nil && bytes.Equal(c.initialDealings[observer].unverifiedBytes, raw) {
		return c.initialDealings[observer].verified, nil
	} else {
		unverifiedDealing, err := codec.Unmarshal(raw, dkg.NewUnverifiedInitialDealing())
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal unverified initial dealing: %w", err)
		}

		dealing, err := dkgInstance.VerifyInitialDealing(unverifiedDealing, observer)
		if err != nil {
			return nil, fmt.Errorf("failed to verify initial dealing from dealer %d: %w", observer, err)
		}

		c.cacheVerifiedInitialDealing(observer, raw, dealing)
		return dealing, nil
	}
}

func (c *cachedValues) cacheVerifiedDecryptionKeyShares(observer int, raw []byte, shares dkg.VerifiedDecryptionKeySharesForInnerDealing) {
	if c.decryptionKeyShares[observer] == nil || !bytes.Equal(c.decryptionKeyShares[observer].unverifiedBytes, raw) {
		c.decryptionKeyShares[observer] = &decryptionKeySharesCache{raw, shares}
	}
}

func (c *cachedValues) recoverVerifiedDecryptionKeyShares(dkgInstance dkg.DKG, dealings initialDealings, observer int, raw []byte) (dkg.VerifiedDecryptionKeySharesForInnerDealing, error) {
	if c.decryptionKeyShares[observer] != nil && bytes.Equal(c.decryptionKeyShares[observer].unverifiedBytes, raw) {
		return c.decryptionKeyShares[observer].verified, nil
	} else {
		unverifiedShares, err := codec.Unmarshal(raw, dkg.NewUnverifiedDecryptionKeySharesForInnerDealing())
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal unverified decryption key shares: %w", err)
		}
		decryptionKeyShares, err := dkgInstance.VerifyDecryptionKeyShares(dealings, unverifiedShares, observer)
		if err != nil {
			return nil, fmt.Errorf("failed to verify decryption key shares from dealer %d: %w", observer, err)
		}

		c.cacheVerifiedDecryptionKeyShares(observer, raw, decryptionKeyShares)
		return decryptionKeyShares, nil
	}
}

func (c *cachedValues) clearCaches() {
	c.initialDealingBlobHandleBytes = nil
	c.initialDealings = make([]*initialDealingCache, len(c.dkg.Dealers()))
	c.decryptionKeyShares = make([]*decryptionKeySharesCache, len(c.dkg.Dealers()))
}

func (c *cachedValues) getDKGInstance(ctx context.Context, config *dkgInstanceConfig) (dkg.DKG, error) {
	if c.dkg == nil {
		var err error
		c.dkg, err = config.newDKG(ctx)
		if err != nil {
			return nil, err
		}
	}
	return c.dkg, nil
}

func (c *cachedValues) getInitialDealingBlobHandleBytes(ctx context.Context, seqNr uint64,
	blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher, dkg dkg.DKG, rand io.Reader,
) ([]byte, error) {
	if c.initialDealingBlobHandleBytes == nil {
		dealing, err := dkg.Deal(rand)
		if err != nil {
			return nil, err
		}

		payload, err := codec.Marshal(dealing.AsUnverifiedDealing())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal unverified initial dealing: %w", err)
		}

		blobHandle, err := blobBroadcastFetcher.BroadcastBlob(ctx, payload, ocr3_1types.BlobExpirationHintSequenceNumber{seqNr})
		if err != nil {
			return nil, fmt.Errorf("failed to broadcast initial dealing blob: %w", err)
		}

		c.initialDealingBlobHandleBytes, err = blobHandle.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal blob handle to binary: %w", err)
		}
	}
	return c.initialDealingBlobHandleBytes, nil
}

func (c *cachedValues) getReportsPlusPrecursor(ctx context.Context, dkg dkg.DKG, innerDealings innerDealings,
	config *dkgocrtypes.ReportingPluginConfig,
) (ocr3_1types.ReportsPlusPrecursor, error) {
	if c.reportsPlusPrecursor == nil {
		result, err := dkg.NewResult(innerDealings)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKG result: %w", err)
		}
		resultPackage := ResultPackage{result, config}

		c.reportsPlusPrecursor, err = resultPackage.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DKG result package: %w", err)
		}
	}
	return c.reportsPlusPrecursor, nil
}
