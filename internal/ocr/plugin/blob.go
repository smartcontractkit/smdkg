package plugin

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
)

// Helper functions for using blob fetcher/broadcaster.

// Broadcast the blob with the payload and return the marshaled blob handle.
func disseminateBlob(ctx context.Context, seqNr uint64, blobBroadcastFetcher ocr3_1types.BlobBroadcastFetcher, payload []byte) ([]byte, error) {
	// expirySeqNr is the max seq nr where you can expect the blob to be available; not enforced in current ocr yet
	blobHandle, err := blobBroadcastFetcher.BroadcastBlob(ctx, payload, ocr3_1types.BlobExpirationHintSequenceNumber{seqNr})
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast initial dealing blob: %w", err)
	}

	// Serialize the blob handle to bytes
	marshaledBlobHandle, err := blobHandle.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal blob handle to binary: %w", err)
	}

	return marshaledBlobHandle, nil
}

// Fetch the blob payload given the marshaled blob handle.
func fetchBlobPayload(ctx context.Context, blobFetcher ocr3_1types.BlobFetcher, marshaledBlobHandle []byte) ([]byte, error) {
	blobHandle := &ocr3_1types.BlobHandle{}
	err := blobHandle.UnmarshalBinary(marshaledBlobHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal blob handle: %w", err)
	}

	payload, err := blobFetcher.FetchBlob(ctx, *blobHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch initial dealing blob: %w", err)
	}

	return payload, nil
}
