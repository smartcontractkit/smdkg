package pluginstate

import (
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/kv"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
)

type KeyValueStateReader = ocr3_1types.KeyValueStateReader
type KeyValueStateReadWriter = ocr3_1types.KeyValueStateReadWriter

// Reads the current plugin phase from the key/value store, or returns the initial phase if none is stored.
func (s *PluginState) ReadPhase(kvReader KeyValueStateReader) (plugintypes.PluginPhase, error) {
	phase, err := kv.ReadObject(kvReader, kv.PluginPhaseKey(), s.phaseUnmarshaler)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin phase: %w", err)
	}
	if phase == nil {
		phase = s.initialPhase
	}
	return phase, nil
}

// Write the given phase to the key/value store and returns the number of bytes written.
func (s *PluginState) WritePhase(kvWriter KeyValueStateReadWriter, phase plugintypes.PluginPhase) (int, error) {
	bytesWritten, err := kv.WriteObject(kvWriter, kv.PluginPhaseKey(), phase)
	if err != nil {
		return 0, fmt.Errorf("failed to write plugin phase: %w", err)
	}
	return bytesWritten, nil
}

// Read the verified list of initial dealings from the key/value store. An error is returned if reading from the
// key/value store fails, unmarshaling fails, or if no initial dealings are stored for the given attempt.
func (s *PluginState) ReadInitialDealings(kvReader KeyValueStateReader, attempt int) (plugintypes.InitialDealings, error) {
	initialDealings, err := kv.ReadObject(kvReader, kv.InitialDealingsKey(attempt), plugintypes.InitialDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to read initial dealings from key/value store: %w", err)
	}
	if initialDealings == nil {
		return nil, fmt.Errorf("no initial dealings found for attempt %d", attempt)
	}
	return initialDealings, nil
}

// Write the given list of initial dealings to the key/value store and returns the number of bytes written.
func (s *PluginState) WriteInitialDealings(
	kvWriter KeyValueStateReadWriter, attempt int, dealings plugintypes.InitialDealings,
) (int, error) {
	bytesWritten, err := kv.WriteObject(kvWriter, kv.InitialDealingsKey(attempt), dealings)
	if err != nil {
		return 0, fmt.Errorf("failed to write initial dealings to key/value store: %w", err)
	}
	return bytesWritten, nil
}

// Read the verified list of decryption key shares from the key/value store. An error is returned if reading from the
// key/value store fails, unmarshaling fails, or if no decryption key shares are stored for the given attempt.
func (s *PluginState) ReadDecryptionKeyShares(kvReader KeyValueStateReader, attempt int) (plugintypes.DecryptionKeyShares, error) {
	result, err := kv.ReadObject(kvReader, kv.DecryptionKeySharesKey(attempt), plugintypes.DecryptionKeyShares{})
	if err != nil {
		return nil, fmt.Errorf("failed to read decryption key shares from key/value store: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("no decryption key shares found for attempt %d", attempt)
	}
	return result, nil
}

// Write the given list of decryption key shares to the key/value store and returns the number of bytes written.
func (s *PluginState) WriteDecryptionKeyShares(
	kvWriter KeyValueStateReadWriter, attempt int, shares plugintypes.DecryptionKeyShares,
) (int, error) {
	bytesWritten, err := kv.WriteObject(kvWriter, kv.DecryptionKeySharesKey(attempt), shares)
	if err != nil {
		return 0, fmt.Errorf("failed to write decryption key shares to key/value store: %w", err)
	}
	return bytesWritten, nil
}

// Read the verified list of inner dealings from the key/value store. An error is returned if reading from the key/value
// store fails, unmarshaling fails, or if no inner dealings are stored for the given attempt.
func (s *PluginState) ReadInnerDealings(kvReader KeyValueStateReader, attempt int) (plugintypes.InnerDealings, error) {
	result, err := kv.ReadObject(kvReader, kv.InnerDealingsKey(attempt), plugintypes.InnerDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to read inner dealings from key/value store: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("no inner dealings found for attempt %d", attempt)
	}
	return result, nil
}

// WriteInnerDealings writes the given list of inner dealings to the key/value store and returns the number of bytes
// written.
func (s *PluginState) WriteInnerDealings(kvWriter KeyValueStateReadWriter, attempt int, dealings plugintypes.InnerDealings) (int, error) {
	bytesWritten, err := kv.WriteObject(kvWriter, kv.InnerDealingsKey(attempt), dealings)
	if err != nil {
		return 0, fmt.Errorf("failed to write inner dealings to key/value store: %w", err)
	}
	return bytesWritten, nil
}

// Read the banned dealers from the key/value store. If no banned dealers are stored in the key/value store,
// an initial value (no banned dealers) is returned.
func (s *PluginState) ReadBannedDealers(kvReader KeyValueStateReader) (plugintypes.BannedDealers, error) {
	result, err := kv.ReadObject(kvReader, kv.BannedDealersKey(), plugintypes.BannedDealers{})
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers from key/value store: %w", err)
	}
	if result == nil {
		result = make(plugintypes.BannedDealers, len(s.initialBannedDealers))
		copy(result, s.initialBannedDealers)
	}
	return result, nil
}

// WriteBannedDealers writes the given list of banned dealers to the key/value store and returns the number of bytes
// written.
func (s *PluginState) WriteBannedDealers(
	kvWriter KeyValueStateReadWriter, bannedDealers plugintypes.BannedDealers,
) (int, error) {
	bytesWritten, err := kv.WriteObject(kvWriter, kv.BannedDealersKey(), bannedDealers)
	if err != nil {
		return 0, fmt.Errorf("failed to write banned dealers to key/value store: %w", err)
	}
	return bytesWritten, nil
}
