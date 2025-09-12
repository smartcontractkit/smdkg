package plugin

import (
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/kv"
)

// Shim for easier reading and writing to protocol state to/from the key/value store.

type KeyValueReader = ocr3_1types.KeyValueReader
type KeyValueReadWriter = ocr3_1types.KeyValueReadWriter

// Attempts to read/write various plugin state objects from/to the key/value store. If no plugin state is stored in the
// key/value store, the initial state is returned.
func (p *DKGPlugin) readOrInitializePluginState(kvReader KeyValueReader) (pluginState, error) {
	result, err := kv.ReadObject(kvReader, kv.PluginStateKey(), &pluginStateUnmarshaler{p})
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}
	if result == nil {
		result = &pluginStateDealing{p, 0}
	}
	return result, nil
}

// Writes the given plugin state to the key/value store and returns the number of bytes written.
func (p *DKGPlugin) writePluginState(kvWriter KeyValueReadWriter, state pluginState) (int, error) {
	return kv.WriteObject(kvWriter, kv.PluginStateKey(), state)
}

// Attempts to read the banned dealers from the key/value store. If no banned dealers are stored in the key/value store,
// an initial value (no banned dealers) is returned.
func (p *DKGPlugin) readOrInitializeBannedDealers(kvReader KeyValueReader) (bannedDealers, error) {
	result, err := kv.ReadObject(kvReader, kv.BannedDealersKey(), bannedDealers{})
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers: %w", err)
	}
	if result == nil {
		result = make(bannedDealers, len(p.dealers))
	}
	return result, nil
}

// Writes the given list of banned dealers to the key/value store and returns the number of bytes written.
func (p *DKGPlugin) writeBannedDealers(kvWriter KeyValueReadWriter, bannedDealers bannedDealers) (int, error) {
	return kv.WriteObject(kvWriter, kv.BannedDealersKey(), bannedDealers)
}

// Reads the list of initial dealings for the given attempt from the key/value store. Returns and an error if reading
// from the key/value store fails, unmarshaling fails, or if no initial dealings are stored for the given attempt.
func (p *DKGPlugin) readInitialDealings(KeyValueReader KeyValueReader, attempt int) (initialDealings, error) {
	result, err := kv.ReadObject(KeyValueReader, kv.InitialDealingsKey(attempt), initialDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to read initial dealings for attempt %d: %w", attempt, err)
	}
	if result == nil {
		return nil, fmt.Errorf("failed to read initial dealings for attempt %d: no value stored", attempt)
	}
	return result, nil
}

// Writes the given list of initial dealings to the key/value store and returns the number of bytes written.
func (p *DKGPlugin) writeInitialDealings(
	kvWriter KeyValueReadWriter, attempt int, dealings initialDealings,
) (int, error) {
	return kv.WriteObject(kvWriter, kv.InitialDealingsKey(attempt), dealings)
}

// Reads the list of inner dealings for the given attempt from the key/value store. Returns and an error if reading
// from the key/value store fails, unmarshaling fails, or if no inner dealings are stored for the given attempt.
func (p *DKGPlugin) readInnerDealings(kvReader KeyValueReader, attempt int) (innerDealings, error) {
	result, err := kv.ReadObject(kvReader, kv.InnerDealingsKey(attempt), innerDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to read inner dealings for attempt %d: %w", attempt, err)
	}
	if result == nil {
		return nil, fmt.Errorf("failed to read inner dealings for attempt %d: no value stored", attempt)
	}
	return result, nil
}

// Writes the given list of inner dealings to the key/value store and returns the number of bytes written.
func (p *DKGPlugin) writeInnerDealings(kvWriter KeyValueReadWriter, attempt int, dealings innerDealings) (int, error) {
	return kv.WriteObject(kvWriter, kv.InnerDealingsKey(attempt), dealings)
}

// Reads the list of decryption key shares for the given attempt from the key/value store. Returns and an error if
// reading from the key/value store fails, unmarshaling fails, or if no decryption key shares are stored for the given
// attempt.
// Note: currently unused as decryption key shares are only written but never read by the plugin itself. Likely useful
// for later analysis/forensics.
// func (p *DKGPlugin) readDecryptionKeyShares(kvReader KeyValueReader, attempt int) (decryptionKeyShares, error) {
//     result, err := kv.ReadObject(kvReader, kv.DecryptionKeyShares(attempt), decryptionKeyShares{})
//     if err != nil {
//         return nil, fmt.Errorf("failed to read decryption key shares for attempt %d: %w", attempt, err)
//     }
//     if result == nil {
//         return nil, fmt.Errorf("failed to read decryption key shares for attempt %d: no value stored", attempt)
//     }
//     return result, nil
// }

// Writes the given list of decryption key shares to the key/value store and returns the number of bytes written.
func (p *DKGPlugin) writeDecryptionKeyShares(
	kvWriter KeyValueReadWriter, attempt int, shares decryptionKeyShares,
) (int, error) {
	return kv.WriteObject(kvWriter, kv.DecryptionKeySharesKey(attempt), shares)
}
