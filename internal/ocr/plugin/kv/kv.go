package kv

import (
	"encoding/binary"
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/codec"
)

// Access shim for the key/value store used by the DKG plugin.
// The keys are defined below. The values are marshaled/unmarshaled using the codec package.
//
// Note: Read semantics of the underlying ocr3_1types.KeyValueReader are followed, i.e. if no value for a given key
// exists, the zero value of the corresponding type is returned without an error (and unmarshaling is not attempted).

const pluginStateKey = "PluginState"
const bannedDealersKey = "BannedDealers"
const initialDealingsKey = "InitialDealings"
const decryptionKeySharesKey = "DecryptionKeyShares"
const innerDealingsKey = "InnerDealings"

type storageKey []byte

// Returns the key/value store key for accessing the plugin state.
func PluginStateKey() storageKey {
	return storageKey(pluginStateKey)
}

// Returns the key/value store key for accessing the banned dealers.
func BannedDealersKey() storageKey {
	return storageKey(bannedDealersKey)
}

// Returns the key/value store key for accessing initial dealings for a given attempt.
func InitialDealingsKey(attempt int) storageKey {
	key := storageKey("0000/" + initialDealingsKey)
	binary.BigEndian.PutUint32(key, uint32(attempt))
	return key
}

// Returns the key/value store key for accessing decryption key shares for a given attempt.
func DecryptionKeySharesKey(attempt int) storageKey {
	var key = []byte("0000/" + decryptionKeySharesKey)
	binary.BigEndian.PutUint32(key, uint32(attempt))
	return key
}

// Returns the key/value store key for accessing inner dealings for a given attempt.
func InnerDealingsKey(attempt int) storageKey {
	key := []byte("0000/" + innerDealingsKey)
	binary.BigEndian.PutUint32(key, uint32(attempt))
	return key
}

// ReadObject reads and unmarshals an object from the key/value store. Follows the underlying semantics of
// ocr3_1types.KeyValueReader.Read, i.e., if no value for the given key exists, the zero value of T is returned without
// an error (and marshaling is not attempted).
func ReadObject[T any](kvStore ocr3_1types.KeyValueReader, key storageKey, unmarshaler codec.Unmarshaler[T]) (T, error) {
	var zero T

	// Try to read the data from the key/value store.
	data, err := kvStore.Read(key)
	if err != nil {
		return zero, fmt.Errorf("kv.ReadObject, read from key/value store failed (key: %x): %w", key, err)
	}

	// No value for the given key exists, return the zero value of T without an error.
	if data == nil {
		return zero, nil
	}

	// Unmarshal the data into an object of type T.
	object, err := codec.Unmarshal(data, unmarshaler)
	if err != nil {
		return zero, fmt.Errorf(
			"kv.ReadObject, unmarshaling failed (key: %x, unmarshaler: %#v): %w", key, unmarshaler, err,
		)
	}
	return object, nil
}

// WriteObject marshals and writes an object to the key/value store. If the call is successful, the number of bytes
// written is returned.
func WriteObject(kvStore ocr3_1types.KeyValueReadWriter, key storageKey, marshaler codec.Marshaler) (int, error) {
	data, err := codec.Marshal(marshaler)
	if err != nil {
		return 0, fmt.Errorf(
			"kv.WriteObject, marshaling failed (key: %x, marshaler: %#v): %w", key, marshaler, err,
		)
	}

	err = kvStore.Write(key, data)
	if err != nil {
		return 0, fmt.Errorf("kv.WriteObject, writing to key/value store failed (key: %x): %w", key, err)
	}
	return len(key) + len(data), nil
}
