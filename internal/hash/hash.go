package hash

import (
	"crypto/sha3"
	"fmt"

	serialization "github.com/smartcontractkit/smdkg/internal/serialization"
)

type hash struct {
	dst     string
	shake   *sha3.SHAKE
	encoder *serialization.Encoder
}

// Initialize a new Hash instance, applying the given domain separation tag.
// Parameters can be written to the hashes state using WriteInt(...), WriteBool(...), WriteBytes(...), WriteString(...)
// functions, which enforce a proper unique encoding.
func NewHash(dst string) *hash {
	shake := sha3.NewSHAKE256()
	h := &hash{dst, shake, serialization.NewEncoderFor(shake)}
	h.WriteString(h.dst)
	return h
}

// Writes an integer to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteInt(value int) {
	h.encoder.WriteInt(value)
}

// Writes a boolean to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteBool(value bool) {
	h.encoder.WriteBool(value)
}

// Writes a byte slice to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteBytes(data []byte) {
	h.encoder.WriteBytes(data)
}

// Writes a string to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteString(str string) {
	h.encoder.WriteString(str)
}

// Reads from the hash's internal SHAKE XOF.
// After calling this function, no Write function must be called again.
func (h *hash) Read(digest []byte) (int, error) {
	if err := h.encoder.Err(); err != nil {
		return 0, err
	}
	return h.shake.Read(digest)
}

// Computes the hash digest, returning a byte slice of the specified length (default: 32 bytes).
// This is just a shorthand for calling Read(...) with a preallocated byte slice of the specified length.
// After calling this function, no Write function must be called again.
func (h *hash) Digest(numBytes ...int) ([]byte, error) {
	if len(numBytes) > 1 {
		return nil, fmt.Errorf("expected at most one parameter numBytes, got %d", len(numBytes))
	}
	if len(numBytes) == 0 {
		numBytes = append(numBytes, 32)
	}

	length := numBytes[0]
	if length <= 0 {
		return nil, fmt.Errorf("invalid length %d for hash digest", length)
	}

	digest := make([]byte, length)
	if _, err := h.shake.Read(digest); err != nil {
		return nil, err
	}
	return digest, nil
}

// Resets the internal SHAKE XOF to its initial state, i.e., the state after NewHash was called.
// (Write calls can be made again after this.)
func (h *hash) Reset() {
	h.shake.Reset()
	h.WriteString(h.dst)
}
