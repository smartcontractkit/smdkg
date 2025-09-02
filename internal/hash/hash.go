package hash

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"io"
)

// Implementation of a hash function based on SHAKE256 XOF, with domain separation and unique encoding of parameters.
// Initialization with a domain separation tag (DST) is enforced.

var _ io.Reader = &hash{}

type hash struct {
	dst   string
	shake *sha3.SHAKE
}

const (
	typeFalse  = iota
	typeTrue   = iota
	typeNil    = iota
	typeInt    = iota
	typeBytes  = iota
	typeString = iota
)

// Initialize a new Hash instance, applying the given domain separation tag.
// Parameters can be written to the hashes state using WriteInt(...), WriteBool(...), WriteBytes(...), WriteString(...)
// functions, which enforce a proper unique encoding.
func NewHash(dst string) *hash {
	shake := sha3.NewSHAKE256()
	h := &hash{dst, shake}
	h.WriteString(h.dst)
	return h
}

// Writes a boolean to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteBool(value bool) {
	if value {
		h.shake.Write([]byte{typeTrue})
	} else {
		h.shake.Write([]byte{typeFalse})
	}
}

// Writes an integer to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteInt(value int) {
	var buf [9]byte = [9]byte{typeInt}
	binary.LittleEndian.PutUint64(buf[1:9], uint64(value))
	h.shake.Write(buf[:])
}

// Writes a byte slice to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteBytes(data []byte) {
	if data == nil {
		h.shake.Write([]byte{typeNil})
		return
	}

	var buf [9]byte = [9]byte{typeBytes}
	binary.LittleEndian.PutUint64(buf[1:9], uint64(len(data)))
	h.shake.Write(buf[:])
	h.shake.Write(data)
}

// Writes a string to the hash's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *hash) WriteString(str string) {
	var buf [9]byte = [9]byte{typeString}
	binary.LittleEndian.PutUint64(buf[1:9], uint64(len(str)))
	h.shake.Write(buf[:])
	h.shake.Write([]byte(str))
}

// Reads from the hash's internal SHAKE XOF.
// After calling this function, no Write function must be called.
func (h *hash) Read(digest []byte) (n int, err error) {
	return h.shake.Read(digest)
}

// Computes the hash digest, returning a byte slice of the specified length (default: 32 bytes).
// This is just a shorthand for calling Read(...) with a preallocated byte slice of the specified length.
// After calling this function, no Write function must be called again.
func (h *hash) Digest(numBytes ...int) []byte {
	if len(numBytes) == 0 {
		var digest [32]byte
		h.shake.Read(digest[:])
		return digest[:]
	}
	if len(numBytes) == 1 {
		if numBytes[0] <= 0 {
			panic(fmt.Sprintf("numBytes must be positive, given %d", numBytes[0]))
		}

		length := numBytes[0]
		digest := make([]byte, length)
		h.shake.Read(digest)
		return digest
	}
	panic(fmt.Sprintf("expected at most one parameter numBytes, got %d", len(numBytes)))
}

// Resets the internal SHAKE XOF to its initial state, i.e., the state after NewHash was called.
// (Write calls can be made again after this.)
func (h *hash) Reset() {
	h.shake.Reset()
	h.WriteString(h.dst)
}
