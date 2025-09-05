package xof

import (
	"crypto/sha3"
	"encoding/binary"
	"io"
)

// Implementation of a hash function based on SHAKE256 XOF, with domain separation and unique encoding of parameters.
// Initialization with a domain separation tag (DST) is enforced.

var _ io.Reader = &xof{}

type xof struct {
	dst        string
	shake      *sha3.SHAKE
	digest     []byte
	readCalled bool
}

type argType byte

const (
	_ argType = iota
	argTypeNil
	argTypeFalse
	argTypeTrue
	argTypeInt
	argTypeBytes
	argTypeString
)

const (
	DigestLength = 32 // Default length of the XOF's digest in bytes.
)

// Initialize a new XOF instance, applying the given domain separation tag.
// Parameters can be written to the hashes state using WriteInt(...), WriteBool(...), WriteBytes(...), WriteString(...)
// functions, which enforce a proper unique encoding.
func New(dst string) *xof {
	shake := sha3.NewSHAKE256()
	h := &xof{dst, shake, nil, false}
	h.WriteString(h.dst)
	return h
}

func (h *xof) writeArgType(t argType) {
	_, _ = h.shake.Write([]byte{byte(t)})
}

// Writes a boolean to the XOF's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *xof) WriteBool(value bool) {
	if value {
		h.writeArgType(argTypeTrue)
	} else {
		h.writeArgType(argTypeFalse)
	}
}

// Writes an integer to the XOF's internal state.
// Must not be used after a call to Digest(...) or Read(...) has been made.
func (h *xof) WriteInt(value int) {
	h.writeArgType(argTypeInt)
	_ = binary.Write(h.shake, binary.BigEndian, uint64(value))
}

// Writes a byte slice to the XOF's internal state.
// WriteBytes panics if it is called after a call to Digest(...) or Read(...) has been made.
func (h *xof) WriteBytes(data []byte) {
	if data == nil {
		h.writeArgType(argTypeNil)
		return
	}

	h.writeArgType(argTypeBytes)
	_ = binary.Write(h.shake, binary.BigEndian, uint64(len(data)))
	_, _ = h.shake.Write(data)
}

// Writes a string to the XOF's internal state.
// WriteString panics if it is called after a call to Digest(...) or Read(...) has been made.
func (h *xof) WriteString(str string) {
	h.writeArgType(argTypeString)
	_ = binary.Write(h.shake, binary.BigEndian, uint64(len(str)))
	_, _ = h.shake.Write([]byte(str))
}

// Reads from the XOF's internal state (the underlying SHAKE XOF).
// Calling any write function or Digest after calling Read results in a panic.
// Calling Read multiple times continues reading from the XOF.
// Return values are required for the io.Reader interface, but this implementation never returns an error.
func (h *xof) Read(digest []byte) (n int, err error) {
	if h.digest != nil {
		panic("cannot call Read after Digest")
	}
	h.readCalled = true
	return h.shake.Read(digest)
}

// Computes the XOF's digest, returning a byte slice of default length (32 bytes).
// Calling any write function or Read, after calling Digest results in a panic.
// Calling Digest multiple times returns the same result.
func (h *xof) Digest() []byte {
	if h.readCalled {
		panic("cannot call Digest after Read")
	}
	if h.digest == nil {
		h.digest = make([]byte, DigestLength)
		_, _ = h.shake.Read(h.digest)
	}

	var digest [DigestLength]byte
	copy(digest[:], h.digest)
	return digest[:]
}

// Resets all internal state to the initial values, effectively resetting this instance to the state after New was
// called. The initially specified domain separation tag is re-applied to the internal SHAKE XOF state after resetting
// it. Write calls can be made again after this.
func (h *xof) Reset() {
	h.shake.Reset()
	h.digest = nil
	h.readCalled = false
	h.WriteString(h.dst)
}
