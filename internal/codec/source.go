package codec

import (
	"encoding/binary"
	"fmt"
)

// Internal representation for a source of bytes to be unmarshaled. The buffer slice is modified during reading.
type source struct {
	buffer []byte
}

// Available returns the number of bytes that are still available for reading from the source.
func (s *source) Available() int {
	return len(s.buffer)
}

// ReadInt reads a 32-bit signed integer from the source in BigEndian byte order.
// It panics if not enough bytes are available in the source.
func (s *source) ReadInt() int {
	if len(s.buffer) < IntSize {
		panic(fmt.Sprintf("ReadInt called, %d bytes required, but only %d bytes available", IntSize, len(s.buffer)))
	}
	value := int(int32(binary.BigEndian.Uint32(s.buffer)))
	s.buffer = s.buffer[IntSize:]
	return value
}

// ReadNonNegativeInt reads a non-negative 32-bit signed integer from the source in BigEndian byte order.
// It panics if not enough bytes are available in the source or if the read integer is negative.
func (s *source) ReadNonNegativeInt() int {
	value := s.ReadInt()
	if value < 0 {
		panic(fmt.Sprintf("ReadNonNegativeInt call failed, negative value %d read", value))
	}
	return value
}

// ReadBool reads a boolean value from the source.
// It panics if not enough bytes are available in the source.
func (s *source) ReadBool() bool {
	if len(s.buffer) < 1 {
		panic("ReadBool called on empty source buffer")
	}
	value := s.buffer[0] != 0
	s.buffer = s.buffer[1:]
	return value
}

// ReadBytes reads a specified number of bytes from the source. Its returns a slice of the source's buffer without
// creating a copy. This may lead to memory leaks if large amounts of data are discarded after reading. Consider using
// ReadBytesInto if you want to avoid this.
func (s *source) ReadBytes(length int) []byte {
	if len(s.buffer) < length {
		panic(fmt.Sprintf("ReadBytes called with length %d, but only %d bytes available", length, len(s.buffer)))
	}
	value := s.buffer[:length:length] // limit cap(value) to prevent overwriting the source's buffer on append
	s.buffer = s.buffer[length:]
	return value
}

// ReadBytesInto reads from the source to fill the provided buffer.
// It panics if not enough bytes are available in the source.
func (s *source) ReadBytesInto(buffer []byte) {
	if len(s.buffer) < len(buffer) {
		panic(fmt.Sprintf("ReadBytesInto called with buffer length %d, but only %d bytes available", len(buffer), len(s.buffer)))
	}
	copy(buffer, s.buffer[:len(buffer)])
	s.buffer = s.buffer[len(buffer):]
}

// ReadLengthPrefixedBytes reads a length-prefixed byte slice from the source. The length is encoded as a 32-bit signed
// integer in BigEndian byte order. A length of -1 indicates a nil slice. It panics if not enough bytes are available
// in the source or if the length is negative (and not -1).
func (s *source) ReadLengthPrefixedBytes() []byte {
	length := s.ReadInt()

	// nil marker
	if length == -1 {
		return nil
	}
	if length < 0 {
		panic("ReadLengthPrefixedBytes call failed, negative length field")
	}

	return s.ReadBytes(length)
}

// ReadString reads a length-prefixed string from the source. The length is encoded as a 32-bit signed integer in
// BigEndian byte order. It panics if not enough bytes are available in the source or if the length is negative.
func (s *source) ReadString() string {
	length := s.ReadInt()
	if length < 0 {
		panic("ReadString call failed, negative length field")
	}
	if len(s.buffer) < length {
		panic(fmt.Sprintf("ReadString call failed, requested %d bytes, but only %d bytes available", length, len(s.buffer)))
	}

	value := string(s.buffer[:length])
	s.buffer = s.buffer[length:]
	return value
}
