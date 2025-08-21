// Minimal CBOR implementation for encoding of integers, booleans, byte slices, and strings.

package serialization

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

type Encoder struct {
	target io.Writer
	err    error
}

type byter interface {
	Bytes() []byte
}

func NewEncoder() *Encoder {
	return &Encoder{&bytes.Buffer{}, nil}
}

func NewEncoderFor(target io.Writer) *Encoder {
	return &Encoder{target, nil}
}

func (e *Encoder) WriteInt(value int) {
	if e.err != nil {
		return
	}

	if value >= 0 {
		e.writeHeader(0, uint64(value))
	} else {
		// -(value + 1) == ^value  for two-complement integers; ^v is always non-negative,
		// so the cast to uint64 is well-defined for both 32- and 64-bit builds.
		e.writeHeader(1, uint64(^value))
	}
}

func (e *Encoder) WriteBool(value bool) {
	if e.err != nil {
		return
	}

	if value {
		e.writeFull([]byte{0xF5})
	} else {
		e.writeFull([]byte{0xF4})
	}
}

func (e *Encoder) WriteBytes(data []byte) {
	if e.err != nil {
		return
	}

	if data == nil {
		e.writeFull([]byte{0xF6})
	} else {
		e.writeHeader(2, uint64(len(data)))
		e.writeFull(data)
	}
}

func (e *Encoder) WriteString(str string) {
	if e.err != nil {
		return
	}

	e.writeHeader(3, uint64(len(str)))
	e.writeFull([]byte(str))
}

// writeHeader emits the CBOR initial byte plus the optional argument bytes in canonical big-endian order.
func (e *Encoder) writeHeader(major uint8, n uint64) {
	var buf [9]byte // 1 + 8 byte header is the maximum

	switch {
	case n < 24:
		buf[0] = major<<5 | uint8(n)
		e.writeFull(buf[:1])

	case n <= math.MaxUint8:
		buf[0] = major<<5 | 24
		buf[1] = uint8(n)
		e.writeFull(buf[:2])

	case n <= math.MaxUint16:
		buf[0] = major<<5 | 25
		binary.BigEndian.PutUint16(buf[1:3], uint16(n))
		e.writeFull(buf[:3])

	case n <= math.MaxUint32:
		buf[0] = major<<5 | 26
		binary.BigEndian.PutUint32(buf[1:5], uint32(n))
		e.writeFull(buf[:5])

	default:
		buf[0] = major<<5 | 27
		binary.BigEndian.PutUint64(buf[1:9], n)
		e.writeFull(buf[:9])
	}
}

func (e *Encoder) writeFull(p []byte) {
	for len(p) > 0 {
		// See https://go.dev/src/io/io.go for the exact semantics of Write.
		n, err := e.target.Write(p)
		if err != nil {
			// Abort if we could not write any bytes to the target, and retry otherwise.
			if n == 0 {
				e.err = err
				return
			}
		}
		p = p[n:]
	}
}

func (e *Encoder) Err() error {
	return e.err
}

// Returns all bytes written to the encoder's buffer.
// This function must not be called when the encoder was initialized to directly output to an io.Writer.
func (e *Encoder) Bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}

	switch v := e.target.(type) {
	case byter:
		return v.Bytes(), nil
	default:
		// TODO: consider returning an error instead of raising the panic.
		// return nil, errors.New("underlying io.Writer does not support Bytes()")
		panic("underlying io.Writer does not support Bytes()")
	}
}

// Returns the size of the encoded value for a []byte of the given length.
// The result includes the length of the slice and the size of the CBOR header.
func SizeOfEncodedBytesByLength(sliceLength int) int {
	if sliceLength < 0 {
		panic("slice length must be non-negative")
	}

	if sliceLength < 24 {
		return 1 + sliceLength
	}
	if sliceLength <= math.MaxUint8 {
		return 2 + sliceLength
	}
	if sliceLength <= math.MaxUint16 {
		return 3 + sliceLength
	}
	if sliceLength <= math.MaxUint32 {
		return 5 + sliceLength
	}
	return 9
}
