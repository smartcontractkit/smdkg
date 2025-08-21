// Minimal CBOR implementation for decoding of integers, booleans, byte slices, and strings.

package serialization

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

type Decoder struct {
	source     io.Reader
	err        error
	bytesRead  int
	bytesTotal int
}

func NewDecoder(source []byte) Decoder {
	return Decoder{bytes.NewReader(source), nil, 0, len(source)}
}

func (d *Decoder) ReadInt() int {
	if d.err != nil {
		return 0
	}

	maj, ai := d.readHeader()
	switch maj {
	case 0:
		u := d.readUint(ai)
		if d.err != nil {
			return 0
		}
		if u > math.MaxInt64 {
			d.err = errors.New("cbor: int overflow")
			return 0
		}
		return int(u)
	case 1:
		u := d.readUint(ai)
		if d.err != nil {
			return 0
		}
		if u > math.MaxInt64 {
			d.err = errors.New("cbor: int overflow")
			return 0
		}
		return int(-1 - int64(u))
	default:
		d.err = errors.New("cbor: next item is not an int")
		return 0
	}
}

func (d *Decoder) ReadBool() bool {
	if d.err != nil {
		return false
	}

	var b [1]byte
	d.readFull(b[:])
	if d.err != nil {
		return false
	}

	switch b[0] {
	case 0xf4:
		return false
	case 0xf5:
		return true
	default:
		d.err = errors.New("cbor: next item is not a bool")
		return false
	}
}

func (d *Decoder) ReadBytes() []byte {
	if d.err != nil {
		return nil
	}

	maj, ai := d.readHeader()

	if maj == 7 && ai == 22 {
		// Special case for a nil byte slice.
		return nil
	}

	if maj != 2 {
		d.err = errors.New("cbor: next item is not a byte string")
		return nil
	}

	length := d.readUint(ai)
	if d.err != nil {
		return nil
	}

	remainingBytes := uint64(d.bytesTotal - d.bytesRead)
	if length > remainingBytes {
		d.err = errors.New("cbor: invalid byte string length")
		return nil
	}

	buf := make([]byte, length)
	d.readFull(buf)
	return buf
}

func (d *Decoder) ReadString() string {
	if d.err != nil {
		return ""
	}

	maj, ai := d.readHeader()
	if maj != 3 {
		d.err = errors.New("cbor: next item is not a text string")
		return ""
	}

	length := d.readUint(ai)
	if d.err != nil {
		return ""
	}

	remainingBytes := uint64(d.bytesTotal - d.bytesRead)
	if length > remainingBytes {
		d.err = errors.New("cbor: invalid string length")
		return ""
	}

	buf := make([]byte, length)
	d.readFull(buf)
	return string(buf)
}

// Err reports the first error encountered (nil means “good so far”).
func (d *Decoder) Err() error {
	return d.err
}

func (d *Decoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if d.bytesRead < d.bytesTotal {
		d.err = errors.New("cbor: unexpected trailing data")
		return d.err
	}
	return nil
}

func (d *Decoder) BytesRead() int {
	return d.bytesRead
}

// readHeader reads a single initial byte and returns <major type, additional-info>.
func (d *Decoder) readHeader() (major, ai byte) {
	var b [1]byte
	d.readFull(b[:])
	return b[0] >> 5, b[0] & 0x1f
}

// readUint consumes 0–8 extra bytes according to the additional-info value
// and returns the resulting unsigned integer.
func (d *Decoder) readUint(ai byte) uint64 {
	var v uint64
	switch {
	case ai < 24:
		v = uint64(ai)

	case ai == 24:
		var b [1]byte
		d.readFull(b[:])
		v = uint64(b[0])
		if v < 24 { // non-canonical
			d.err = errors.New("cbor: non-canonical integer (ai=24 but value<24)")
		}

	case ai == 25:
		var b [2]byte
		d.readFull(b[:])
		v = uint64(binary.BigEndian.Uint16(b[:]))
		if v <= math.MaxUint8 { // should have used ai 24 or <24
			d.err = errors.New("cbor: non-canonical integer (ai=25 but value≤255)")
		}

	case ai == 26:
		var b [4]byte
		d.readFull(b[:])
		v = uint64(binary.BigEndian.Uint32(b[:]))
		if v <= math.MaxUint16 {
			d.err = errors.New("cbor: non-canonical integer (ai=26 but value≤65535)")
		}

	case ai == 27:
		var b [8]byte
		d.readFull(b[:])
		v = binary.BigEndian.Uint64(b[:])
		if v <= math.MaxUint32 {
			d.err = errors.New("cbor: non-canonical integer (ai=27 but value≤4294967295)")
		}

	default:
		d.err = errors.New("cbor: unsupported additional-info")
	}
	return v
}

// readFull is the decoder-side twin of the encoder’s writeFull: it guarantees
// that *all* requested bytes are read or records the first error.
func (d *Decoder) readFull(buf []byte) {
	if len(buf) == 0 {
		return
	}
	n, err := io.ReadFull(d.source, buf)
	if err != nil {
		d.err = err
	} else {
		d.bytesRead += n
	}
}
