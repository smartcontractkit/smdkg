package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Internal representation for a target to which bytes can be marshaled. The buffer slice is updated during writing,
// growing as needed.
type target struct {
	buffer []byte
}

// Written returns the number of bytes that have been written to the target so far.
func (t *target) Written() int {
	return len(t.buffer)
}

// Marshals the given object into the this target. Panics, which may be raised by the marshaling of child objects,
// are recovered and returned as errors. To propagate (i.e., not catch) the panic use target.Write(...) instead.
func (t *target) Marshal(object Marshaler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered panic during marshaling: %v", r)
		}
	}()

	t.Write(object)
	return nil
}

// Write the given object into this target. This is just an alias for object.MarshalTo(target). The given object must
// not be nil. Panics raised during marshaling are NOT recovered and must be handled by the caller. To recover from
// panics use target.Marshal(object) instead. However, at the top-level codec.Marshal(...) function panics are always
// recovered.
func (t *target) Write(object Marshaler) {
	if object == nil {
		panic("Write called with nil object")
	}
	object.MarshalTo(t)
}

// Write an optional object into this target. If the given object is nil, a false boolean is written. Otherwise, a true
// boolean is written followed by the object itself.
func (t *target) WriteOptional(object MarshalerWithNilSupport) {
	if object == nil || object.IsNil() {
		t.WriteBool(false)
	} else {
		t.WriteBool(true)
		object.MarshalTo(t)
	}
}

// WriteInt writes a 32-bit signed integer to the target in BigEndian byte order.
// It panics if the given integer is out of the range of int32.
func (t *target) WriteInt(value int) {
	if value > math.MaxInt32 || value < math.MinInt32 {
		panic(fmt.Sprintf("WriteInt called with value %d, which is out of range of int32", value))
	}

	t.buffer, _ = binary.Append(t.buffer, binary.BigEndian, uint32(value))
}

// WriteBool writes a boolean value to the target.
func (t *target) WriteBool(value bool) {
	if value {
		t.buffer = append(t.buffer, 1)
	} else {
		t.buffer = append(t.buffer, 0)
	}
}

// WriteBytes writes the given byte slice to the target.
func (t *target) WriteBytes(value []byte) {
	t.buffer = append(t.buffer, value...)
}

// WriteLengthPrefixedBytes writes a length-prefixed byte slice to the target. The length is encoded as a 32-bit signed
// integer in BigEndian byte order. A nil slice is encoded as a length of -1.
func (t *target) WriteLengthPrefixedBytes(value []byte) {
	if value == nil {
		t.WriteInt(-1)
		return
	}
	t.WriteInt(len(value))
	t.WriteBytes(value)
}

// WriteString writes a length-prefixed string to the target. The length is encoded as a 32-bit signed integer in
// BigEndian byte order.
func (t *target) WriteString(value string) {
	t.WriteInt(len(value))
	t.buffer = append(t.buffer, value...)
}
