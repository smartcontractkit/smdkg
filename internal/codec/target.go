package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

type target struct {
	buffer []byte
}

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

func (t *target) WriteInt(value int) {
	if value > math.MaxInt32 || value < math.MinInt32 {
		panic(fmt.Sprintf("WriteInt called with value %d, which is out of range of int32", value))
	}
	t.buffer = binary.LittleEndian.AppendUint32(t.buffer, uint32(value))
}

func (t *target) WriteBool(value bool) {
	if value {
		t.buffer = append(t.buffer, 1)
	} else {
		t.buffer = append(t.buffer, 0)
	}
}

func (t *target) WriteBytes(value []byte) {
	t.buffer = append(t.buffer, value...)
}

func (t *target) WriteLengthPrefixedBytes(value []byte) {
	if value == nil {
		t.WriteInt(-1)
		return
	}
	t.WriteInt(len(value))
	t.WriteBytes(value)
}

func (t *target) WriteString(value string) {
	t.WriteInt(len(value))
	t.buffer = append(t.buffer, value...)
}
