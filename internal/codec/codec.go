package codec

import "fmt"

// High level type definitions for the codec package.
// Use the codec.Marshal(...) and codec.Unmarshal(...) functions for marshaling and unmarshaling.
//
// The codec.Unmarshal(...) and codec.UnmarshalFromSource() functions always recover from panics during unmarshaling.

const IntSize = 4

type Marshaler interface {
	MarshalTo(target Target)
}

type MarshalerWithNilSupport interface {
	Marshaler

	// IsNil returns true if the object is nil.
	IsNil() bool
}

type Unmarshaler[T any] interface {
	UnmarshalFrom(source Source) T
}

type Codec[T any] interface {
	MarshalerWithNilSupport
	Unmarshaler[T]
}

type Target = *target
type Source = *source

// Marshals the given (non-nil) object into a byte slice.
// Panics during marshaling are recovered and returned as errors.
func Marshal(object Marshaler) ([]byte, error) {
	target := &target{}
	err := target.Marshal(object)
	if err != nil {
		return nil, err
	}
	return target.buffer, nil
}

// Unmarshal the given byte slice into a new instance of type T. The unmarshaler may or may not be implemented by T
// itself. Panics during unmarshaling are recovered and returned as errors. Additionally, this function also checks that
// all input bytes are consumed during unmarshaling, returning an error if any non-read bytes remain.
func Unmarshal[T any](data []byte, unmarshaler Unmarshaler[T]) (result T, err error) {
	src := &source{data}
	result, err = UnmarshalFromSource(src, unmarshaler)
	if err != nil {
		return result, err
	}
	if src.Available() > 0 {
		var zero T
		return zero, fmt.Errorf(
			"unmarshaling did not consume all bytes, %d bytes remaining", src.Available(),
		)
	}
	return result, nil
}

// Unmarshal the given byte slice into a new instance of type T. The unmarshaling is implemented by the provided
// function. This a wrapper to ensure panics during unmarshaling are recovered and returned as errors. Additionally,
// this function also checks that all input bytes are consumed during unmarshaling, returning an error if any non-read
// bytes remain.
func UnmarshalUsing[T any](data []byte, unmarshalFunc func(Source) T) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered panic while unmarshaling: %v", r)
		}
	}()

	src := &source{data}
	result = unmarshalFunc(src)

	if src.Available() > 0 {
		var zero T
		return zero, fmt.Errorf(
			"unmarshaling did not consume all bytes, %d bytes remaining", src.Available(),
		)
	}
	return result, nil
}

// Read the next object of type T from the given source using the provided unmarshaler. Panics during unmarshaling are
// recovered and returned as errors. Additional data remaining in the source after unmarshaling is not considered an
// error.
func UnmarshalFromSource[T any](source Source, obj Unmarshaler[T]) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered panic while unmarshaling: %v", r)
		}
	}()
	return obj.UnmarshalFrom(source), nil
}

// Wrapper to read an object of type T from the given source using the provided unmarshaler.
func ReadObject[T any](s Source, u Unmarshaler[T]) T {
	return u.UnmarshalFrom(s)
}

// Read an optional object of type T from the given source using the provided unmarshaler. If a the underlying source
// does not contain the value, the zero/default value for T is returned. The provided factory is used to initialize
// a new instance of type T if a valid should be read. Use this function for pointer types or interfaces (default: nil).
// For value types, instead consider using ReadOptionalValue(...) to distinguish between missing values and zero-valued
// T in a type-safe manner.
func ReadOptional[T any, F Unmarshaler[T]](source Source, factory func() F) T {
	hasValue := source.ReadBool()
	if !hasValue {
		var zero T
		return zero
	}
	return factory().UnmarshalFrom(source)
}

// Read an optional object of type T from the given source using the provided unmarshaler. If a the underlying source
// does not contain the value, the zero/default value for T is returned along with a boolean flag set to false.
func ReadOptionalValue[T any](s Source, u Unmarshaler[T]) (T, bool) {
	hasValue := s.ReadBool()
	if !hasValue {
		var zero T
		return zero, false
	}
	return u.UnmarshalFrom(s), true
}
