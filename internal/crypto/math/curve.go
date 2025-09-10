package math

import "github.com/smartcontractkit/smdkg/internal/codec"

type Curve interface {
	// prevent outside packages from implementing this interface, (marshal/unmarshal would not work correctly)
	internal()

	codec.Marshaler
	// Use codec.UnmarshalUsing(..., math.UnmarshalCurve) to unmarshal.

	// Returns the name of the curve.
	// This is used for debugging and logging purposes.
	Name() string

	// Returns a new zero-valued Scalar instance for the curve (mod the group's order).
	Scalar() Scalar

	// Returns a new uninitialized Point instance for the curve.
	// The uninitialized value returned must only be used as receiver.
	Point() Point

	// c.Generator() returns the base point Generator of the curve.
	// The base point is the generator of the group of points on the curve.
	// This function returns a copy of Generator, the caller may modify it.
	Generator() Point

	// Return the size of the group order of the curve, it corresponds to the domain of the Scalar type.
	// This is NOT the prime modulus for the field over which the curve is defined.
	GroupOrder() *Modulus

	// c.ScalarBytes() returns the number of bytes used to encode a scalar (mod the group's order).
	ScalarBytes() int

	// c.PointBytes() returns the number of bytes used to encode a point on the curve.
	PointBytes() int
}
