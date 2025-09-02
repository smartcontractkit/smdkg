package math

import "github.com/smartcontractkit/smdkg/internal/codec"

type Point interface {
	codec.Codec[Point]

	// v.Curve() returns the point's underlying elliptic curve.
	Curve() Curve

	// v.New() returns a new independent Point instance for the same underlying curve.
	// The returned Point is not initialized, and must be set using SetBytes(...) or Set(...) or used as receiver only.
	New() Point

	// v.Clone() returns a copy of v.
	Clone() Point

	// v.Set(u) sets v = u, and returns v.
	Set(u Point) Point

	// v.Add(p, q) sets v = p + q, and returns v.
	Add(p, q Point) Point

	// v.Subtract(p, q) sets v = p - q, and returns v.
	Subtract(p, q Point) Point

	// v.ScalarBaseMult(x) sets v = x * G, where G is the base point of the curve, and returns v.
	ScalarBaseMult(x Scalar) Point

	// v.ScalarMult(x) sets v = x * q.
	ScalarMult(x Scalar, q Point) Point

	// v.Equal(p) returns true if v is equivalent to u, and false otherwise.
	Equal(u Point) bool

	// v.Bytes() returns the canonical encoding of v.
	// Implementations must ensure a that encoded point on the same curve have a consistent length.
	Bytes() []byte

	// v.SetBytes(x) sets v = x, where x is encoding of v. The encoding must be in the compressed format.
	// If x does not represent a valid point on the curve, SetBytes returns nil and an error and the receiver is
	// unchanged. Otherwise, SetBytes returns v.
	SetBytes(x []byte) (Point, error)
}

type Points []Point

func (p Points) Sum() Point {
	var result Point
	for _, pᵢ := range p {
		if result == nil {
			result = pᵢ.Clone()
		} else {
			result.Add(result, pᵢ)
		}
	}
	return result
}
