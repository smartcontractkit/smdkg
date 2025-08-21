// Constant time implementation of scalar arithmetic based on the bigmod package from Go's internal stdlib, exported
// via flippo.io/bigmod.

package math

import (
	"io"
	"math/big"

	"filippo.io/bigmod"
	"github.com/smartcontractkit/smdkg/internal/serialization"
)

// Scalar represents a scalar value in a finite field defined by a modulus.
// Scalars of different moduli are not compatible, and cannot be used together in arithmetic operations.
// TODO: Consider added a runtime check ensuring that indeed the moduli are the same when performing operations.
//
//	Maybe that is overkill, as throughout an instance of a DKG protocol, only scalars with the same modulus are
//	used.
type Scalar = *scalar
type Scalars []Scalar

type Modulus = *bigmod.Modulus
type Nat = *bigmod.Nat

type ScalarFactory interface {
	Scalar() Scalar
}

type scalar struct {
	value   Nat
	modulus Modulus
}

// NewScalar creates a new scalar with the given modulus.
// The value is initialized to zero.
func NewScalar(m Modulus) Scalar {
	return &scalar{bigmod.NewNat().ExpandFor(m), m}
}

// Non-constant time function, to be used for testing purposes and initialization only.
// Panics on invalid inputs; value must represent a natural number smaller than the modulus.
func NewScalarFromString(value string, modulus Modulus) Scalar {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid scalar value: " + value)
	}

	valueParsed, err := bigmod.NewNat().SetBytes(n.Bytes(), modulus)
	if err != nil {
		panic("invalid scalar value: " + value + ", error: " + err.Error())
	}

	return &scalar{valueParsed, modulus}
}

// Non-constant time function, to be used for testing purposes and initialization only.
// Panics on invalid input; value must represent a natural number.
func NewModulus(value string) *bigmod.Modulus {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid modulus value: " + value)
	}
	m, err := bigmod.NewModulus(n.Bytes())
	if err != nil {
		panic("invalid modulus value: " + value + ", error: " + err.Error())
	}
	return m
}

// x.Set(y) sets x = y, and returns the scalar x.
// This creates a copy of the value of y, so that x and y can be modified independently.
func (x Scalar) Set(y Scalar) Scalar {
	copy(x.value.Bits(), y.value.Bits())
	return x
}

// x.SetUint(y) sets x = y, returns the scalar x.
// y must be smaller than the modulus of x.
func (x Scalar) SetUint(y uint) Scalar {
	x.value.SetUint(y).ExpandFor(x.modulus)
	return x
}

// x.SetBytes(y) sets x to the scalar represented by the byte slice y, and returns x.
// If y does not represent a valid scalar (of the expected length, and smaller than x.modulus), SetBytes returns an
// error and the receiver is unchanged. Otherwise, SetBytes returns x.
func (x Scalar) SetBytes(y []byte) (Scalar, error) {
	_, err := x.value.SetBytes(y, x.modulus)
	if err != nil {
		return nil, err
	}
	return x, nil
}

// x.SetRandom(rand io.Reader) sets x to a random scalar and returns x. We require the random value to be
// sampled with uniformly distributed from {0, 1, 2, ... modulus - 1}. The underlying implementation must ensure
// that a constant number of bytes is read from the provided io.Reader, and that the same scalar is
// deterministically derived from the provided io.Reader.
func (s Scalar) SetRandom(rand io.Reader) (Scalar, error) {
	// Read entropy from the provided io.Reader, 128 bits (16 bytes) more thran the modulus size.
	rngBytes := make([]byte, s.modulus.Size()+16)
	if _, err := io.ReadFull(rand, rngBytes); err != nil {
		return nil, err
	}

	// Build a modulus that is larger than rngBytes (when interpreted as big-endian number).
	largeModBytes := make([]byte, len(rngBytes)+1)
	largeModBytes[0] = 1
	largeMod, err := bigmod.NewModulus(largeModBytes)
	if err != nil {
		return nil, err
	}

	// Convert the random bytes into a Nat (mod largeMod), the value fits and no modulus reduction is needed.
	t := bigmod.NewNat()
	if _, err := t.SetBytes(rngBytes, largeMod); err != nil {
		return nil, err
	}

	// Finally, reduce the value modulo the scalar's modulus. Effectively, this means that the scalar's value will
	// then be uniformly distributed in the range {0, 1, ... s.modulus - 1}.
	s.value.Mod(t, s.modulus)
	return s, nil
}

func (x Scalar) Add(y Scalar) Scalar {
	x.value.Add(y.value, x.modulus)
	return x
}

func (x Scalar) Subtract(y Scalar) Scalar {
	x.value.Sub(y.value, x.modulus)
	return x
}

func (x Scalar) Multiply(y Scalar) Scalar {
	x.value.Mul(y.value, x.modulus)
	return x
}

func (x Scalar) InverseVarTime() (Scalar, bool) {
	_, ok := x.value.InverseVarTime(x.value, x.modulus)
	return x, ok
}

func (x Scalar) Exp(e []byte) Scalar {
	x.value.Exp(x.value, e, x.modulus)
	return x
}

// x.IsZero() returns true if x is zero, and false otherwise.
func (x Scalar) IsZero() bool {
	return x.value.IsZero() == 1
}

// x.IsOne() returns true if x is zero, and false otherwise.
func (x Scalar) IsOne() bool {
	return x.value.IsOne() == 1
}

// Returns an independent copy of the scalar.
func (x Scalar) Clone() Scalar {
	return NewScalar(x.modulus).Set(x)
}

// Returns the internal reference to the modulus underlying the scalar.
// Must not be modified by the caller. Useful for the initialization of new scalars.
func (x Scalar) Modulus() Modulus {
	return x.modulus
}

// x.Bytes() returns the canonical encoding of x.
func (x Scalar) Bytes() []byte {
	return x.value.Bytes(x.modulus)
}

// Non-constant time function, to be used for testing purposes.
func (x Scalar) String() string {
	return new(big.Int).SetBytes(x.value.Bytes(x.modulus)).String()
}

func (w Scalars) Bytes() ([]byte, error) {
	encoder := serialization.NewEncoder()
	for _, wᵢ := range w {
		encoder.WriteBytes(wᵢ.Bytes())
	}
	return encoder.Bytes()
}

func (w Scalars) Sum() Scalar {
	var result Scalar
	for _, wᵢ := range w {
		if result == nil {
			result = wᵢ.Clone()
		} else {
			result.Add(wᵢ)
		}
	}
	return result
}

// type Scalar interface {
// 	// s.Set(x) sets s = x, and returns s.
// 	// Set(x Scalar) Scalar

// 	// The call panics if x is negative. X is reduced modulo the scalar's modulus.
// 	// SetInt(int) Scalar

// 	// s.Add(x, y) sets s = x + y, and returns s.
// 	Add(x, y Scalar) Scalar

// 	// s.AddOne() sets s = x + 1, and returns s.
// 	// AddOne(x Scalar) Scalar

// 	// s.Subtract(x, y) sets s = x - y, and returns s.
// 	Subtract(x, y Scalar) Scalar

// 	// s.Negate(x) sets s = -x, and returns s.
// 	Negate(x Scalar) Scalar

// 	// s.Multiply(x, y) sets s = x * y, and returns s.
// 	Multiply(x, y Scalar) Scalar

// 	// s.Divide(x, y) sets s = x / y, and returns s.
// 	// This is equivalent to s = x * Invert(y).
// 	Divide(x, y Scalar) Scalar

// 	// s.Invert() sets s to the inverse of a nonzero scalar v, and returns s.
// 	// If v is zero, Invert will return zero.
// 	Invert(t Scalar) Scalar

// 	IsZero() bool

// 	// s.Equal(x) returns 1 if s is equivalent to x, and 0 otherwise.
// 	// TODO: Check if returning a boolean would be more common.
// 	Equal(x Scalar) int

// 	// Implementations must ensure that encoded scalars with the same modulus a consistent length.
// 	Bytes() []byte

// 	// s.SetBytes(x) sets s = x, where x is the canonical encoding of a scalar. If x does not represent a valid scalar
// 	// (of the expected length), SetBytes returns nil and an error and the receiver is unchanged. Otherwise, SetBytes
// 	// returns v.
// 	SetBytes(x []byte) (Scalar, error)

// 	SetRandom(rand io.Reader) (Scalar, error)

// 	// TODO: add if needed
// 	// SetRandomNonZero(io.Reader) (Scalar, error)
// }
