// Constant time implementation of scalar arithmetic based on the bigmod package from Go's internal stdlib, exported
// via filippo.io/bigmod.

package math

import (
	"io"
	"math/big"

	"filippo.io/bigmod"
	"github.com/smartcontractkit/smdkg/internal/codec"
)

// Scalar represents a scalar value in a finite field defined by a modulus.
// Scalars of different moduli are not compatible, and cannot be used together in arithmetic operations.
// Executing any arithmetic operation on scalars with different moduli will result in a panic.

type Scalar = *scalar
type Scalars []Scalar

type Nat = *bigmod.Nat

type ScalarFactory interface {
	Scalar() Scalar
}

var _ codec.Codec[*scalar] = &scalar{}

type scalar struct {
	value   Nat
	modulus *Modulus
}

// NewScalar creates a new scalar with the given modulus.
// The value is initialized to zero.
func NewScalar(m *Modulus) Scalar {
	return &scalar{bigmod.NewNat().ExpandFor(&m.value), m}
}

// Non-constant time function, to be used for testing purposes and initialization only.
// Panics on invalid inputs; value must represent a natural number smaller than the modulus.
func NewScalarFromString(value string, modulus *Modulus) Scalar {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid scalar value: " + value)
	}

	valueParsed, err := bigmod.NewNat().SetBytes(n.Bytes(), &modulus.value)
	if err != nil {
		panic("invalid scalar value: " + value + ", error: " + err.Error())
	}

	return &scalar{valueParsed, modulus}
}

func (s *scalar) IsNil() bool {
	return s == nil
}

// x.Set(y) sets x = y, and returns the scalar x.
// This creates a copy of the value of y, so that x and y can be modified independently.
// This functions panics if x and y have different moduli.
func (x *scalar) Set(y Scalar) Scalar {
	requireEqualModulus(x, y)
	copy(x.value.Bits(), y.value.Bits())
	return x
}

// x.SetUint(y) sets x = y, returns the scalar x.
// y must be smaller than the modulus of x.
func (x *scalar) SetUint(y uint) Scalar {
	x.value.SetUint(y).ExpandFor(&x.modulus.value)
	return x
}

// x.SetBytes(y) sets x to the scalar represented by the byte slice y, and returns x.
// If y does not represent a valid scalar (of the expected length, and smaller than x.modulus), SetBytes returns an
// error and the receiver is unchanged. Otherwise, SetBytes returns x.
func (x *scalar) SetBytes(y []byte) (Scalar, error) {
	_, err := x.value.SetBytes(y, &x.modulus.value)
	if err != nil {
		return nil, err
	}
	return x, nil
}

// x.SetRandom(rand io.Reader) sets x to a random scalar and returns x. We require the random value to be
// sampled with uniformly distributed from {0, 1, 2, ... modulus - 1}. The underlying implementation ensures
// that a constant number of bytes is read from the provided io.Reader, and that the same scalar is
// deterministically derived from the provided io.Reader.
func (s *scalar) SetRandom(rand io.Reader) (Scalar, error) {
	// Read entropy from the provided io.Reader, 128 bits (16 bytes) more than the modulus size.
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
	// then be statistically close to uniformly distributed in range {0, 1, ... s.modulus - 1}.
	s.value.Mod(t, &s.modulus.value)
	return s, nil
}

// x.Add(y) computes x = x + y (mod modulus), and returns x.
// This functions panics if x and y have different moduli.
func (x *scalar) Add(y Scalar) Scalar {
	requireEqualModulus(x, y)
	x.value.Add(y.value, &x.modulus.value)
	return x
}

// x.Subtract(y) computes x = x - y (mod modulus), and returns x.
// This functions panics if x and y have different moduli.
func (x *scalar) Subtract(y Scalar) Scalar {
	requireEqualModulus(x, y)
	x.value.Sub(y.value, &x.modulus.value)
	return x
}

// x.Multiply(y) computes x = x * y (mod modulus), and returns x.
// This functions panics if x and y have different moduli.
func (x *scalar) Multiply(y Scalar) Scalar {
	requireEqualModulus(x, y)
	x.value.Mul(y.value, &x.modulus.value)
	return x
}

// x.InverseVarTime() computes the modular inverse of x = x^-1 and returns (x, true) if the inverse exists, or
// (nil, false) otherwise.
func (x *scalar) InverseVarTime() (Scalar, bool) {
	if _, ok := x.value.InverseVarTime(x.value, &x.modulus.value); !ok {
		return nil, false
	}
	return x, true
}

// x.Exp(e) computes x = x^e (mod modulus), and returns x.
// The exponent e is interpreted as a big-endian integer.
func (x *scalar) Exp(e []byte) Scalar {
	x.value.Exp(x.value, e, &x.modulus.value)
	return x
}

// x.IsZero() returns true if x is zero, and false otherwise.
func (x *scalar) IsZero() bool {
	return x.value.IsZero() == 1
}

// x.IsOne() returns true if x is zero, and false otherwise.
func (x *scalar) IsOne() bool {
	return x.value.IsOne() == 1
}

// Returns an independent copy of the scalar.
func (x *scalar) Clone() Scalar {
	return NewScalar(x.modulus).Set(x)
}

// Returns the internal reference to the modulus underlying the scalar.
// Must not be modified by the caller. Useful for the initialization of new scalars.
func (x *scalar) Modulus() *Modulus {
	return x.modulus
}

// x.Bytes() returns the canonical encoding of x.
func (x *scalar) Bytes() []byte {
	return x.value.Bytes(&x.modulus.value)
}

// MarshalTo writes the canonical encoding of x to the provided codec.Target.
func (x *scalar) MarshalTo(target codec.Target) {
	target.WriteBytes(x.value.Bytes(&x.modulus.value))
}

// UnmarshalFrom reads the canonical encoding of a scalar from the provided codec.Source, sets it to x, and returns x.
// The scalar x must have non-nil modulus, otherwise UnmarshalFrom panics.
func (x *scalar) UnmarshalFrom(source codec.Source) Scalar {
	b := source.ReadBytes(x.modulus.Size())
	_, err := x.value.SetBytes(b, &x.modulus.value)
	if err != nil {
		panic(err)
	}
	return x
}

// x.Equal(y) tests two scalars for equality. Equality is defined as having the same value and the same modulus.
func (x *scalar) Equal(y Scalar) bool {
	return x == y || (x.value.Equal(y.value) == 1 && x.modulus.Equal(y.modulus))
}

// x.String() returns a human readable representation of the scalar's value. It is a non-constant time function, to be
// used for testing purposes.
func (x *scalar) String() string {
	return new(big.Int).SetBytes(x.value.Bytes(&x.modulus.value)).String()
}

// Checks that two scalars have the same modulus, and panics otherwise.
// This is a helper function to be used at the beginning of arithmetic operations.
// The check is typically very cheap, as it only compares pointers to the modulus in the first step.
func requireEqualModulus(x Scalar, y Scalar) {
	if !x.modulus.Equal(y.modulus) {
		panic("scalars have different moduli")
	}
}

// MarshalTo writes the canonical encoding of all scalars in ω to the provided codec.Target.
func (ω Scalars) MarshalTo(target codec.Target) {
	for _, ωᵢ := range ω {
		ωᵢ.MarshalTo(target)
	}
}

// ω.Sum() returns the sum of all scalars in ω. If ω is empty, Sum returns nil.
func (ω Scalars) Sum() Scalar {
	var result Scalar
	for _, ωᵢ := range ω {
		if result == nil {
			result = ωᵢ.Clone()
		} else {
			result.Add(ωᵢ)
		}
	}
	return result
}

// ScalarsAddElementWise returns a new slice where each element is the sum of the corresponding elements in scalars1
// and scalars2. Panics if the two slices have different lengths.
func ScalarsAddElementWise(scalars1, scalars2 Scalars) Scalars {
	if len(scalars1) != len(scalars2) {
		panic("cannot add scalars slices of different lengths")
	}
	result := make(Scalars, len(scalars1))
	for i := range scalars1 {
		result[i] = scalars1[i].Clone().Add(scalars2[i])
	}
	return result
}
