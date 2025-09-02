// Constant time implementation of scalar arithmetic based on the bigmod package from Go's internal stdlib, exported
// via flippo.io/bigmod.

package math

import (
	"io"
	"math/big"

	"filippo.io/bigmod"
	"github.com/smartcontractkit/smdkg/internal/codec"
)

// Scalar represents a scalar value in a finite field defined by a modulus.
// Scalars of different moduli are not compatible, and cannot be used together in arithmetic operations.
// TODO: Consider added a runtime checks ensuring that indeed the moduli are the same when performing operations.
// Maybe that is overkill, as throughout an instance of a DKG protocol, only scalars with the same modulus are used.
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

func (s *scalar) IsNil() bool {
	return s == nil
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

// x.Set(y) sets x = y, and returns the scalar x.
// This creates a copy of the value of y, so that x and y can be modified independently.
func (x Scalar) Set(y Scalar) Scalar {
	copy(x.value.Bits(), y.value.Bits())
	return x
}

// x.SetUint(y) sets x = y, returns the scalar x.
// y must be smaller than the modulus of x.
func (x Scalar) SetUint(y uint) Scalar {
	x.value.SetUint(y).ExpandFor(&x.modulus.value)
	return x
}

// x.SetBytes(y) sets x to the scalar represented by the byte slice y, and returns x.
// If y does not represent a valid scalar (of the expected length, and smaller than x.modulus), SetBytes returns an
// error and the receiver is unchanged. Otherwise, SetBytes returns x.
func (x Scalar) SetBytes(y []byte) (Scalar, error) {
	_, err := x.value.SetBytes(y, &x.modulus.value)
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
	s.value.Mod(t, &s.modulus.value)
	return s, nil
}

func (x Scalar) Add(y Scalar) Scalar {
	x.value.Add(y.value, &x.modulus.value)
	return x
}

func (x Scalar) Subtract(y Scalar) Scalar {
	x.value.Sub(y.value, &x.modulus.value)
	return x
}

func (x Scalar) Multiply(y Scalar) Scalar {
	x.value.Mul(y.value, &x.modulus.value)
	return x
}

func (x Scalar) InverseVarTime() (Scalar, bool) {
	_, ok := x.value.InverseVarTime(x.value, &x.modulus.value)
	return x, ok
}

func (x Scalar) Exp(e []byte) Scalar {
	x.value.Exp(x.value, e, &x.modulus.value)
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
func (x Scalar) Modulus() *Modulus {
	return x.modulus
}

// x.Bytes() returns the canonical encoding of x.
func (x Scalar) Bytes() []byte {
	return x.value.Bytes(&x.modulus.value)
}

func (x Scalar) MarshalTo(target codec.Target) {
	target.WriteBytes(x.value.Bytes(&x.modulus.value))
}

func (x Scalar) UnmarshalFrom(source codec.Source) Scalar {
	b := source.ReadBytes(x.modulus.Size())
	_, err := x.value.SetBytes(b, &x.modulus.value)
	if err != nil {
		panic(err)
	}
	return x
}

// Tests two scalars for equality. Only supported for scalars with the same modulus.
func (x Scalar) Equal(y Scalar) bool {
	return x.value.Equal(y.value) == 1
}

// Non-constant time function, to be used for testing purposes.
func (x Scalar) String() string {
	return new(big.Int).SetBytes(x.value.Bytes(&x.modulus.value)).String()
}

func (w Scalars) MarshalTo(target codec.Target) {
	for _, wᵢ := range w {
		wᵢ.MarshalTo(target)
	}
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
