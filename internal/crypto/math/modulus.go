package math

import (
	"math/big"

	"filippo.io/bigmod"
)

type Modulus struct {
	value bigmod.Modulus
}

// Non-constant time function, to be used for testing purposes and initialization only.
// Panics on invalid input; value must represent a natural number.
func NewModulus(value string) *Modulus {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid modulus value: " + value)
	}
	m, err := bigmod.NewModulus(n.Bytes())
	if err != nil {
		panic("invalid modulus value: " + value + ", error: " + err.Error())
	}
	return &Modulus{*m}
}

func (m *Modulus) Equal(other *Modulus) bool {
	return m == other || (&m.value).Nat().Equal((&other.value).Nat()) == 1
}

func (m *Modulus) Size() int {
	return (&m.value).Size()
}

func (m *Modulus) Bytes() []byte {
	return (&m.value).Nat().Bytes(&m.value)
}
