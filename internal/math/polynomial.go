package math

import (
	"errors"
	"fmt"
	"io"
)

type Polynomial = Scalars
type PolynomialCommitment []Point

type ScalarShare struct {
	X Scalar
	Y Scalar
}

type ScalarShares []ScalarShare

// Initialize a the coefficients for random polynomial ω(x) of degree t - 1, with its first coefficient being set to the
// secret s. Note that a degree t - 1 polynomial has t coefficients (including s).
func RandomPolynomial(s Scalar, t int, rand io.Reader) (Polynomial, error) {
	if t <= 0 {
		return nil, errors.New("invalid polynomial degree")
	}

	coefficients := make(Polynomial, t)
	coefficients[0] = s
	for i := 1; i < t; i++ {
		var err error
		coefficients[i], err = NewScalar(s.Modulus()).SetRandom(rand)
		if err != nil {
			return nil, err
		}
	}
	return coefficients, nil
}

// Evaluate a polynomial ω(x) of degree t - 1, with coefficients w[0], w[1], ..., w[t-1], at the point x.
// ω(x) = w[0] + w[1] * x + w[2] * x^2 + ... + w[t-1] * x^(t-1)
func (w Polynomial) Eval(x Scalar) Scalar {
	sum := w[0].Clone()
	xPowI := x.Clone() // holds x^i for i = 1, 2, ..., t-1
	for i := 1; i < len(w); i++ {
		t := w[i].Clone().Multiply(xPowI) // t = w[i] * x^i
		sum.Add(t)                        // sum += t
		if i != len(w)-1 {
			xPowI.Multiply(x) // x^(i+1) = x^i * x
		}
	}
	return sum
}

// Return the commitment vector g^[w] <-- [g^w[0], g^w[1], ..., g^w[t-1]], where g is the base point of the curve.
func (w Polynomial) Commitment(c Curve) PolynomialCommitment {
	commitment := make(PolynomialCommitment, len(w))
	for i, wᵢ := range w {
		commitment[i] = c.Point().ScalarBaseMult(wᵢ)
	}
	return commitment
}

func (w PolynomialCommitment) Eval(x Scalar) Point {
	sum := w[0].Clone()
	xᶺi := x.Clone() // holds x^i for i = 1, 2, ..., t-1

	for i := 1; i < len(w); i++ {
		t := w[i].Clone().ScalarMult(xᶺi, w[i]) // t = w[i] * x^i
		sum.Add(sum, t)                         // sum += t
		if i != len(w)-1 {
			xᶺi.Multiply(x) // x^(i+1) = x^i * x
		}
	}
	return sum
}

func lagrangeBasisZero(i int, xs []Scalar) (Scalar, error) {
	M := xs[0].Modulus()
	numerator := NewScalar(M).SetUint(1)
	denominator := NewScalar(M).SetUint(1)
	negXj := NewScalar(M)
	difXij := NewScalar(M)

	for j := range xs {
		if i != j {
			negXj.SetUint(0).Subtract(xs[j]) // negXj       <-- -x_j
			difXij.Set(xs[i]).Add(negXj)     // difXij      <-- x_i - x_j
			numerator.Multiply(negXj)        // numerator   <-- numerator * (-x_j)
			denominator.Multiply(difXij)     // denominator <-- denominator * (x_i - x_j)
		}
	}

	_, ok := denominator.InverseVarTime() // denominator <-- inv(denominator)
	if !ok {
		return nil, fmt.Errorf("non-invertible denominator")
	}

	numerator.Multiply(denominator) // numerator <-- numerator / denominator
	return numerator, nil
}

// Interpolates a polynomial described by the points (xᵢ, xᵢ) at x = 0.
func InterpolatePolynomialZero(xs []Scalar, ys []Scalar) (Scalar, error) {
	var result Scalar
	for i := range xs {
		term, err := lagrangeBasisZero(i, xs)
		if err != nil {
			return nil, err
		}

		term.Multiply(ys[i])
		if result == nil {
			result = term
		} else {
			result.Add(term)
		}
	}
	return result, nil
}

// Interpolates a polynomial commitment described by the points (xᵢ, yᵢ) at x = 0.
func InterpolateCommitmentZero(xs []Scalar, ys []Point) (Point, error) {
	var result Point
	for i := range xs {
		basis, err := lagrangeBasisZero(i, xs)
		if err != nil {
			return nil, err
		}

		term := ys[i].Clone().ScalarMult(basis, ys[i])
		if result == nil {
			result = term
		} else {
			result.Add(result, term)
		}
	}
	return result, nil
}
