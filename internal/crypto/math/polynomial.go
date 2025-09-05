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

// Evaluate a polynomial ω(x) of degree t - 1, with coefficients w[0], w[1], ..., w[t-1], at the point x = i + 1.
// ω(x) = w[0] + w[1] * x + w[2] * x^2 + ... + w[t-1] * x^(t-1)
func (w Polynomial) Eval(i int) Scalar {
	x := w[0].Clone().SetUint(uint(i) + 1) // x = i + 1
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
func (w Polynomial) Commitment(curve Curve) PolynomialCommitment {
	C := make(PolynomialCommitment, len(w))
	for i, wᵢ := range w {
		C[i] = curve.Point().ScalarBaseMult(wᵢ)
	}
	return C
}

// Evaluate a polynomial commitment C at the point x = i + 1.
func (C PolynomialCommitment) Eval(i int) Point {
	if i < 0 {
		panic("polynomial commitment evaluation index must be non-negative")
	}

	sum := C[0].Clone()
	x := C[0].Curve().Scalar().SetUint(uint(i) + 1) // x = i + 1
	xⁱ := x.Clone()                                 // holds xⁱ for i = 1, 2, ..., t-1

	for i := 1; i < len(C); i++ {
		t := C[i].Clone().ScalarMult(xⁱ, C[i]) // t = Cᵢ * xⁱ
		sum.Add(sum, t)                        // sum += t
		if i != len(C)-1 {
			xⁱ.Multiply(x) // x^(i+1) = x^i * x
		}
	}
	return sum
}

// Evaluate a polynomial commitment C at points xᵢ ∈  { 1, 2, ..., n }.
func (C PolynomialCommitment) EvalRange(n int) []Point {
	result := make([]Point, n)
	for i := 0; i < n; i++ {
		result[i] = C.Eval(i)
	}
	return result
}

// lagrangeBasisZero computes the i-th Lagrange basis coefficient evaluated at x = 0
// Concretely: l_i(0) = ∏_{j≠i} (xⱼ / (xⱼ - xᵢ))
//
// All xs must lie in the same field (share the same modulus).
// All xs must be pairwise distinct, otherwise the denominator becomes non-invertible and an error is returned.
func lagrangeBasisZero(i int, xs []Scalar) (Scalar, error) {
	M := xs[0].Modulus()
	numerator := NewScalar(M).SetUint(1)
	denominator := NewScalar(M).SetUint(1)
	tmp := NewScalar(M)

	xᵢ := xs[i]
	for j, xⱼ := range xs {
		if i != j {
			numerator.Multiply(xⱼ)                         // numerator   *= xⱼ
			denominator.Multiply(tmp.Set(xⱼ).Subtract(xᵢ)) // denominator *= xⱼ - xᵢ
		}
	}

	invDenominator, ok := denominator.InverseVarTime()
	if !ok {
		return nil, fmt.Errorf("non-invertible denominator")
	}

	return numerator.Multiply(invDenominator), nil
}

type Interpolator struct {
	curve         Curve
	lagrangeBasis []Scalar // Holds l_i(0) for (i + 1) ∈ indices
}

// Sets up a new interpolator instance for Lagrange interpolation at x = 0, for the given indices.
// Currently the indices are directly mapped to x-coordinates via x = index + 1, i.e., index 0 maps to x = 1,
func NewInterpolator(curve Curve, indices []int) (Interpolator, error) {
	result := Interpolator{
		curve,
		make([]Scalar, len(indices)),
	}

	xs := make([]Scalar, len(indices))
	for i, idx := range indices {
		if idx < 0 {
			return Interpolator{}, fmt.Errorf("failed to initialize interpolator: indices must be non-negative")
		}
		xs[i] = curve.Scalar().SetUint(uint(idx + 1))
	}

	for i := range indices {
		var err error
		result.lagrangeBasis[i], err = lagrangeBasisZero(i, xs)
		if err != nil {
			return Interpolator{}, fmt.Errorf("failed to initialize interpolator: %w", err)
		}
	}
	return result, nil
}

// Performs the lagrange interpolation of the polynomial w given by the points (xᵢ, yᵢ) at x = 0.
func (ip Interpolator) ScalarAtZero(ys []Scalar) (Scalar, error) {
	if len(ys) != len(ip.lagrangeBasis) {
		return nil, fmt.Errorf("mismatching number of points to interpolate")
	}

	var result Scalar
	for i, yᵢ := range ys {
		term := ip.lagrangeBasis[i].Clone().Multiply(yᵢ)
		if result == nil {
			result = term
		} else {
			result.Add(term)
		}
	}
	return result, nil
}

// Performs the Lagrange interpolation of the commitment polynomial C given by the points (xᵢ, Yᵢ) at x = 0.
func (ip Interpolator) PointAtZero(Ys []Point) (Point, error) {
	if len(Ys) != len(ip.lagrangeBasis) {
		return nil, fmt.Errorf("mismatching number of points to interpolate")
	}

	var result Point
	for i, Yᵢ := range Ys {
		term := Yᵢ.Clone().ScalarMult(ip.lagrangeBasis[i], Yᵢ)
		if result == nil {
			result = term
		} else {
			result.Add(result, term)
		}
	}
	return result, nil
}
