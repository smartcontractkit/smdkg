package vess

import (
	"fmt"
	stdmath "math"
	"math/big"

	"github.com/smartcontractkit/smdkg/internal/crypto/math"
)

type candidateParams struct {
	N           int
	M           int
	DealingSize int
}

// Computes a set of suitable parameters for the VESS protocol based on the given security level with different
// trade-offs between compute cost and size of the dealing. The returned parameters are sorted by increasing compute
// cost (N) and decreasing dealing size.
func candidateParameters(curve math.Curve, n int, t int, statisticalSecurityBits int) []candidateParams {
	// Checks if the parameter choices N and M are sufficient for the given security level.
	achievesSecurityLevel := func(N, M int) bool {
		choices := new(big.Int).Binomial(int64(N), int64(M))
		return choices.BitLen() > statisticalSecurityBits
	}

	// Determine the initial parameters N and M that are sufficient for the security level.
	N, M := 2, 1
	for !achievesSecurityLevel(N, M) {
		N += 2
		M += 1
	}
	for achievesSecurityLevel(N, M-1) {
		M--
	}

	minDealingSize := dealingSize(curve, n, t, N, M)

	params := make([]candidateParams, 0)
	params = append(params, candidateParams{N, M, minDealingSize})

	for {
		N++
		if !achievesSecurityLevel(N, M-1) {
			continue
		}
		M--
		for achievesSecurityLevel(N, M-1) {
			M--
		}

		currentDealingSize := dealingSize(curve, n, t, N, M)
		if currentDealingSize > minDealingSize {
			break
		}

		minDealingSize = currentDealingSize
		params = append(params, candidateParams{N, M, currentDealingSize})
	}

	return params
}

// Selects the optimal parameters from the given candidates based on the computeWeight. The computeWeight is a (%-)value
// in the range [0..100] that determines the weight of the compute cost relative to the size of the dealing. A value of
// 0 means that the size is the only factor, while a value of 100 means that the compute cost is the only factor.
// Only pass results from candidateParameters() to this function, the function assumes that the candidates are sorted
// by increasing N / decreasing dealing size.
func selectOptimalParameters(params []candidateParams, computeWeight int) candidateParams {
	if computeWeight < 0 || computeWeight > 100 {
		panic("computeWeight must be in the range [0, 100], got: " + fmt.Sprint(computeWeight))
	}
	sizeWeight := 100 - computeWeight

	// Normalize the parameters to a common scale for a fair balancing.
	minSize, maxSize := params[len(params)-1].DealingSize, params[0].DealingSize
	minRepetitions, maxRepetitions := params[0].N, params[len(params)-1].N
	rangeSize := maxSize - minSize
	rangeRepetitions := maxRepetitions - minRepetitions
	scaleSize := 1_000_000_000 / int64(rangeSize)
	scaleRepetitions := 1_000_000_000 / int64(rangeRepetitions)

	var minWeight int64 = stdmath.MaxInt64
	bestParams := candidateParams{}

	for _, p := range params {
		normalizedSize := int64(p.DealingSize-minSize) * scaleSize
		normalizedRepetitions := int64(p.N-minRepetitions) * scaleRepetitions
		weight := (normalizedSize * int64(sizeWeight)) + (normalizedRepetitions * int64(computeWeight))
		if weight < minWeight {
			minWeight = weight
			bestParams = p
		}
	}
	return bestParams
}
