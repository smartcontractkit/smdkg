package dkg

import (
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/vess"
)

// BandwidthConfig contains the parameters needed to estimate the bandwidth consumption of DKG operations.
type bandwidthParams struct {
	iid         dkgtypes.InstanceID
	curve       math.Curve
	n_D         int  // number of dealers
	f_D         int  // max number of faulty dealers
	n_R         int  // number of recipients
	t_R         int  // threshold for recipients
	isResharing bool // true if resharing, false if fresh dealing
}

type estimates struct {
	EstimatedDealingsThreshold               int
	EstimatedDecryptionThreshold             int
	EstimatedBandwidthForInitialDealing      int
	EstimatedBandwidthForDecryptionKeyShares int
	EstimatedBandwidthForInnerDealings       int
	EstimatedBandwidthForResult              int
}

type BandwidthEstimator struct {
	params bandwidthParams
	N_D    int
	F_D    int
	estimates
}

// Initializes a new BandwidthEstimator with the given parameters.
// If t_D is nil for a resharing, the estimator will use loose estimates that do not depend on t_D.
func NewBandwidthEstimator(iid dkgtypes.InstanceID, curve math.Curve, n_D int, f_D int, n_R int, t_R int, isResharing bool, t_D *int) BandwidthEstimator {
	params := bandwidthParams{iid, curve, n_D, f_D, n_R, t_R, isResharing}
	e := BandwidthEstimator{params, n_D, f_D, estimates{}}
	e.estimates = computeEstimates(params, t_D)
	return e
}

// Updates the t_D parameter of the estimator and recomputes all estimates.
// This should only be called when t_D becomes available for a resharing.
func (e *BandwidthEstimator) UpdateT_D(t_D int) {
	e.estimates = computeEstimates(e.params, &t_D)
}

func computeEstimates(params bandwidthParams, t_D *int) estimates {
	return estimates{
		params.estimateDealingsThreshold(t_D),
		params.estimateDecryptionThreshold(),
		params.estimateBandwidthForInitialDealing(),
		params.estimateBandwidthForDecryptionKeyShares(params.estimateDealingsThreshold(t_D)),
		params.estimateBandwidthForInnerDealings(t_D),
		params.estimateBandwidthForResult(t_D),
	}
}

// Returns the estimated number of dealings needed to be gathered in a DKG instance.
// This is a loose estimate when T_D is not available for resharing.
func (p *bandwidthParams) estimateDealingsThreshold(t_D *int) int {
	if !p.isResharing {
		return p.f_D + 1
	} else {
		if t_D != nil {
			return *t_D
		} else {
			return p.n_D // a loose upper bound
		}
	}
}

// Returns the threshold for decrypting decryption key shares in a DKG instance.
// This is always a tight estimate, as it only depends on F_D.
func (p *bandwidthParams) estimateDecryptionThreshold() int {
	return p.f_D + 1
}

// Returns the estimated bandwidth consumption (in bytes) for an initial dealing.
// This is always a tight estimate, as T_D is not needed for this.
func (p *bandwidthParams) estimateBandwidthForInitialDealing() int {
	// Recall the member fields of an unverified initial dealing unverifiedInitialDealing:
	// 	- 	OD:  *vess.UnverifiedDealing
	// 	- 	EID:  encryptedInnerDealing

	size := 0
	size += vess.EstimateDealingSize(p.curve, p.n_D, p.f_D+1) // OD
	size += vess.EstimateDealingSize(p.curve, p.n_R, p.t_R)   // EID
	size += codec.IntSize                                     // length prefix for EID

	return size
}

// Returns the estimated bandwidth consumption (in bytes) for decryption key shares from a dealer.
// For fresh dealing, this is always a tight estimate, as DealingsThreshold only depends on F_D.
// For resharing, this could be a loose estimate, as DealingsThreshold depends on T_D, which may be unknown at the time of estimation.
func (p *bandwidthParams) estimateBandwidthForDecryptionKeyShares(dealingsThreshold int) int {
	// Recall the member fields of a decryption key shares decryptionKeySharesForInnerDealings:
	// 	-	curve math.Curve
	// 	-	z_D   []math.Scalar

	size := 0
	size += 1                                         // curve type
	size += codec.IntSize                             // length prefix for z_D
	size += p.n_D * 1                                 // bitmask for indicating which shares are present
	size += dealingsThreshold * p.curve.ScalarBytes() // z_{D', D} for all D' ∈ L
	return size
}

// Returns the estimated bandwidth consumption (in bytes) for a list of verified inner dealing.
// For fresh dealing, this is always a tight estimate, as the number of inner dealings only depends on F_D.
// For resharing, this could be a loose estimate, as the number of inner dealings depends on T_D, which may be unknown at the time of estimation.
func (p *bandwidthParams) estimateBandwidthForInnerDealings(t_D *int) int {
	innerDealing := vess.EstimateDealingSize(p.curve, p.n_R, p.t_R)

	size := 0
	size += codec.IntSize                                   // length of L'
	size += p.n_D * 1                                       // bitmask for indicating which dealings are present
	size += p.estimateDealingsThreshold(t_D) * innerDealing // ID_D for all D ∈ L'
	return size
}

// Returns the estimated bandwidth consumption (in bytes) for a result package.
// For fresh dealing, this is always a tight estimate, as the number of inner dealings only depends on F_D.
// For resharing, this could be a loose estimate, as the number of inner dealings depends on T_D, which may be unknown at the time of estimation.
func (p *bandwidthParams) estimateBandwidthForResult(t_D *int) int {
	// Recall the member fields of a decryption key shares decryptionKeySharesForInnerDealings:
	// 	-	iid         dkgtypes.InstanceID
	// 	-	curve       math.Curve
	// 	-	t_R         int
	// 	-	Lꞌ          []VerifiedInnerDealing
	// 	-	y           math.Point
	// 	-	y_R         []math.Point
	// 	-	wasReshared bool

	size := 0
	size += len(p.iid)                               // iid
	size += codec.IntSize                            // length prefix for iid
	size += 1                                        // curve type
	size += codec.IntSize                            // t_r
	size += p.estimateBandwidthForInnerDealings(t_D) // L'
	size += codec.IntSize                            // length of y_R
	size += p.curve.PointBytes()                     // y
	size += p.n_R * p.curve.PointBytes()             // y_R
	size += 1                                        // wasReshared
	return size
}
