package plugin

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/kv"
)

// The estimator of ocr3_1types.ReportingPluginLimits for a DKG instance
type limitsEstimator struct {
	pluginConfigLength int
	bandwidthEstimator dkg.BandwidthEstimator
	limits             ocr3_1types.ReportingPluginLimits
}

// Initializes a new limitsEstimator with the given parameters.
// If t_D is nil for a resharing, the estimator will use loose estimates that do not depend on t_D.
func NewLimitsEstimator(
	iid dkgtypes.InstanceID, curve math.Curve, n_D int, f_D int, n_R int, t_R int,
	isResharing bool, t_D *int, pluginConfigLength int,
) limitsEstimator {
	be := dkg.NewBandwidthEstimator(iid, curve, n_D, f_D, n_R, t_R, isResharing, t_D)
	limits := reportingPluginLimits(&be, pluginConfigLength)
	return limitsEstimator{pluginConfigLength, be, limits}
}

// Updates the t_D parameter of the estimator and recomputes all estimates.
// This should only be called when t_D becomes available for a resharing.
func (e *limitsEstimator) UpdateT_D(t_D int) {
	e.bandwidthEstimator.UpdateT_D(t_D)
	e.limits = reportingPluginLimits(&e.bandwidthEstimator, e.pluginConfigLength)
}

// Returns a copy of loosened limits by the given percentage (e.g., 20 means increase each limit by 20%).
// Note that MaxQueryLength and MaxReportCount are not changed.
func (e *limitsEstimator) LoosenedLimitsByPercentage(percentage int) ocr3_1types.ReportingPluginLimits {
	factor := 1 + float64(percentage)/100.0

	return ocr3_1types.ReportingPluginLimits{
		e.limits.MaxQueryLength, // keep this unchanged
		int(float64(e.limits.MaxObservationLength) * factor),
		int(float64(e.limits.MaxReportsPlusPrecursorLength) * factor),
		int(float64(e.limits.MaxReportLength) * factor),
		e.limits.MaxReportCount, // keep this unchanged
		int(float64(e.limits.MaxKeyValueModifiedKeysPlusValuesLength) * factor),
		int(float64(e.limits.MaxBlobPayloadLength) * factor),
	}
}

// Returns the limits for the reporting plugin based on the given bandwidth estimator and plugin config length.
func reportingPluginLimits(estimator *dkg.BandwidthEstimator, pluginConfigLength int) ocr3_1types.ReportingPluginLimits {
	return ocr3_1types.ReportingPluginLimits{
		0, // MaxQueryLength: Not sending any thing via Query
		estimateObservationLength(estimator),
		estimateReportsPlusPrecursorLength(estimator, pluginConfigLength),
		estimateReportLength(estimator, pluginConfigLength),
		1, // MaxReportCount: Only one report, the dkg result package, is transmitted in each round
		estimateKeyValueModifiedKeysPlusValuesLength(estimator),
		estimateBlobPayloadLength(estimator),
	}
}

// Estimates the length of a blob handle based on the given bandwidth estimator.
func estimateBlobHandleLength(estimator *dkg.BandwidthEstimator) int {
	// [TODO] temporary measure as below; must be replaced before production!!!
	// (sha256.Size*(len(payload)+chunkSize-1)/chunkSize + ed25519.SignatureSize*(n-f) + 256) * 3

	payload := estimator.EstimatedBandwidthForInitialDealing
	chunkSize := 1024 * 1024 // 1 MiB chunks
	numChunks := (payload + chunkSize - 1) / chunkSize
	chunkDigests := sha256.Size * numChunks

	numSigs := estimator.N_D - estimator.F_D // n-f
	signatures := ed25519.SignatureSize * numSigs
	return (chunkDigests + signatures + 256) * 3
}

// MaxObservationLength: max(blob handle, decryption key shares)
func estimateObservationLength(estimator *dkg.BandwidthEstimator) int {
	return max(estimateBlobHandleLength(estimator), estimator.EstimatedBandwidthForDecryptionKeyShares)
}

// MaxReportsPlusPrecursorLength: length of ResultPackage
func estimateReportsPlusPrecursorLength(estimator *dkg.BandwidthEstimator, pluginConfigLength int) int {
	size := 0
	size += estimator.EstimatedBandwidthForResult // Result
	size += codec.IntSize                         // Length prefix for config
	size += pluginConfigLength                    // ReportingPluginConfig
	return size
}

// MaxReportLength: length of ResultPackage
func estimateReportLength(estimator *dkg.BandwidthEstimator, pluginConfigLength int) int {
	return estimateReportsPlusPrecursorLength(estimator, pluginConfigLength)
}

// MaxKeyValueModifiedKeysPlusValuesLength: the max size of modification to the kv store in a single transaction
// For estimating the upper bound, we assume all entries are written in a single transaction
func estimateKeyValueModifiedKeysPlusValuesLength(estimator *dkg.BandwidthEstimator) int {
	// in each instance of dkg, these are written to the kv store:
	// 	- 	pluginState
	// 	- 	bannedDealers
	// 	- 	initialDealings
	// 	- 	decryptionKeyShares
	// 	- 	innerDealings

	initialDealing := estimator.EstimatedBandwidthForInitialDealing           // initialDealing size
	decryptionKeyShares := estimator.EstimatedBandwidthForDecryptionKeyShares // decryptionKeyShares size
	innerDealings := estimator.EstimatedBandwidthForInnerDealings             // innerDealings size

	size := 0

	// pluginState
	size += len(kv.PluginStateKey()) // key
	size += codec.IntSize            // value (state)
	size += codec.IntSize            // value (countRestart)

	// bannedDealers
	size += len(kv.BannedDealersKey()) // key
	size += codec.IntSize              // value (length prefix)
	size += estimator.N_D * 1          // value (bool per dealer)

	// initialDealings
	size += len(kv.InitialDealingsKey(0))                         // key
	size += codec.IntSize                                         // value (length prefix)
	size += estimator.N_D * 1                                     // value (bit mask for nil indicating which dealings are present)
	size += estimator.EstimatedDealingsThreshold * initialDealing // value (dealings)

	// decryptionKeyShares
	size += len(kv.DecryptionKeySharesKey(0))                            // key
	size += codec.IntSize                                                // value (length prefix)
	size += estimator.N_D * 1                                            // value (bit mask for nil indicating which shares are present)
	size += estimator.EstimatedDecryptionThreshold * decryptionKeyShares // value (shares)

	// innerDealings
	size += len(kv.InnerDealingsKey(0)) // key
	size += innerDealings               // value (estimated size of inner dealings)

	return size
}

// MaxBlobPayloadLength: length of an initial dealing
func estimateBlobPayloadLength(estimator *dkg.BandwidthEstimator) int {
	return estimator.EstimatedBandwidthForInitialDealing
}
