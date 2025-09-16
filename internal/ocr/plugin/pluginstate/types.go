package pluginstate

import (
	"context"
	"sync"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
)

// PluginState holds the state of the reporting plugin. It is safe for concurrent use.
// Only use the New(...) function to create a new - properly initialized - instance.
type PluginState struct {
	cryptoProvider dkg.DKG      // the crypto provider (after initialization) is itself stateless
	mu             sync.RWMutex // mutex to synchronize access to underlying fields

	initialPhase           plugintypes.PluginPhase                // used when no phase is stored in the kv store
	initialBannedDealers   plugintypes.BannedDealers              // used when no banned dealers are stored in the kv store
	initCryptoProviderFunc func(context.Context) (dkg.DKG, error) // used to initialize the crypto provider on access (cached afterwards)

	phaseUnmarshaler codec.Unmarshaler[plugintypes.PluginPhase]

	// Note on cache sizes below: We never delete from the caches, so they will grow over time. However, since per
	// attempt, there is at most one entry a in a cache field per dealer, and the number of attempts is expected to be
	// low and bounded by the number of participants (i.e., in particular the number of bad dealers triggering a
	// restart of the protocol instance), the caches will remain small in practice.

	// Cache storing all outbound initial dealings created by this node. Also stores a reference to the blob handle.
	outboundInitialDealingsCache map[outboundInitialDealingsCacheKey]ocr3_1types.BlobHandle

	// Cache storing all received verified initial dealings to avoid re-verification.
	inboundDealingCache map[inboundInitialDealingsCacheKey]inboundInitialDealingsCacheValue

	// Cache storing all received decryption key shares to avoid re-verification.
	inboundDecryptionKeySharesCache map[inboundDecryptionKeySharesCacheKey]inboundDecryptionKeySharesCacheValue

	// Cache storing the reportsPlusPrecursor for each attempt.
	cachedReportsPlusPrecursor ocr3_1types.ReportsPlusPrecursor
}

func New(
	initialPhase plugintypes.PluginPhase,
	initialBannedDealers plugintypes.BannedDealers,
	initCryptoProviderFunc func(context.Context) (dkg.DKG, error),
	pluginPhaseUnmarshaler codec.Unmarshaler[plugintypes.PluginPhase],
) *PluginState {
	return &PluginState{
		nil,
		sync.RWMutex{},
		initialPhase,
		initialBannedDealers,
		initCryptoProviderFunc,
		pluginPhaseUnmarshaler,
		make(map[outboundInitialDealingsCacheKey]ocr3_1types.BlobHandle),
		make(map[inboundInitialDealingsCacheKey]inboundInitialDealingsCacheValue),
		make(map[inboundDecryptionKeySharesCacheKey]inboundDecryptionKeySharesCacheValue),
		nil,
	}
}

type outboundInitialDealingsCacheKey struct {
	attempt int
}

type inboundInitialDealingsCacheKey struct {
	attempt int
	dealer  int
}

type inboundInitialDealingsCacheValue struct {
	raw      []byte
	verified dkg.VerifiedInitialDealing
}

type inboundDecryptionKeySharesCacheKey struct {
	attempt int
	dealer  int
}

type inboundDecryptionKeySharesCacheValue struct {
	raw      []byte
	verified dkg.VerifiedDecryptionKeySharesForInnerDealings
}
