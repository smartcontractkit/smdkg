package dkg

import (
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/testimplementations/unsaferand"
)

// Within this file, a simulated execution of the DKG protocol is implemented. It uses the real cryptographic
// primitives, but does not use any networking. Instead, all participants are represented as objects in memory.
// The key is not actually generated in a distributed manner, but locally on a single machine.
//
// 🚨🚨🚨  SECURITY WARNING                                                       🚨🚨🚨
// ️🚨🚨🚨  This simulation is NOT secure. It is meant for testing purposes only.  🚨🚨🚨
//
// Use the SimulateInitialDKG(...) and SimulateResharingDKG(...) functions which return the result of simulating the
// full DKG execution similar to initializing a DKG instance using NewInitialDKG(...) or NewResharingDKG().

// SimulateInitialDKG simulates a full execution of the initial DKG protocol with the given parameters and returns
// the resulting shared key. The simulation is deterministic for a given InstanceID.
func SimulateInitialDKGForTest(
	iid dkgtypes.InstanceID,
	curve math.Curve,
	dealers []dkgtypes.P256PublicKey,
	recipients []dkgtypes.P256PublicKey,
	f_D int,
	t_R int,
	keyrings []dkgtypes.P256Keyring, // keyrings for all dealers
) (Result, error) {
	dkgs := make([]DKG, len(dealers))
	for i, keyring := range keyrings {
		var err error
		dkgs[i], err = NewInitialDKG(iid, curve, dealers, recipients, f_D, t_R, keyring)
		if err != nil {
			return nil, err
		}
	}
	return simulateDKG(iid, dkgs)
}

// SimulateResharingDKG simulates a full execution of the re-sharing DKG protocol with the given parameters and returns
// the resulting shared key. The simulation is deterministic for a given InstanceID.
func SimulateResharingDKGForTest(
	iid dkgtypes.InstanceID,
	dealers []dkgtypes.P256PublicKey, // must match the prior result's recipients
	recipients []dkgtypes.P256PublicKey,
	f_D int,
	t_R int,
	keyrings []dkgtypes.P256Keyring, // keyrings for all dealers
	prior Result,
) (Result, error) {
	dkgs := make([]DKG, len(dealers))
	for i, keyring := range keyrings {
		var err error
		dkgs[i], err = NewResharingDKG(iid, dealers, recipients, f_D, t_R, keyring, prior)
		if err != nil {
			return nil, err
		}
	}
	return simulateDKG(iid, dkgs)
}

func simulateDKG(iid dkgtypes.InstanceID, dkgs []DKG) (Result, error) {
	var err error

	n_D := len(dkgs[0].Dealers())
	dealingsThreshold := dkgs[0].DealingsThreshold()
	decryptionThreshold := dkgs[0].DecryptionThreshold()

	initialDealings := make([]VerifiedInitialDealing, n_D)
	for i, dkg := range dkgs[:dealingsThreshold] {
		rand := unsaferand.New("simulate-initial-dkg-deal", iid, i)
		initialDealings[i], err = dkg.Deal(rand)
		if err != nil {
			return nil, err
		}
	}

	decryptionShares := make([]VerifiedDecryptionKeySharesForInnerDealings, n_D)
	for i, dkg := range dkgs[:decryptionThreshold] {
		decryptionShares[i], err = dkg.DecryptDecryptionKeyShares(initialDealings)
		if err != nil {
			return nil, err
		}
	}

	innerDealings, _, _, err := dkgs[0].RecoverInnerDealings(initialDealings, decryptionShares)
	if err != nil {
		return nil, err
	}

	return dkgs[0].NewResult(innerDealings)
}
