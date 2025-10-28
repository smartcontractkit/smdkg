package testhelpers

import (
	"io"
	"testing"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"

	"github.com/stretchr/testify/require"

	keyringHelpers "github.com/smartcontractkit/smdkg/internal/testimplementations/testhelpers"
)

func NewDKGs(
	t *testing.T, iid dkgtypes.InstanceID, curve math.Curve, dealers []dkgtypes.P256PublicKey,
	recipients []dkgtypes.P256PublicKey, f_D, t_R int, priorResult dkg.Result, keyrings []dkgtypes.P256Keyring,
) []dkg.DKG {
	dkgs := make([]dkg.DKG, len(dealers))
	if priorResult == nil {
		for i := range dealers {
			var err error
			dkgs[i], err = dkg.NewInitialDKG(iid, curve, dealers, recipients, f_D, t_R, keyrings[i])
			require.NoError(t, err)
		}
	} else {
		for i := range dealers {
			var err error
			dkgs[i], err = dkg.NewResharingDKG(iid, dealers, recipients, f_D, t_R, keyrings[i], priorResult, 0)
			require.NoError(t, err)
		}
	}
	return dkgs
}

func NewDKGResults(
	t *testing.T, iid dkgtypes.InstanceID, curve math.Curve, dealers []dkgtypes.P256PublicKey,
	recipients []dkgtypes.P256PublicKey, f_D, t_R int, priorResult dkg.Result, keyrings []dkgtypes.P256Keyring,
	rand io.Reader,
) (plugintypes.InitialDealings, plugintypes.DecryptionKeyShares, plugintypes.InnerDealings, plugintypes.ResultPackage) {
	dkgs := NewDKGs(t, iid, curve, dealers, recipients, f_D, t_R, priorResult, keyrings)

	dealings := make(plugintypes.InitialDealings, len(dealers))
	for i := range dkgs[0].DealingsThreshold() {
		var err error
		dealings[i], err = dkgs[i].Deal(rand)
		require.NoErrorf(t, err, "Failed to create dealing for dealer %d", i)
	}

	decryptionShares := make(plugintypes.DecryptionKeyShares, len(dealers))
	for i := range dkgs[0].DecryptionThreshold() {
		var err error
		decryptionShares[i], err = dkgs[i].DecryptDecryptionKeyShares(dealings)
		require.NoError(t, err)
	}

	innerDealings, _, _, err := dkgs[0].RecoverInnerDealings(dealings, decryptionShares)
	require.NoError(t, err, "Failed to recover inner dealings for fresh dealing")

	result, err := dkgs[0].NewResult(innerDealings)
	require.NoError(t, err, "Failed to create result from inner dealings")

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("failed to read nonce: %v", err)
	}

	pluginConfig := dkgocrtypes.ReportingPluginConfig{
		keyringHelpers.P256KeysToParticipantPublicKeys(dealers),
		keyringHelpers.P256KeysToParticipantPublicKeys(recipients),
		t_R,
		nil,
		nonce,
	}
	resultPackage := plugintypes.ResultPackage{result, &pluginConfig}

	return dealings, decryptionShares, innerDealings, resultPackage
}
