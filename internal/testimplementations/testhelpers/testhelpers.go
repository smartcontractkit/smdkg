package testhelpers

import (
	"io"
	"testing"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
	"github.com/smartcontractkit/smdkg/p256keyring"
	"github.com/stretchr/testify/require"
)

func NewP256Keys(t *testing.T, n int, rand io.Reader) ([]dkgtypes.P256Keyring, []dkgtypes.P256PublicKey) {
	krs := make([]dkgtypes.P256Keyring, n)
	eks := make([]dkgtypes.P256PublicKey, n)
	for i := 0; i < n; i++ {
		kr, err := p256keyring.New(rand)
		require.NoError(t, err)

		krInternal, err := p256keyringshim.New(kr)
		require.NoError(t, err)

		krs[i] = krInternal
		eks[i] = krInternal.PublicKey()
	}
	return krs, eks
}

func P256KeysToParticipantPublicKeys(pks []dkgtypes.P256PublicKey) []dkgocrtypes.P256ParticipantPublicKey {
	participantPublicKeys := make([]dkgocrtypes.P256ParticipantPublicKey, len(pks))
	for i, pk := range pks {
		participantPublicKeys[i] = pk.Bytes()
	}
	return participantPublicKeys
}
