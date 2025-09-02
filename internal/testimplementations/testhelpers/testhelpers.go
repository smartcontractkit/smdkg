package testhelpers

import (
	"io"
	"testing"

	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/testimplementations"
	"github.com/stretchr/testify/require"
)

func NewP256Keys(t *testing.T, n int, rand io.Reader) ([]dkgtypes.P256Keyring, []dkgtypes.P256PublicKey) {
	krs := make([]dkgtypes.P256Keyring, n)
	eks := make([]dkgtypes.P256PublicKey, n)
	for i := 0; i < n; i++ {
		kr, err := testimplementations.NewRandomP256Keyring(rand)
		require.NoError(t, err)
		krs[i] = kr
		eks[i] = kr.PublicKey()
	}
	return krs, eks
}
