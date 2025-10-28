package dummydkg

import (
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/p256keyringshim"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin/plugintypes"
	"github.com/smartcontractkit/smdkg/internal/testimplementations/unsaferand"
	"github.com/smartcontractkit/smdkg/p256keyring"
)

type ResultPackage struct {
	inner  dkg.Result
	config *dkgocrtypes.ReportingPluginConfig
}

func (r *ResultPackage) MarshalTo(target codec.Target) {
	target.Write(r.inner)
	configBytes, err := r.config.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("failed to marshal config: %v", err))
	}
	target.WriteLengthPrefixedBytes(configBytes)
}

func Setup(n_D, n_R, t_R int, seed string) (
	dkgocrtypes.InstanceID, dkgocrtypes.ReportingPluginConfig,
	[]dkgocrtypes.P256Keyring, []dkgocrtypes.P256Keyring, *unsaferand.UnsafeRand, error,
) {
	var err error

	// Setup a deterministic random number generator based on the instance ID.
	rand := unsaferand.New("DummyDKG-Setup", seed, n_D, n_R, t_R)

	// Generate a unique instance ID based on the seed.
	// This is a placeholder!
	iid := dkgocrtypes.MakeInstanceID(
		common.HexToAddress("0x514910771af9ca656af840dff83e8264ecf986ca"),
		sha256.Sum256([]byte(seed)),
	)

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", dkgocrtypes.ReportingPluginConfig{}, nil, nil, nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	// Initialize keyrings and public keys for all dealers.
	dealers := make([]dkgocrtypes.P256ParticipantPublicKey, n_D)
	dealerKeyrings := make([]dkgocrtypes.P256Keyring, n_D)
	for i := 0; i < n_D; i++ {
		if dealerKeyrings[i], err = p256keyring.New(rand); err != nil {
			return "", dkgocrtypes.ReportingPluginConfig{}, nil, nil, nil, err
		}
		dealers[i] = dealerKeyrings[i].PublicKey()
	}

	// Initialize keyrings and public keys for all recipients.
	recipients := make([]dkgocrtypes.P256ParticipantPublicKey, n_R)
	recipientKeyrings := make([]dkgocrtypes.P256Keyring, n_R)
	for i := 0; i < n_R; i++ {
		if recipientKeyrings[i], err = p256keyring.New(rand); err != nil {
			return "", dkgocrtypes.ReportingPluginConfig{}, nil, nil, nil, err
		}
		recipients[i] = recipientKeyrings[i].PublicKey()
	}

	// Create a DKG configuration.
	config := dkgocrtypes.ReportingPluginConfig{
		dealers,    // public keys of the dealers
		recipients, // public keys of the recipients
		t_R,        // number of shares needed to reconstruct the master secret key
		nil,        // no previous instance ID, fresh DKG run
		nonce,      // random nonce
	}

	return iid, config, dealerKeyrings, recipientKeyrings, rand, nil
}

// Simulates the execution of a DKG protocol and returns its result. This demo implementation generates a DKG result
// locally, but follows the DKG interface definitions. Simulating the execution requires passing all dealers' keyrings,
// corresponding to the public keys in config.DealerPublicKeys.
func NewResultPackage(
	iid dkgocrtypes.InstanceID, config dkgocrtypes.ReportingPluginConfig, keyrings []dkgocrtypes.P256Keyring,
) (dkgocrtypes.ResultPackage, error) {
	var err error
	curve := math.P256

	n_D := len(config.DealerPublicKeys)
	f_D := (n_D - 1) / 3
	n_R := len(config.RecipientPublicKeys)
	t_R := config.T

	dealers := make([]dkgtypes.P256PublicKey, n_D)
	dealersKeyrings := make([]dkgtypes.P256Keyring, n_D)

	for i, keyring := range keyrings {
		if dealers[i], err = dkgtypes.NewP256PublicKey(config.DealerPublicKeys[i]); err != nil {
			return nil, err
		}
		dealersKeyrings[i], err = p256keyringshim.New(keyring)
		if err != nil {
			return nil, err
		}
		if !dealers[i].Equal(dealersKeyrings[i].PublicKey()) {
			return nil, fmt.Errorf("dealer keyring %d does not match the corresponding public key in the config", i)
		}
	}

	recipients := make([]dkgtypes.P256PublicKey, n_R)
	for i, pk := range config.RecipientPublicKeys {
		if recipients[i], err = dkgtypes.NewP256PublicKey(pk); err != nil {
			return nil, err
		}
	}

	result, err := dkg.SimulateInitialDKGForTest(dkgtypes.InstanceID(iid), curve, dealers, recipients, f_D, t_R, dealersKeyrings)
	if err != nil {
		return nil, err
	}

	return &plugintypes.ResultPackage{result, &config}, nil
}
