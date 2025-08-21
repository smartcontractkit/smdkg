package dummydkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	unsafeRand "math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
)

var _ dkgocrtypes.P256Keyring = &P256Keyring{}

type P256Keyring struct {
	keypair dkgtypes.P256KeyPair
}

func (kr *P256Keyring) ECDH(publicKey dkgocrtypes.P256ParticipantPublicKey) (dkgocrtypes.P256ECDHSharedSecret, error) {
	pk, err := dkgtypes.NewP256PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return kr.keypair.SecretKey.ECDH(pk)
}

func (kr *P256Keyring) PublicKey() dkgocrtypes.P256ParticipantPublicKey {
	return kr.keypair.PublicKey.Bytes()
}

func NewP256Keyring(rand io.Reader) (dkgocrtypes.P256Keyring, error) {
	kp, err := dkgtypes.NewP256KeyPair(rand)
	if err != nil {
		return nil, err
	}
	return &P256Keyring{kp}, nil
}

func Setup(n, t int, seed string) (
	dkgocrtypes.InstanceID,
	dkgocrtypes.ReportingPluginConfig,
	[]dkgocrtypes.P256Keyring,
	io.Reader,
	error,
) {
	// Setup a deterministic random number generator based on the instance ID.
	rand := randFromSeed(seed)
	seed = fmt.Sprintf("DummyDKG(n=%d, t=%d, seed=%v)", n, t, seed)

	// Generate a unique instance ID based on the seed.
	// This is a placeholder!
	iid := dkgocrtypes.MakeInstanceID(
		common.HexToAddress("0x514910771af9ca656af840dff83e8264ecf986ca"),
		sha256.Sum256([]byte(seed)),
	)

	// Initialize keyrings for all participants.
	recipientKeyrings := make([]dkgocrtypes.P256Keyring, n)
	for i := 0; i < n; i++ {
		recipientKeyring, err := NewP256Keyring(rand)
		if err != nil {
			return "", dkgocrtypes.ReportingPluginConfig{}, nil, nil, fmt.Errorf("failed to create keyring for participant %d: %w", i, err)
		}
		recipientKeyrings[i] = recipientKeyring
	}

	// Get the public keys of all participants.
	recipientPublicKeys := make([]dkgocrtypes.P256ParticipantPublicKey, n)
	for i, keyring := range recipientKeyrings {
		recipientPublicKeys[i] = keyring.PublicKey()
	}

	// Create a DKG configuration.
	config := dkgocrtypes.ReportingPluginConfig{
		nil,                 // public keys of the dealers (not used by the dummy DKG implementation)
		recipientPublicKeys, // public keys of the recipients.
		t,                   // number of shares needed to reconstruct the master secret key
		nil,                 // no previous instance ID, fresh DKG run
	}

	return iid, config, recipientKeyrings, rand, nil
}

var _ dkgocrtypes.ResultPackage = &ResultPackage{}

type ResultPackage struct {
	iid    dkgocrtypes.InstanceID
	config dkgocrtypes.ReportingPluginConfig
	mpk    math.Point
	mpks   []math.Point
	msks   []math.Scalar
}

// Simulates the execution of a DKG protocol and returns its result. This demo implementation generates a DKG result
// locally, but follows the DKG interface definitions.
func NewResultPackage(iid dkgocrtypes.InstanceID, config dkgocrtypes.ReportingPluginConfig, rand io.Reader) (dkgocrtypes.ResultPackage, error) {
	t := config.T
	n := len(config.RecipientPublicKeys)
	curve := math.P256

	// Generate a master secret centrally.
	msk, err := curve.Scalar().SetRandom(rand)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master secret key")
	}

	// Compute the corresponding master public key.
	mpk := curve.Point().ScalarBaseMult(msk)

	// Setup a random polynomial to share it.
	poly, err := math.RandomPolynomial(msk, t, rand)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polynomial: %w", err)
	}

	// Compute the shares.
	msks := make([]math.Scalar, n)
	mpks := make([]math.Point, n)
	for i := 0; i < n; i++ {
		x := curve.Scalar().SetUint(uint(i + 1))
		msks[i] = poly.Eval(x)
		mpks[i] = curve.Point().ScalarBaseMult(msks[i])
	}

	return &ResultPackage{iid, config, mpk, mpks, msks}, nil
}

func (r *ResultPackage) InstanceID() dkgocrtypes.InstanceID {
	return r.iid
}

func (r *ResultPackage) MasterPublicKey() dkgocrtypes.P256MasterPublicKey {
	return r.mpk.Bytes()
}

func (r *ResultPackage) MasterPublicKeyShares() []dkgocrtypes.P256MasterPublicKeyShare {
	mpks := make([]dkgocrtypes.P256MasterPublicKeyShare, len(r.mpks))
	for i, k := range r.mpks {
		mpks[i] = k.Bytes()
	}
	return mpks
}

func (r *ResultPackage) MasterSecretKeyShare(keyring dkgocrtypes.P256Keyring) (dkgocrtypes.P256MasterSecretKeyShare, error) {
	for i, pk := range r.config.RecipientPublicKeys {
		if bytes.Equal(pk, keyring.PublicKey()) {
			return r.msks[i].Bytes(), nil
		}
	}
	return nil, fmt.Errorf("failed to \"decrypt\" master secret key share using the given keyring")
}

func (r *ResultPackage) ReportingPluginConfig() dkgocrtypes.ReportingPluginConfig {
	return r.config
}

func (r *ResultPackage) MarshalBinary() (data []byte, err error) {
	panic("not implemented")
}

func (r *ResultPackage) UnmarshalBinary(data []byte) error {
	panic("not implemented")
}

// Sets up a deterministic random number generator based on a seed string.
func randFromSeed(seed string) io.Reader {
	sum := sha256.Sum256([]byte(seed))
	seedInt := int64(binary.LittleEndian.Uint64(sum[:8])) // take first 8 bytes
	return unsafeRand.New(unsafeRand.NewSource(seedInt))
}
