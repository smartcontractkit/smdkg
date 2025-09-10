package contractconfig

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/confighelper"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	ragetypes "github.com/smartcontractkit/libocr/ragep2p/types"
	"github.com/smartcontractkit/smdkg/internal/ocr/onchainkeyring"
	"golang.org/x/crypto/curve25519"
)

func OffchainPrivateKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(fmt.Sprintf("CanadaCanadaCanadaCanada%8d", i)))
}

func ConfigEncryptionPrivateKey(i int) [curve25519.ScalarSize]byte {
	var priv [curve25519.ScalarSize]byte
	copy(priv[:], []byte(fmt.Sprintf("Bonjour!Bonjour!Bonjour!%8d", i)))
	return priv
}

func P2pPrivateKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(fmt.Sprintf("MontrealMontrealMontreal%8d", i)))
}

func offchainPublicKeyKeyFromPrivateKey(priv ed25519.PrivateKey) types.OffchainPublicKey {
	var result types.OffchainPublicKey
	copy(result[:], priv.Public().(ed25519.PublicKey))
	return result
}

func peerIDFromPrivateKey(priv ed25519.PrivateKey) string {
	peerID, err := ragetypes.PeerIDFromPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return peerID.String()
}

func OracleIdentity(i int) confighelper.OracleIdentityExtra {
	var configEncryptionPublicKey types.ConfigEncryptionPublicKey
	{
		scalar := ConfigEncryptionPrivateKey(i)
		curve25519.ScalarBaseMult((*[32]byte)(&configEncryptionPublicKey), &scalar)
	}

	pubKey := offchainPublicKeyKeyFromPrivateKey(OffchainPrivateKey(i))

	return confighelper.OracleIdentityExtra{
		confighelper.OracleIdentity{
			pubKey,
			onchainkeyring.OCR3CapabilityCompatibleOnchainPublicKey(pubKey),
			peerIDFromPrivateKey(P2pPrivateKey(i)),
			types.Account(common.HexToAddress(fmt.Sprintf("0xc1c1c1c1%x", pubKey[:16])).String()),
		},
		configEncryptionPublicKey,
	}
}

func OracleIdentities(n int) []confighelper.OracleIdentityExtra {
	var result []confighelper.OracleIdentityExtra
	for i := 0; i < n; i++ {
		result = append(result, OracleIdentity(i))
	}
	return result
}
