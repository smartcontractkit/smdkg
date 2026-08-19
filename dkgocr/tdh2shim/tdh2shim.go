package tdh2shim

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/crs"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2"
)

// Shim for extracting the TDH2 public key from a DKG result.
// Currently, this shim only supports the P256 curve, as it is the only one used by TDH2.

// Copied from tdh2.go, as those types are not exported.
type publicKeyRaw struct {
	Group  string   // curve name
	G_bar  []byte   // randomly (but deterministically) generated point, must remain stable across resharings
	H      []byte   // master public key (included the master public key shares)
	HArray [][]byte // master secret key shares
}

// Copied from tdh2.go, as those types are not exported.
type privateShareRaw struct {
	Group string // curve name
	Index int    // zero-based index !!!
	V     []byte // scalar value
}

// The point G_bar of a TDH2 public key must remain stable across resharings of the underlying master secret key,
// so that ciphertexts created before a resharing remain valid afterwards. G_bar is therefore derived from the
// (compressed) master public key itself, which - in contrast to the DKG instance ID - does not change when the
// key is reshared.
const gBarFromMasterPublicKeyTag = "tdh2shim/g_bar-from-mpk/v1"

// Before the derivation rule above was introduced, G_bar was derived from the DKG instance ID with this tag,
// which changes when a key is reshared. This legacy derivation method remains in use for the keys pinned in
// legacyGBarInstanceIDs.
const gBarFromInstanceIDTag = "tdh2shim"

// legacyGBarInstanceIDs maps the hex-encoded compressed master public key of each key generated under the legacy
// derivation rule to the instance ID of the key's initial DKG run. For these keys, G_bar continues to be derived
// from the pinned initial instance ID, for backwards compatibility with the G_bar values already in use.
var legacyGBarInstanceIDs = map[string]dkgtypes.InstanceID{
	// production

	"03776c6fe4f3c6eba75e883603e9532c1c85294108436c6c1cdd76aa6a7840e3c5": "sanmarinodkg/v1/0x7BCcaFBD064cB3658476066Cc33ceE3F3414c04c/000e104dc5c3ee7263501c1da5ec491ba3a7212193b627ed07a7dce368403564",

	// enterprise

	"02e037b0361cb09e3dfceaf34553b9485b8bb9118cff479de2452b338d280e037a": "sanmarinodkg/v1/0x9757490F67f5C6914eA5bb463b239F0fBF738Aa9/000e8c875b197aee61b1253584fe465d15319a191331b31c1dea2ca6916a8c89",

	// reliability

	"023d4454adfd9e90d30e349ae92197afe5e36a897b1469d7e040aa5e6547aaae8c": "sanmarinodkg/v1/0xB3Dd5D1459596e71190EC70C78e0B1358e44B9a0/000e9b11c4a836ce3e6816035f9f18e249d6260a6ec814598de48510694ab827",

	// staging

	"027b30ab68a6ed53fcfa83fa5714d784418f304cd4cabf9168802b121a321eda48": "sanmarinodkg/v1/0x011F13729274975BF95adC20EFf0a73C44f668aB/000ef0a76054709acbc690f782dcbbfd398d828e43575913ba25c85071fc30dd",

	// test/v1-fresh-sharing

	"035ac58792e4f221ddb163e420ea3c2f3c3e1205f9f38a5781ce7dd694b1ee5713": "test-dkg-fresh-dealing",
}

// Derives the TDH2 parameter G_bar for the given master public key (see the comments on the constants above).
func deriveGBar(masterPublicKey dkgocrtypes.P256MasterPublicKey) (dkgtypes.P256PublicKey, error) {
	// The master public key must be given in its canonical (compressed) encoding. This ensures that the lookup
	// of the legacy keys below cannot be bypassed - and the derived G_bar value cannot be changed - by encoding
	// the same point differently (e.g., in uncompressed form). Note that this strict check cannot reject any
	// existing key: the pre-fix shim only ever accepted the compressed encoding as well (math.P256Point.SetBytes
	// has rejected longer encodings since its first version), so no key exists in any other encoding.
	if len(masterPublicKey) != dkgocrtypes.P256MasterPublicKeyLength {
		return dkgtypes.P256PublicKey{}, fmt.Errorf(
			"master public key must be %d bytes (compressed encoding), got %d bytes",
			dkgocrtypes.P256MasterPublicKeyLength, len(masterPublicKey),
		)
	}
	if iid, ok := legacyGBarInstanceIDs[hex.EncodeToString(masterPublicKey)]; ok {
		return crs.NewP256CRS(iid, gBarFromInstanceIDTag)
	}
	return crs.NewP256CRSFromBytes(masterPublicKey, gBarFromMasterPublicKeyTag)
}

// Consumers must obtain the TDH2 public key exclusively through this shim. The value returned by
// result.MasterPublicKey() is an opaque byte string (currently the compressed P-256 encoding of the master
// public key H), not a marshaled TDH2 public key, and its encoding may change. In particular, the TDH2
// parameter G_bar is not part of the result package at all: it is derived by this shim (see deriveGBar,
// including the pinning of legacy keys via legacyGBarInstanceIDs), so constructing a TDH2 public key by hand
// yields a wrong G_bar for pinned keys - invalidating all of the key's existing ciphertexts.
func TDH2PublicKeyFromDKGResult(result dkgocrtypes.ResultPackage) (*tdh2.PublicKey, error) {
	curve := math.P256

	mpk, err := curve.Point().SetBytes(result.MasterPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to convert master public key to P256 point: %w", err)
	}
	mpkBytes, err := convertToUncompressedPoint(mpk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert master public key to uncompressed format: %w", err)
	}

	mpkSharesBytes := make([][]byte, 0)
	for _, share := range result.MasterPublicKeyShares() {
		p, err := curve.Point().SetBytes(share)
		if err != nil {
			return nil, fmt.Errorf("failed to convert master public key share to P256 point: %w", err)
		}

		pBytes, err := convertToUncompressedPoint(p)
		if err != nil {
			return nil, fmt.Errorf("failed to convert master public key share to uncompressed format: %w", err)
		}
		mpkSharesBytes = append(mpkSharesBytes, pBytes)
	}

	gBar, err := deriveGBar(result.MasterPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to derive G_bar: %w", err)
	}
	gBarPoint, err := curve.Point().SetBytes(gBar.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert G_bar to P256 point: %w", err)
	}
	gBarBytes, err := convertToUncompressedPoint(gBarPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to convert G_bar to uncompressed format: %w", err)
	}

	mpkJson, err := json.Marshal(&publicKeyRaw{
		curve.Name(),   // curve name
		gBarBytes,      // G_bar
		mpkBytes,       // H
		mpkSharesBytes, // HArray
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal master public key: %w", err)
	}

	pk := new(tdh2.PublicKey)
	if err := pk.Unmarshal(mpkJson); err != nil {
		return nil, fmt.Errorf("failed to unmarshal master public key: %w", err)
	}
	return pk, nil
}

// Shim for extracting the private TDH2 share from a DKG result. Requires a participants keyring for decryption.
func TDH2PrivateShareFromDKGResult(
	result dkgocrtypes.ResultPackage,
	keyring dkgocrtypes.P256Keyring,
) (*tdh2.PrivateShare, error) {
	index := -1
	for i, pk := range result.ReportingPluginConfig().RecipientPublicKeys {
		if bytes.Equal(pk, keyring.PublicKey()) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("keyring public key not found in the recipient public keys from the configuration")
	}

	mskShare, err := result.MasterSecretKeyShare(keyring)
	if err != nil {
		return nil, err
	}

	mskShareJson, err := json.Marshal(&privateShareRaw{
		"P256",   // curve name
		index,    // zero-based index !!!
		mskShare, // scalar value
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal master secret key share: %w", err)
	}

	ps := new(tdh2.PrivateShare)
	if err := ps.Unmarshal(mskShareJson); err != nil {
		return nil, fmt.Errorf("failed to unmarshal master secret key share: %w", err)
	}
	return ps, nil
}

func convertToUncompressedPoint(point math.Point) ([]byte, error) {
	switch p := point.(type) {
	case *math.P224Point:
		return p.BytesUncompressed(), nil
	case *math.P256Point:
		return p.BytesUncompressed(), nil
	case *math.P384Point:
		return p.BytesUncompressed(), nil
	case *math.P521Point:
		return p.BytesUncompressed(), nil
	default:
		return nil, fmt.Errorf("failed to convert point into uncompressed format, unsupported point type")
	}
}
