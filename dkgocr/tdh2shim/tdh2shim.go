package tdh2shim

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/crs"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/tdh2/go/tdh2/tdh2"
)

// Shim for extracting the public TDH2 public key from a DKG result.
// Currently, this shim only supports the P256 curve, as it is the only one used by TDH2.

// Copied from tdh2.go, as those types are not exported.
type publicKeyRaw struct {
	Group  string   // curve name
	G_bar  []byte   // randomly (but deterministically) generated point
	H      []byte   // master public key (included the master public key shares)
	HArray [][]byte // master secret key shares
}

// Copied from tdh2.go, as those types are not exported.
type privateShareRaw struct {
	Group string // curve name
	Index int    // zero-based index !!!
	V     []byte // scalar value
}

// Note: in this demo code, a direct Unmarshal of the value returned by result.MasterPublicKey() is sufficient,
// but the consumer of this code must not rely on this behavior, and instead use the provided shim.
func TDH2PublicKeyFromDKGResult(result dkgocrtypes.ResultPackage) (*tdh2.PublicKey, error) {
	curve := math.P256
	iid := dkgtypes.InstanceID(result.InstanceID())

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

	crs, err := crs.NewP256CRS(iid, "tdh2shim")
	if err != nil {
		return nil, fmt.Errorf("failed to create CRS: %w", err)
	}
	crsPoint, err := curve.Point().SetBytes(crs.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert CRS to P256 point: %w", err)
	}
	crsBytes, err := convertToUncompressedPoint(crsPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CRS to uncompressed format: %w", err)
	}

	mpkJson, err := json.Marshal(&publicKeyRaw{
		curve.Name(),   // curve name
		crsBytes,       // G_bar
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
func TDH2PrivateShareFromDKGResult(result dkgocrtypes.ResultPackage, keyring dkgocrtypes.P256Keyring) (*tdh2.PrivateShare, error) {
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
		return nil, fmt.Errorf("failed to convert point into uncompressed format, unsupport point type")
	}
}
