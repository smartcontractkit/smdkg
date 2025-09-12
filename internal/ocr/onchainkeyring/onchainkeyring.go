package onchainkeyring

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type OCR3CapabilityCompatibleOnchainKeyring struct {
	OffchainKeyring types.OffchainKeyring
}

var _ ocr3types.OnchainKeyring[struct{}] = (*OCR3CapabilityCompatibleOnchainKeyring)(nil)

// Assigned by https://github.com/smartcontractkit/chainlink/blob/288c2ddde8306d135a824586918762c428b23c79/core/services/keystore/chaintype/chaintype.go#L62
const offchainPublicKeyType byte = 0x8

// We encode the public key following the format used by OCR3Capability configuration contract:
//
// - 1 type byte
// - little-endian uint16 with length
// - the public key itself
//
// source: https://github.com/smartcontractkit/chainlink-evm/blob/075bf754cf7d89edd4ea0041ad101ecf1b6cadda/contracts/src/v0.8/keystone/OCR3Capability.sol#L64-L69
func OCR3CapabilityCompatibleOnchainPublicKey(offchainPublicKey types.OffchainPublicKey) types.OnchainPublicKey {
	result := make([]byte, 0, 1+2+len(offchainPublicKey))
	result = append(result, offchainPublicKeyType)
	result = binary.LittleEndian.AppendUint16(result, uint16(len(offchainPublicKey)))
	result = append(result, offchainPublicKey[:]...)

	return result
}

func (k *OCR3CapabilityCompatibleOnchainKeyring) PublicKey() types.OnchainPublicKey {
	return OCR3CapabilityCompatibleOnchainPublicKey(k.OffchainKeyring.OffchainPublicKey())
}

const domainSeparationTag = "San Marino DKG v1 Report"

// Computed as domainSeparationTag || sha256(configDigest || seqNr || len(reportWithInfo.Report) || reportWithInfo.Report)
// We use the scheme of domainSeparationTag || sha256(...) since that matches what libocr does.
func signatureMessage(configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}]) []byte {
	msg := make([]byte, 0, len(domainSeparationTag)+sha256.Size)
	msg = append(msg, domainSeparationTag...)

	sha := sha256.New()
	sha.Write(configDigest[:])
	_ = binary.Write(sha, binary.BigEndian, seqNr)
	_ = binary.Write(sha, binary.BigEndian, uint64(len(reportWithInfo.Report)))
	_, _ = sha.Write(reportWithInfo.Report)
	msg = sha.Sum(msg)

	return msg
}

func (k *OCR3CapabilityCompatibleOnchainKeyring) Sign(configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}]) (signature []byte, err error) {
	return k.OffchainKeyring.OffchainSign(signatureMessage(configDigest, seqNr, reportWithInfo))
}

func (k *OCR3CapabilityCompatibleOnchainKeyring) Verify(onchainPublicKey types.OnchainPublicKey, configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}], signature []byte) bool {
	if len(onchainPublicKey) != 1+2+ed25519.PublicKeySize {
		// wrong format
		return false
	}

	if !bytes.Equal(onchainPublicKey[:3], []byte{offchainPublicKeyType, 0x20, 0x00}) {
		// wrong format
		return false
	}

	publicKey := ed25519.PublicKey(onchainPublicKey[3:])
	return ed25519.Verify(publicKey, signatureMessage(configDigest, seqNr, reportWithInfo), signature)
}

func (k *OCR3CapabilityCompatibleOnchainKeyring) MaxSignatureLength() int {
	return ed25519.SignatureSize
}
