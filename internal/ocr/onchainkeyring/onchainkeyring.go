package onchainkeyring

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type OnchainKeyring struct {
	OffchainKeyring types.OffchainKeyring
}

var _ ocr3types.OnchainKeyring[struct{}] = (*OnchainKeyring)(nil)

func (k *OnchainKeyring) PublicKey() types.OnchainPublicKey {
	offchainPublicKey := k.OffchainKeyring.OffchainPublicKey()
	return types.OnchainPublicKey(offchainPublicKey[:])
}

const domainSeparationTag = "San Marino DKG Report"

func signatureMessage(configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}]) []byte {
	msg := make([]byte, 0, len(domainSeparationTag)+len(configDigest)+8+len(reportWithInfo.Report))
	msg = append(msg, domainSeparationTag...)
	msg = append(msg, configDigest[:]...)
	msg = binary.BigEndian.AppendUint64(msg, seqNr)
	msg = binary.BigEndian.AppendUint64(msg, uint64(len(reportWithInfo.Report)))
	msg = append(msg, reportWithInfo.Report...)
	return msg
}

func (k *OnchainKeyring) Sign(configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}]) (signature []byte, err error) {
	return k.OffchainKeyring.OffchainSign(signatureMessage(configDigest, seqNr, reportWithInfo))
}

func (k *OnchainKeyring) Verify(onchainPublicKey types.OnchainPublicKey, configDigest types.ConfigDigest, seqNr uint64, reportWithInfo ocr3types.ReportWithInfo[struct{}], signature []byte) bool {
	// Defensive: check public key length for ed25519
	if len(onchainPublicKey) != ed25519.PublicKeySize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(onchainPublicKey), signatureMessage(configDigest, seqNr, reportWithInfo), signature)
}

func (k *OnchainKeyring) MaxSignatureLength() int {
	return ed25519.SignatureSize
}
