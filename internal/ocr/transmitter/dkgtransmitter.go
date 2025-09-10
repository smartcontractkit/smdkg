package transmitter

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin"
)

var _ ocr3types.ContractTransmitter[struct{}] = &Transmitter{}

type Transmitter struct {
	DealingPackageDatabase dkgocrtypes.ResultPackageDatabase
	OffchainKeyring        types.OffchainKeyring
}

// Transmit sends the report to the on-chain smart contract's Transmit method.
func (t *Transmitter) Transmit(
	ctx context.Context,
	configDigest types.ConfigDigest,
	seqNr uint64,
	report ocr3types.ReportWithInfo[struct{}],
	signatures []types.AttributedOnchainSignature,
) error {
	// no need to check signatures since libocr already handled that for us

	// unmarshal report into dealingPackage
	dealingPackage := &plugin.ResultPackage{}
	err := dealingPackage.UnmarshalBinary(report.Report)
	if err != nil {
		return fmt.Errorf("unmarshal dealing package: %w", err)
	}

	// prepare database value
	value := dkgocrtypes.ResultPackageDatabaseValue{configDigest, seqNr, report.Report, signatures}

	// write to entry to t.DealingPackageDatabase
	return t.DealingPackageDatabase.WriteResultPackage(ctx, dealingPackage.InstanceID(), value)
}

// We use the offchain public key as the "transmitter" account, formatted as an Ethereum address for compatibility the
// EVM contract used for configuration dissemination.
// Example: If the offchain public key is aef16539e9c968943157f665da069451a20225b9875049897c14ec74db36228f
// the returned Account is 0xc1c1c1c1aef16539e9c968943157F665da069451. (Following EIP-55.)
func (t *Transmitter) FromAccount(ctx context.Context) (types.Account, error) {
	pubKey := t.OffchainKeyring.OffchainPublicKey()
	// return types.Account(fmt.Sprintf("0xc1c1c1c1%x", pubKey[:16])), nil
	address := common.HexToAddress(fmt.Sprintf("0xc1c1c1c1%x", pubKey[:16]))
	return types.Account(address.Hex()), nil
}
