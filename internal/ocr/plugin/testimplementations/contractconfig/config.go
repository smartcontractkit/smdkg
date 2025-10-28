package contractconfig

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1confighelper"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

var configDigest types.ConfigDigest = types.ConfigDigest{0x13, 0x37}

func pointerToValue[T any](value T) *T {
	return &value
}

func MakeContractConfig(F, N int, reportingPluginConfig []byte) types.ContractConfig {
	signers, transmitters, f, onchainConfig, offchainConfigVersion, offchainConfig, err := ocr3_1confighelper.ContractSetConfigArgsForTests(
		ocr3_1confighelper.CheckPublicConfigLevelDefault,
		OracleIdentities(N),
		F,

		10*time.Second,
		10*time.Millisecond,
		0,
		10,
		time.Second,
		[]int{N},
		reportingPluginConfig,
		nil,
		time.Second,
		10*time.Second,
		10*time.Second,
		10*time.Second,
		10*time.Second,
		10*time.Second,
		10*time.Second,
		time.Second,
		time.Second,
		ocr3_1confighelper.ContractSetConfigArgsOptionalConfig{
			SnapshotInterval: pointerToValue(uint64(100_000)),
		},
	)
	if err != nil {
		panic(err)
	}
	return types.ContractConfig{
		configDigest,
		1,
		signers,
		transmitters,
		f,
		onchainConfig,
		offchainConfigVersion,
		offchainConfig,
	}
}

var _ types.ContractConfigTracker = &FakeContractConfigTracker{}

type FakeContractConfigTracker struct {
	config types.ContractConfig
}

func NewFakeContractConfigTracker(config types.ContractConfig) *FakeContractConfigTracker {
	return &FakeContractConfigTracker{config}
}

func (f *FakeContractConfigTracker) Notify() <-chan struct{} {
	return nil
}

func (f *FakeContractConfigTracker) LatestConfigDetails(ctx context.Context) (uint64, types.ConfigDigest, error) {
	return 0, configDigest, nil
}

func (f *FakeContractConfigTracker) LatestConfig(ctx context.Context, changedInBlock uint64) (types.ContractConfig, error) {
	return f.config, nil
}

func (f *FakeContractConfigTracker) LatestBlockHeight(ctx context.Context) (uint64, error) {
	return 0, nil
}

var _ types.OffchainConfigDigester = &FakeOffchainConfigDigester{}

type FakeOffchainConfigDigester struct{}

func (f *FakeOffchainConfigDigester) ConfigDigest(ctx context.Context, config types.ContractConfig) (types.ConfigDigest, error) {
	return configDigest, nil
}

func (f *FakeOffchainConfigDigester) ConfigDigestPrefix(ctx context.Context) (types.ConfigDigestPrefix, error) {
	return types.ConfigDigestPrefix(binary.BigEndian.Uint16(configDigest[0:2])), nil
}
