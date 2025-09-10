package oracleargs

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/ocr/onchainkeyring"
	"github.com/smartcontractkit/smdkg/internal/ocr/plugin"
	"github.com/smartcontractkit/smdkg/internal/ocr/transmitter"
)

func OCR3_1OracleArgsForSanMarinoDKG(
	// regular OCR injected dependencies
	binaryNetworkEndpointFactory types.BinaryNetworkEndpoint2Factory,
	v2Bootstrappers []commontypes.BootstrapperLocator,
	contractConfigTracker types.ContractConfigTracker,
	database ocr3_1types.Database,
	keyValueDatabaseFactory ocr3_1types.KeyValueDatabaseFactory,
	localConfig types.LocalConfig,
	logger commontypes.Logger,
	metricsRegisterer prometheus.Registerer,
	monitoringEndpoint commontypes.MonitoringEndpoint,
	offchainConfigDigester types.OffchainConfigDigester,
	offchainKeyring types.OffchainKeyring,
	// special for DKG
	dkgP256Keyring dkgocrtypes.P256Keyring,
	dealingResultPackageDatabase dkgocrtypes.ResultPackageDatabase,
	configContractAddress common.Address,
) offchainreporting2plus.OCR3_1OracleArgs[struct{}] {
	return offchainreporting2plus.OCR3_1OracleArgs[struct{}]{
		binaryNetworkEndpointFactory,
		v2Bootstrappers,
		contractConfigTracker,
		&transmitter.Transmitter{dealingResultPackageDatabase, offchainKeyring},
		database,
		keyValueDatabaseFactory,
		localConfig,
		logger,
		metricsRegisterer,
		monitoringEndpoint,
		offchainConfigDigester,
		offchainKeyring,
		&onchainkeyring.OCR3CapabilityCompatibleOnchainKeyring{OffchainKeyring: offchainKeyring},
		plugin.NewDKGPluginFactory(logger, dkgP256Keyring, dealingResultPackageDatabase, configContractAddress),
	}
}
