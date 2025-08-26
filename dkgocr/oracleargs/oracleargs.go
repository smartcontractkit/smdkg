package oracleargs

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	ocr2ptypes "github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/dkgocr/internal/onchainkeyring"
	"github.com/smartcontractkit/smdkg/dkgocr/internal/plugin"
	"github.com/smartcontractkit/smdkg/dkgocr/internal/transmitter"
)

func OCR3_1OracleArgsForSanMarinoDKG(
	// regular OCR injected dependencies
	binaryNetworkEndpointFactory ocr2ptypes.BinaryNetworkEndpoint2Factory,
	v2Bootstrappers []commontypes.BootstrapperLocator,
	contractConfigTracker ocr2ptypes.ContractConfigTracker,
	database ocr3_1types.Database,
	keyValueDatabaseFactory ocr3_1types.KeyValueDatabaseFactory,
	localConfig ocr2ptypes.LocalConfig,
	logger commontypes.Logger,
	metricsRegisterer prometheus.Registerer,
	monitoringEndpoint commontypes.MonitoringEndpoint,
	offchainConfigDigester ocr2ptypes.OffchainConfigDigester,
	offchainKeyring ocr2ptypes.OffchainKeyring,
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
		&onchainkeyring.OnchainKeyring{OffchainKeyring: offchainKeyring},
		plugin.NewDKGPluginFactory(logger, dkgP256Keyring, dealingResultPackageDatabase, configContractAddress),
	}
}
