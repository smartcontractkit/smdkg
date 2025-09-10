package db

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type InMemoryDatabase struct {
	state types.PersistentState
	// ProtocolState is a protocol version-agnostic serialized node state.
	protocolState map[string][]byte
	config        types.ContractConfig
	transmissions map[types.ReportTimestamp]types.PendingTransmission
	mu            sync.Mutex
}

var (
	_ types.Database                  = (*InMemoryDatabase)(nil)
	_ ocr3types.ProtocolStateDatabase = (*InMemoryDatabase)(nil)
)

func (db *InMemoryDatabase) ReadState(_ context.Context, digest types.ConfigDigest) (*types.PersistentState, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return &db.state, nil
}

func (db *InMemoryDatabase) WriteState(_ context.Context, digest types.ConfigDigest, state types.PersistentState) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.state = state
	return nil
}

func (db *InMemoryDatabase) ReadConfig(_ context.Context) (*types.ContractConfig, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return &db.config, nil
}

func (db *InMemoryDatabase) WriteConfig(_ context.Context, config types.ContractConfig) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.config = config
	return nil
}

func (db *InMemoryDatabase) StorePendingTransmission(_ context.Context, ts types.ReportTimestamp, transmission types.PendingTransmission) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.transmissions[ts] = transmission
	return nil
}

func (db *InMemoryDatabase) PendingTransmissionsWithConfigDigest(_ context.Context, digest types.ConfigDigest) (map[types.ReportTimestamp]types.PendingTransmission, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	out := make(map[types.ReportTimestamp]types.PendingTransmission)
	for key, transmission := range db.transmissions {
		if key.ConfigDigest == digest {
			out[key] = transmission
		}
	}
	return out, nil
}

func (db *InMemoryDatabase) DeletePendingTransmission(_ context.Context, ts types.ReportTimestamp) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	delete(db.transmissions, ts)
	return nil
}

func (db *InMemoryDatabase) DeletePendingTransmissionsOlderThan(_ context.Context, cutoff time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	clean := make(map[types.ReportTimestamp]types.PendingTransmission)
	removed := make(map[types.ReportTimestamp]types.PendingTransmission)
	for key, transmission := range db.transmissions {
		if transmission.Time.After(cutoff) {
			clean[key] = transmission
		} else {
			removed[key] = transmission
		}
	}
	db.transmissions = clean
	return nil
}

// In case the key is not found, nil should be returned.
func (db *InMemoryDatabase) ReadProtocolState(ctx context.Context, configDigest types.ConfigDigest, key string) ([]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.protocolState[key], nil
}

// Writing with a nil value is the same as deleting.
func (db *InMemoryDatabase) WriteProtocolState(ctx context.Context, configDigest types.ConfigDigest, key string, value []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if value == nil {
		delete(db.protocolState, key)
	} else {
		db.protocolState[key] = value
	}
	return nil
}

// Factory for in-memory databases

type InMemoryDatabaseFactory struct {
	dbs map[int]*InMemoryDatabase
}

func NewInMemoryDatabaseFactory() *InMemoryDatabaseFactory {
	dbs := make(map[int]*InMemoryDatabase)

	return &InMemoryDatabaseFactory{
		dbs: dbs,
	}
}

func (d *InMemoryDatabaseFactory) GetDatabase(oracleID int) *InMemoryDatabase {
	db := d.dbs[oracleID]
	return db
}

func (d *InMemoryDatabaseFactory) MakeDatabase(oracleID int) *InMemoryDatabase {
	d.dbs[oracleID] = &InMemoryDatabase{
		state:         types.PersistentState{},
		protocolState: make(map[string][]byte),
		config:        types.ContractConfig{},
		transmissions: make(map[types.ReportTimestamp]types.PendingTransmission),
		mu:            sync.Mutex{},
	}
	return d.dbs[oracleID]
}

type OCR3_1InMemoryDatabase struct {
	*InMemoryDatabase
}

var (
	_ ocr3types.ProtocolStateDatabase = (*OCR3_1InMemoryDatabase)(nil)
	_ ocr3_1types.BlockDatabase       = (*OCR3_1InMemoryDatabase)(nil)
)

func NewOCR3_1InMemoryDatabase(config types.ContractConfig) *OCR3_1InMemoryDatabase {
	return &OCR3_1InMemoryDatabase{
		&InMemoryDatabase{
			types.PersistentState{},
			make(map[string][]byte),
			config,
			make(map[types.ReportTimestamp]types.PendingTransmission),
			sync.Mutex{},
		},
	}
}

func (db *OCR3_1InMemoryDatabase) ReadBlock(ctx context.Context, configDigest types.ConfigDigest, seqNr uint64) ([]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.protocolState[strconv.FormatUint(seqNr, 10)]; !ok {
		return nil, nil
	}
	return db.protocolState[strconv.FormatUint(seqNr, 10)], nil
}

func (db *OCR3_1InMemoryDatabase) WriteBlock(ctx context.Context, configDigest types.ConfigDigest, seqNr uint64, block []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if block == nil {
		delete(db.protocolState, strconv.FormatUint(seqNr, 10))
	} else {
		db.protocolState[strconv.FormatUint(seqNr, 10)] = block
	}

	return nil
}
