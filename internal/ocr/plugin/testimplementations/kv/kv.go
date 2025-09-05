package kv

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type InMemoryKeyValueDatabaseFactory struct{}

var _ ocr3_1types.KeyValueDatabaseFactory = &InMemoryKeyValueDatabaseFactory{}

func (d *InMemoryKeyValueDatabaseFactory) NewKeyValueDatabase(configDigest types.ConfigDigest) (ocr3_1types.KeyValueDatabase, error) {
	return NewInMemoryKeyValueDatabase(), nil
}

var errKeyValueDatabaseClosed = fmt.Errorf("key value database closed")

type InMemoryKeyValueDatabase struct {
	mu      sync.Mutex
	version uint64
	store   map[string][]byte // key -> value
	closed  bool
}

var _ ocr3_1types.KeyValueDatabase = &InMemoryKeyValueDatabase{}

func NewInMemoryKeyValueDatabase() *InMemoryKeyValueDatabase {
	return &InMemoryKeyValueDatabase{
		sync.Mutex{},
		0,
		make(map[string][]byte),
		false,
	}
}

func (d *InMemoryKeyValueDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.store)
	d.closed = true
	return nil
}

func (d *InMemoryKeyValueDatabase) NewReadTransaction() (ocr3_1types.KeyValueReadTransaction, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errKeyValueDatabaseClosed
	}

	return &inMemoryReadWriteTransaction{
		d,
		d.version,
		sync.Mutex{},
		maps.Clone(d.store),
	}, nil
}

func (d *InMemoryKeyValueDatabase) NewReadWriteTransaction() (ocr3_1types.KeyValueReadWriteTransaction, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errKeyValueDatabaseClosed
	}

	return &inMemoryReadWriteTransaction{
		d,
		d.version,
		sync.Mutex{},
		maps.Clone(d.store),
	}, nil
}

func (d *InMemoryKeyValueDatabase) commit(versionAtCreation uint64, txStore map[string][]byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errKeyValueDatabaseClosed
	}
	if d.version != versionAtCreation {

		return fmt.Errorf("can't commit: have version %d but tx is for version %d", d.version, versionAtCreation)
	}
	d.store = txStore // move
	d.version++
	return nil
}

type inMemoryReadWriteTransaction struct {
	parent                  *InMemoryKeyValueDatabase
	parentVersionAtCreation uint64

	mu      sync.Mutex
	txStore map[string][]byte
}

func (d *inMemoryReadWriteTransaction) Range(loKey []byte, hiKeyExcl []byte) ocr3_1types.KeyValueIterator {
	loKey = bytes.Clone(loKey)
	hiKeyExcl = bytes.Clone(hiKeyExcl)

	d.mu.Lock()
	defer d.mu.Unlock()
	var err error
	if d.txStore == nil {
		err = errDiscarded
	}

	var keys []string
	for k := range d.txStore {
		if bytes.Compare([]byte(k), loKey) >= 0 && (len(hiKeyExcl) == 0 || bytes.Compare([]byte(k), hiKeyExcl) < 0) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	idx, _ := slices.BinarySearch(keys, string(loKey))

	return &inMemoryRangeIterator{
		err,
		idx,
		false,
		keys,
		d,
		nil,
	}
}

type inMemoryRangeIterator struct {
	err    error
	idx    int
	closed bool

	sortedKeys []string
	d          *inMemoryReadWriteTransaction

	currentKey []byte
}

var _ ocr3_1types.KeyValueIterator = &inMemoryRangeIterator{}

func (i *inMemoryRangeIterator) Close() error {
	i.closed = true
	return nil
}

func (i *inMemoryRangeIterator) Next() bool {
	if i.closed {
		return false
	}

	if i.err != nil {
		return false
	}

	if i.idx >= len(i.sortedKeys) {
		return false
	}

	i.currentKey = []byte(i.sortedKeys[i.idx])
	i.idx++
	return true
}

func (i *inMemoryRangeIterator) Key() []byte {
	return bytes.Clone(i.currentKey)
}

func (i *inMemoryRangeIterator) Value() ([]byte, error) {
	return i.d.Read(i.currentKey)
}

func (i *inMemoryRangeIterator) Err() error {
	return i.err
}

var _ ocr3_1types.KeyValueReadWriteTransaction = &inMemoryReadWriteTransaction{}
var _ ocr3_1types.KeyValueReadTransaction = &inMemoryReadWriteTransaction{}

var errDiscarded = fmt.Errorf("transaction discarded")

func (d *inMemoryReadWriteTransaction) Commit() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.txStore == nil {
		return errDiscarded
	}

	txStore := d.txStore
	d.txStore = nil // move to parent below
	err := d.parent.commit(d.parentVersionAtCreation, txStore)
	return err
}

func (d *inMemoryReadWriteTransaction) Delete(key []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.txStore == nil {
		return errDiscarded
	}

	delete(d.txStore, string(key))
	return nil
}

func (d *inMemoryReadWriteTransaction) Write(key []byte, value []byte) error {
	value = bytes.Clone(value) // protect txStore against later modification
	value = NilCoalesceSlice(value)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.txStore == nil {
		return errDiscarded
	}

	d.txStore[string(key)] = value
	return nil
}

func (d *inMemoryReadWriteTransaction) Discard() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.txStore = nil
}

func (d *inMemoryReadWriteTransaction) Read(key []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.txStore == nil {
		return nil, errDiscarded
	}

	if v, ok := d.txStore[string(key)]; ok {
		return bytes.Clone(v), nil // protect txStore against later modification
	}
	return nil, nil
}

func NilCoalesceSlice[T any](maybe []T) []T {
	if maybe != nil {
		return maybe
	} else {
		return []T{}
	}
}
