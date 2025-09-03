package plugin

import (
	"fmt"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3_1types"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkg"
)

type pluginState struct {
	state   stateMachineState
	attempt int
}

type (
	bannedDealers       []bool                                           // The length of the slice is the number of dealers, true means banned
	initialDealings     []dkg.VerifiedInitialDealing                     // The length of the slice is the number of dealers, nil means no initial dealing from the dealer
	decryptionKeyShares []dkg.VerifiedDecryptionKeySharesForInnerDealing // The length of the slice is the number of dealers, nil means no decryption key shares from the dealer
	innerDealings       []dkg.VerifiedInnerDealing                       // The length of the slice is the number of dealers, nil means no inner dealing from the dealer
)

const (
	pluginStateKey         = "PluginState"
	bannedDealersKey       = "BannedDealers"
	initialDealingsKey     = "InitialDealings"
	decryptionKeySharesKey = "DecryptionKeyShares"
	innerDealingsKey       = "InnerDealings"
)

func (p *DKGPlugin) getPluginStateKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.dkgConfig.instanceID, pluginStateKey))
}

func (p *DKGPlugin) getBannedDealersKey() []byte {
	return []byte(fmt.Sprintf("%s_%s", p.dkgConfig.instanceID, bannedDealersKey))
}

func (p *DKGPlugin) getInitialDealingsKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkgConfig.instanceID, initialDealingsKey, countRestart))
}

func (p *DKGPlugin) getDecryptionKeySharesKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkgConfig.instanceID, decryptionKeySharesKey, countRestart))
}

func (p *DKGPlugin) getInnerDealingsKey(countRestart int) []byte {
	return []byte(fmt.Sprintf("%s_%s_%d", p.dkgConfig.instanceID, innerDealingsKey, countRestart))
}

func (p *DKGPlugin) readPluginState(keyValueReader ocr3_1types.KeyValueReader) (state, error) {
	data, err := keyValueReader.Read(p.getPluginStateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin state from key-value store: %w", err)
	}

	var state *pluginState
	if len(data) > 0 {
		state, err = codec.Unmarshal(data, &pluginState{})
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal plugin state: %w", err)
		}
	} else {
		state = &pluginState{stateDealing, 0}
	}

	switch state.state {
	case stateDealing:
		return &stateMachineDealing{p, state.attempt}, nil
	case stateDecrypting:
		return &stateMachineDecrypting{p, state.attempt}, nil
	case stateFinished:
		return &stateMachineFinished{p, state.attempt}, nil
	default:
		return nil, fmt.Errorf("unknown state machine state: %v", state.state)
	}
}

func (p *DKGPlugin) writePluginState(keyValueReadWriter ocr3_1types.KeyValueReadWriter, state *pluginState) error {
	data, err := codec.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal plugin state: %w", err)
	}

	err = keyValueReadWriter.Write(p.getPluginStateKey(), data)
	if err != nil {
		return fmt.Errorf("failed to write plugin state to key-value store: %w", err)
	}
	return nil
}

func (p *DKGPlugin) readBannedDealers(keyValueReader ocr3_1types.KeyValueReader) (bannedDealers, error) {
	data, err := keyValueReader.Read(p.getBannedDealersKey())
	if err != nil {
		return nil, fmt.Errorf("failed to read banned dealers from key-value store: %w", err)
	}

	bannedDealers := make(bannedDealers, len(p.dkgConfig.dealers))
	for i := range bannedDealers {
		bannedDealers[i] = false
	}

	if len(data) > 0 {
		bannedDealers, err = codec.Unmarshal(data, &bannedDealers)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal banned dealers: %w", err)
		}
	}
	return bannedDealers, nil
}

func (p *DKGPlugin) readInitialDealings(keyValueReader ocr3_1types.KeyValueReader, countRestart int) (initialDealings, error) {
	raw, err := keyValueReader.Read(p.getInitialDealingsKey(countRestart))
	if err != nil {
		return nil, fmt.Errorf("failed to read initial dealings from key-value store: %w", err)
	}

	initialDealings, err := codec.Unmarshal(raw, &initialDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial dealings: %w", err)
	}
	return initialDealings, nil
}

func (p *DKGPlugin) writeInitialDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, countRestart int, dealings initialDealings) error {
	data, err := codec.Marshal(dealings)
	if err != nil {
		return fmt.Errorf("failed to marshal initial dealings: %w", err)
	}

	err = keyValueReadWriter.Write(p.getInitialDealingsKey(countRestart), data)
	if err != nil {
		return fmt.Errorf("failed to write initial dealings to key-value store: %w", err)
	}
	return nil
}

func (p *DKGPlugin) readInnerDealings(keyValueReader ocr3_1types.KeyValueReader, countRestart int) (innerDealings, error) {
	raw, err := keyValueReader.Read(p.getInnerDealingsKey(countRestart))
	if err != nil {
		return nil, fmt.Errorf("failed to read inner dealings from key-value store: %w", err)
	}
	innerDealings, err := codec.Unmarshal(raw, &innerDealings{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner dealings: %w", err)
	}

	return innerDealings, nil
}

func (p *DKGPlugin) writeRecoveredInnerDealings(keyValueReadWriter ocr3_1types.KeyValueReadWriter, countRestart int, decryptionKeyShares decryptionKeyShares, innerDealings innerDealings, bannedDealers bannedDealers) error {
	data, err := codec.Marshal(decryptionKeyShares)
	if err != nil {
		return fmt.Errorf("failed to marshal decryption key shares: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getDecryptionKeySharesKey(countRestart), data); err != nil {
		return fmt.Errorf("failed to write decryption key shares to key-value store: %w", err)
	}

	data, err = codec.Marshal(innerDealings)
	if err != nil {
		return fmt.Errorf("failed to marshal inner dealings: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getInnerDealingsKey(countRestart), data); err != nil {
		return fmt.Errorf("failed to write inner dealings to key-value store: %w", err)
	}

	data, err = codec.Marshal(bannedDealers)
	if err != nil {
		return fmt.Errorf("failed to marshal banned dealers: %w", err)
	}
	if err := keyValueReadWriter.Write(p.getBannedDealersKey(), data); err != nil {
		return fmt.Errorf("failed to write banned dealers to key-value store: %w", err)
	}

	return nil
}
