package plugin

import (
	"encoding"
	"fmt"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
)

func (p *pluginStateDealing) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginStateTypeDealing))
	target.WriteInt(p.attempt)
}

func (p *pluginStateDecrypting) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginStateTypeDecrypting))
	target.WriteInt(p.attempt)
}

func (s *pluginStateFinished) MarshalTo(target codec.Target) {
	target.WriteInt(int(pluginStateTypeFinished))
	target.WriteInt(s.attempt)
}

// Implements unmarshaling for a pluginState.
// If provided, the plugin field of the unmarshaled state to the given value from the unmarshaler.
type pluginStateUnmarshaler struct {
	plugin *DKGPlugin
}

func (u pluginStateUnmarshaler) UnmarshalFrom(source codec.Source) pluginState {
	pluginStateType := pluginStateType(source.ReadInt())
	attempt := source.ReadInt()

	switch pluginStateType {
	case pluginStateTypeDealing:
		return &pluginStateDealing{u.plugin, attempt}
	case pluginStateTypeDecrypting:
		return &pluginStateDecrypting{u.plugin, attempt}
	case pluginStateTypeFinished:
		return &pluginStateFinished{u.plugin, attempt}
	default:
		panic(fmt.Sprintf("unknown pluginStateType: %v", pluginStateType))
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[bannedDealers] = &bannedDealers{}

func (b bannedDealers) MarshalTo(target codec.Target) {
	target.WriteInt(len(b))
	for i := range b {
		target.WriteBool(b[i])
	}
}

func (b bannedDealers) UnmarshalFrom(source codec.Source) bannedDealers {
	n := source.ReadInt()
	b = make(bannedDealers, n)
	for i := range b {
		b[i] = source.ReadBool()
	}
	return b
}

func (b bannedDealers) IsNil() bool {
	return b == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[initialDealings] = &initialDealings{}

func (d initialDealings) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d initialDealings) UnmarshalFrom(source codec.Source) initialDealings {
	n := source.ReadInt()
	d = make(initialDealings, n)
	for i := range d {
		d[i] = codec.ReadOptional(source, dkg.NewVerifiedInitialDealing)
	}
	return d
}

func (d initialDealings) IsNil() bool {
	return d == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[decryptionKeyShares] = &decryptionKeyShares{}

func (d decryptionKeyShares) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d decryptionKeyShares) UnmarshalFrom(source codec.Source) decryptionKeyShares {
	n := source.ReadInt()
	d = make(decryptionKeyShares, n)
	for i := range d {
		d[i] = codec.ReadOptional(source, dkg.NewVerifiedDecryptionKeySharesForInnerDealings)
	}
	return d
}

func (d decryptionKeyShares) IsNil() bool {
	return d == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[innerDealings] = &innerDealings{}

func (d innerDealings) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d innerDealings) UnmarshalFrom(source codec.Source) innerDealings {
	n := source.ReadInt()
	d = make(innerDealings, n)
	for i := range d {
		d[i] = codec.ReadOptional(source, dkg.NewVerifiedInnerDealing)
	}
	return d
}

func (d innerDealings) IsNil() bool {
	return d == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[*ResultPackage] = &ResultPackage{}
var _ encoding.BinaryMarshaler = &ResultPackage{}
var _ encoding.BinaryUnmarshaler = &ResultPackage{}

func (r *ResultPackage) MarshalBinary() ([]byte, error) {
	return codec.Marshal(r)
}

func (r *ResultPackage) UnmarshalBinary(data []byte) error {
	_, err := codec.Unmarshal(data, r)
	return err
}

func (r *ResultPackage) MarshalTo(target codec.Target) {
	r.Inner.MarshalTo(target)

	rawConfig, err := r.Config.MarshalBinary()
	if err != nil {
		panic("failed to marshal the DKG config: " + err.Error())
	}
	target.WriteLengthPrefixedBytes(rawConfig)
}

func (r *ResultPackage) UnmarshalFrom(source codec.Source) *ResultPackage {
	r.Inner = dkg.NewResult()
	r.Inner.UnmarshalFrom(source)

	rawConfig := source.ReadLengthPrefixedBytes()
	r.Config = &dkgocrtypes.ReportingPluginConfig{}

	err := r.Config.UnmarshalBinary(rawConfig)
	if err != nil {
		panic("failed to unmarshal the DKG config: " + err.Error())
	}

	return r
}

func (r *ResultPackage) IsNil() bool {
	return r == nil
}
