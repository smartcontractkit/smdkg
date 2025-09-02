package plugin

import (
	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkg"
)

var _ codec.Codec[*pluginState] = &pluginState{}

func (s *pluginState) MarshalTo(target codec.Target) {
	target.WriteInt(int(s.stateMachineState))
	target.WriteInt(s.countRestart)
}

func (s *pluginState) UnmarshalFrom(source codec.Source) *pluginState {
	s.stateMachineState = stateMachineState(source.ReadInt())
	s.countRestart = source.ReadInt()
	return s
}

func (s *pluginState) IsNil() bool {
	return s == nil
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
		d[i] = codec.ReadOptional(source, dkg.NewVerifiedDecryptionKeySharesForInnerDealing)
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

func (r *ResultPackage) MarshalTo(target codec.Target) {
	r.inner.MarshalTo(target)

	rawConfig, err := r.config.MarshalBinary()
	if err != nil {
		panic("failed to marshal the DKG config: " + err.Error())
	}
	target.WriteLengthPrefixedBytes(rawConfig)
}

func (r *ResultPackage) UnmarshalFrom(source codec.Source) *ResultPackage {
	r.inner = dkg.NewResult()
	r.inner.UnmarshalFrom(source)

	rawConfig := source.ReadLengthPrefixedBytes()
	r.config = &dkgocrtypes.ReportingPluginConfig{}
	err := r.config.UnmarshalBinary(rawConfig)
	if err != nil {
		panic("failed to unmarshal the DKG config: " + err.Error())
	}

	return r
}

func (r *ResultPackage) IsNil() bool {
	return r == nil
}
