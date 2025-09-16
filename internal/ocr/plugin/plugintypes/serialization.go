package plugintypes

import (
	"encoding"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
)

var _ codec.Codec[BannedDealers] = &BannedDealers{}

func (b BannedDealers) MarshalTo(target codec.Target) {
	target.WriteInt(len(b))
	for i := range b {
		target.WriteBool(b[i])
	}
}

func (b BannedDealers) UnmarshalFrom(source codec.Source) BannedDealers {
	n := source.ReadInt()
	b = make(BannedDealers, 0)
	for i := 0; i < n; i++ {
		b = append(b, source.ReadBool())
	}
	return b
}

func (b BannedDealers) IsNil() bool {
	return b == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[InitialDealings] = &InitialDealings{}

func (d InitialDealings) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d InitialDealings) UnmarshalFrom(source codec.Source) InitialDealings {
	n := source.ReadInt()
	d = make(InitialDealings, 0)
	for i := 0; i < n; i++ {
		d = append(d, codec.ReadOptional(source, dkg.NewVerifiedInitialDealing))
	}
	return d
}

func (d InitialDealings) IsNil() bool {
	return d == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[DecryptionKeyShares] = &DecryptionKeyShares{}

func (d DecryptionKeyShares) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d DecryptionKeyShares) UnmarshalFrom(source codec.Source) DecryptionKeyShares {
	n := source.ReadInt()
	d = make(DecryptionKeyShares, 0)
	for i := 0; i < n; i++ {
		d = append(d, codec.ReadOptional(source, dkg.NewVerifiedDecryptionKeySharesForInnerDealings))
	}
	return d
}

func (d DecryptionKeyShares) IsNil() bool {
	return d == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ codec.Codec[InnerDealings] = &InnerDealings{}

func (d InnerDealings) MarshalTo(target codec.Target) {
	target.WriteInt(len(d))
	for i := range d {
		target.WriteOptional(d[i])
	}
}

func (d InnerDealings) UnmarshalFrom(source codec.Source) InnerDealings {
	n := source.ReadInt()
	d = make(InnerDealings, 0)
	for i := 0; i < n; i++ {
		d = append(d, codec.ReadOptional(source, dkg.NewVerifiedInnerDealing))
	}
	return d
}

func (d InnerDealings) IsNil() bool {
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
