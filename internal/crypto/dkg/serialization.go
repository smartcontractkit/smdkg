package dkg

import (
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
	"github.com/smartcontractkit/smdkg/internal/crypto/vess"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewResult() Result {
	return &result{}
}

func (r *result) IsNil() bool {
	return r == nil
}

func (r *result) MarshalTo(target codec.Target) {
	t_R := r.t_R
	n_R := len(r.y_R)

	target.WriteString(string(r.iid))
	r.curve.MarshalTo(target)
	target.WriteInt(t_R)
	target.WriteInt(n_R)

	n_D := len(r.Lꞌ)
	target.WriteInt(n_D)

	for _, ID := range r.Lꞌ {
		target.WriteOptional(ID)
	}

	r.y.MarshalTo(target)

	for _, y_Rᵢ := range r.y_R {
		y_Rᵢ.MarshalTo(target)
	}

	target.WriteBool(r.wasReshared)
	target.WriteInt(r.attempt)
}

func (r *result) UnmarshalFrom(source codec.Source) Result {
	r.iid = dkgtypes.InstanceID(source.ReadString())
	r.curve = math.UnmarshalCurve(source)
	t_R := source.ReadNonNegativeInt()
	n_R := source.ReadNonNegativeInt()
	n_D := source.ReadNonNegativeInt()

	if t_R < 1 || n_R < t_R {
		panic(fmt.Sprintf("result.UnmarshalFrom: invalid parameters (n=%d, t=%d)", n_R, t_R))
	}

	r.t_R = t_R
	r.Lꞌ = make([]VerifiedInnerDealing, 0)
	for i := 0; i < n_D; i++ {
		r.Lꞌ = append(r.Lꞌ, codec.ReadOptional(source, NewVerifiedInnerDealing))
	}

	r.y = r.curve.Point()
	r.y.UnmarshalFrom(source)

	r.y_R = make([]math.Point, 0)
	for i := 0; i < n_R; i++ {
		r.y_R = append(r.y_R, r.curve.Point().UnmarshalFrom(source))
	}

	r.wasReshared = source.ReadBool()
	r.attempt = source.ReadInt()
	return r
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewUnverifiedInitialDealing() UnverifiedInitialDealing {
	return &unverifiedInitialDealing{}
}

func (d *unverifiedInitialDealing) IsNil() bool {
	return d == nil
}

func (d *unverifiedInitialDealing) MarshalTo(target codec.Target) {
	d.OD.MarshalTo(target)
	target.WriteLengthPrefixedBytes(d.EID)
}

func (d *unverifiedInitialDealing) UnmarshalFrom(source codec.Source) UnverifiedInitialDealing {
	d.OD = codec.ReadObject(source, &vess.UnverifiedDealing{})
	d.EID = source.ReadLengthPrefixedBytes()
	return d
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewVerifiedInitialDealing() VerifiedInitialDealing {
	return &verifiedInitialDealing{}
}

func (d *verifiedInitialDealing) IsNil() bool {
	return d == nil
}

func (d *verifiedInitialDealing) MarshalTo(target codec.Target) {
	d.OD.MarshalTo(target)
	target.WriteLengthPrefixedBytes(d.EID)
}

func (d *verifiedInitialDealing) UnmarshalFrom(source codec.Source) VerifiedInitialDealing {
	d.OD = codec.ReadObject(source, &vess.VerifiedDealing{})
	d.EID = source.ReadLengthPrefixedBytes()
	return d
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewVerifiedDecryptionKeySharesForInnerDealings() VerifiedDecryptionKeySharesForInnerDealings {
	return &verifiedDecryptionKeySharesForInnerDealings{}
}

func NewUnverifiedDecryptionKeySharesForInnerDealings() UnverifiedDecryptionKeySharesForInnerDealings {
	return &unverifiedDecryptionKeySharesForInnerDealings{}
}

func (s *decryptionKeySharesForInnerDealings) IsNil() bool {
	return s == nil
}

func (s *decryptionKeySharesForInnerDealings) MarshalTo(target codec.Target) {
	s.curve.MarshalTo(target)
	target.WriteInt(len(s.z_D))
	for _, share := range s.z_D {
		target.WriteOptional(share)
	}
}

func (ds *decryptionKeySharesForInnerDealings) UnmarshalFrom(source codec.Source) *decryptionKeySharesForInnerDealings {
	ds.curve = math.UnmarshalCurve(source)

	numShares := source.ReadInt()
	ds.z_D = make([]math.Scalar, 0)

	for i := 0; i < numShares; i++ {
		ds.z_D = append(ds.z_D, codec.ReadOptional(source, ds.curve.Scalar))
	}

	return ds
}

func (s *unverifiedDecryptionKeySharesForInnerDealings) IsNil() bool {
	return s == nil
}

func (s *unverifiedDecryptionKeySharesForInnerDealings) MarshalTo(target codec.Target) {
	s.base.MarshalTo(target)
}

func (s *unverifiedDecryptionKeySharesForInnerDealings) UnmarshalFrom(source codec.Source) UnverifiedDecryptionKeySharesForInnerDealings {
	return &unverifiedDecryptionKeySharesForInnerDealings{
		codec.ReadObject(source, &decryptionKeySharesForInnerDealings{}),
	}
}

func (s *verifiedDecryptionKeySharesForInnerDealings) IsNil() bool {
	return s == nil
}

func (s *verifiedDecryptionKeySharesForInnerDealings) MarshalTo(target codec.Target) {
	s.base.MarshalTo(target)
}

func (s *verifiedDecryptionKeySharesForInnerDealings) UnmarshalFrom(source codec.Source) VerifiedDecryptionKeySharesForInnerDealings {
	return &verifiedDecryptionKeySharesForInnerDealings{
		codec.ReadObject(source, &decryptionKeySharesForInnerDealings{}),
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewVerifiedInnerDealing() VerifiedInnerDealing {
	return &verifiedInnerDealing{}
}

func (d *verifiedInnerDealing) IsNil() bool {
	return d == nil
}

func (d *verifiedInnerDealing) MarshalTo(target codec.Target) {
	d.base.MarshalTo(target)
}

func (d *verifiedInnerDealing) UnmarshalFrom(source codec.Source) VerifiedInnerDealing {
	return &verifiedInnerDealing{
		codec.ReadObject(source, &vess.VerifiedDealing{}),
	}
}
