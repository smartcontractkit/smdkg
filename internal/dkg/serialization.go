package dkg

import (
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/math"
	"github.com/smartcontractkit/smdkg/internal/vess"
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
	t := r.t_R
	n := len(r.y_R)

	target.WriteString(string(r.iid))
	r.curve.MarshalTo(target)
	target.WriteInt(t)
	target.WriteInt(n)
	target.WriteInt(len(r.Lꞌ))

	for _, ID := range r.Lꞌ {
		target.WriteOptional(ID)
	}

	r.y.MarshalTo(target)

	for _, y_Rᵢ := range r.y_R {
		y_Rᵢ.MarshalTo(target)
	}

	target.WriteBool(r.wasReshared)
}

func (r *result) UnmarshalFrom(source codec.Source) Result {
	r.iid = dkgtypes.InstanceID(source.ReadString())
	r.curve = math.UnmarshalCurve(source)
	t := source.ReadNonNegativeInt()
	n := source.ReadNonNegativeInt()
	l := source.ReadNonNegativeInt() // TODO: add lengths checks for l

	if t < 1 || n < t {
		panic(fmt.Sprintf("result.UnmarshalFrom: invalid parameters (n=%d, t=%d)", n, t))
	}

	r.t_R = t
	r.Lꞌ = make([]VerifiedInnerDealing, l)
	for i := 0; i < l; i++ {
		r.Lꞌ[i] = codec.ReadOptional(source, NewVerifiedInnerDealing)
	}

	r.y = r.curve.Point()
	r.y.UnmarshalFrom(source)

	r.y_R = make([]math.Point, n)
	for i := 0; i < n; i++ {
		r.y_R[i] = r.curve.Point().UnmarshalFrom(source)
	}

	r.wasReshared = source.ReadBool()
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

func NewVerifiedDecryptionKeySharesForInnerDealing() VerifiedDecryptionKeySharesForInnerDealing {
	return &verifiedDecryptionKeySharesForInnerDealing{}
}

func NewUnverifiedDecryptionKeySharesForInnerDealing() UnverifiedDecryptionKeySharesForInnerDealing {
	return &unverifiedDecryptionKeySharesForInnerDealing{}
}

func (s *decryptionKeySharesForInnerDealing) IsNil() bool {
	return s == nil
}

func (s *decryptionKeySharesForInnerDealing) MarshalTo(target codec.Target) {
	s.curve.MarshalTo(target)
	target.WriteInt(len(s.z_D))
	for _, share := range s.z_D {
		target.WriteOptional(share)
	}
}

func (ds *decryptionKeySharesForInnerDealing) UnmarshalFrom(source codec.Source) *decryptionKeySharesForInnerDealing {
	ds.curve = math.UnmarshalCurve(source)

	numShares := source.ReadInt()
	ds.z_D = make([]math.Scalar, numShares)

	for i := 0; i < numShares; i++ {
		ds.z_D[i] = codec.ReadOptional(source, ds.curve.Scalar)
	}

	return ds
}

func (s *unverifiedDecryptionKeySharesForInnerDealing) IsNil() bool {
	return s == nil
}

func (s *unverifiedDecryptionKeySharesForInnerDealing) MarshalTo(target codec.Target) {
	s.base.MarshalTo(target)
}

func (s *unverifiedDecryptionKeySharesForInnerDealing) UnmarshalFrom(source codec.Source) UnverifiedDecryptionKeySharesForInnerDealing {
	return &unverifiedDecryptionKeySharesForInnerDealing{
		codec.ReadObject(source, &decryptionKeySharesForInnerDealing{}),
	}
}

func (s *verifiedDecryptionKeySharesForInnerDealing) IsNil() bool {
	return s == nil
}

func (s *verifiedDecryptionKeySharesForInnerDealing) MarshalTo(target codec.Target) {
	s.base.MarshalTo(target)
}

func (s *verifiedDecryptionKeySharesForInnerDealing) UnmarshalFrom(source codec.Source) VerifiedDecryptionKeySharesForInnerDealing {
	return &verifiedDecryptionKeySharesForInnerDealing{
		codec.ReadObject(source, &decryptionKeySharesForInnerDealing{}),
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
