package math

import (
	"crypto/subtle"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
	"filippo.io/nistec"
	"github.com/smartcontractkit/smdkg/internal/codec"
)

type P224Point struct {
	value nistec.P224Point
}

func (v *P224Point) Curve() Curve {
	return P224
}

func (v *P224Point) New() Point {
	return &P224Point{*nistec.NewP224Point()}
}

func (v *P224Point) Clone() Point {
	return &P224Point{*nistec.NewP224Point().Set(&v.value)}
}

func (v *P224Point) Set(u Point) Point {
	v.value.Set(&u.(*P224Point).value)
	return v
}

func (v *P224Point) Add(p Point, q Point) Point {
	v.value.Add(&p.(*P224Point).value, &q.(*P224Point).value)
	return v
}

func (v *P224Point) Subtract(p Point, q Point) Point {
	negQ := nistec.NewP224Point().Negate(&q.(*P224Point).value)
	v.value.Add(&p.(*P224Point).value, negQ)
	return v
}

func (v *P224Point) ScalarBaseMult(x Scalar) Point {
	_, _ = v.value.ScalarBaseMult(x.Bytes())
	return v
}

func (v *P224Point) ScalarMult(x Scalar, q Point) Point {
	_, _ = v.value.ScalarMult(&q.(*P224Point).value, x.Bytes())
	return v
}

func (v *P224Point) Equal(q Point) bool {
	return subtle.ConstantTimeCompare(v.value.BytesCompressed(), q.(*P224Point).value.BytesCompressed()) == 1
}

func (v *P224Point) Bytes() []byte {
	return v.value.BytesCompressed()
}

func (v *P224Point) BytesUncompressed() []byte {
	return v.value.Bytes()
}

func (v *P224Point) SetBytes(x []byte) (Point, error) {
	if len(x) != p224CompressedLength {
		return nil, fmt.Errorf("invalid P224 point length: %d, expected: %d (compressed format)", len(x), p224CompressedLength)
	}
	_, err := v.value.SetBytes(x)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(v.value.BytesCompressed(), x) != 1 {
		return nil, fmt.Errorf("invalid P224 point: not in canonical form")
	}
	return v, nil
}

func (v *P224Point) MarshalTo(target codec.Target) {
	target.WriteBytes(v.value.BytesCompressed())
}

func (v *P224Point) UnmarshalFrom(source codec.Source) Point {
	var buf [p224CompressedLength]byte
	source.ReadBytesInto(buf[:])
	_, err := v.value.SetBytes(buf[:])
	if err != nil {
		panic("failed to unmarshal P224 point: " + err.Error())
	}
	return v
}

func (v *P224Point) IsNil() bool {
	return v == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type P256Point struct {
	value nistec.P256Point
}

func (v *P256Point) Curve() Curve {
	return P256
}

func (v *P256Point) New() Point {
	return &P256Point{*nistec.NewP256Point()}
}

func (v *P256Point) Clone() Point {
	return &P256Point{*nistec.NewP256Point().Set(&v.value)}
}

func (v *P256Point) Set(u Point) Point {
	v.value.Set(&u.(*P256Point).value)
	return v
}

func (v *P256Point) Add(p Point, q Point) Point {
	v.value.Add(&p.(*P256Point).value, &q.(*P256Point).value)
	return v
}

func (v *P256Point) Subtract(p Point, q Point) Point {
	negQ := nistec.NewP256Point().Negate(&q.(*P256Point).value)
	v.value.Add(&p.(*P256Point).value, negQ)
	return v
}

func (v *P256Point) ScalarBaseMult(x Scalar) Point {
	_, _ = v.value.ScalarBaseMult(x.Bytes())
	return v
}

func (v *P256Point) ScalarMult(x Scalar, q Point) Point {
	_, _ = v.value.ScalarMult(&q.(*P256Point).value, x.Bytes())
	return v
}

func (v *P256Point) Equal(q Point) bool {
	return subtle.ConstantTimeCompare(v.value.BytesCompressed(), q.(*P256Point).value.BytesCompressed()) == 1
}

func (v *P256Point) Bytes() []byte {
	return v.value.BytesCompressed()
}

func (v *P256Point) BytesUncompressed() []byte {
	return v.value.Bytes()
}

func (v *P256Point) SetBytes(x []byte) (Point, error) {
	if len(x) != p256CompressedLength {
		return nil, fmt.Errorf("invalid P256 point length: %d, expected: %d (compressed format)", len(x), p256CompressedLength)
	}
	_, err := v.value.SetBytes(x)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(v.value.BytesCompressed(), x) != 1 {
		return nil, fmt.Errorf("invalid P256 point: not in canonical form")
	}
	return v, nil
}

func (v *P256Point) MarshalTo(target codec.Target) {
	target.WriteBytes(v.value.BytesCompressed())
}

func (v *P256Point) UnmarshalFrom(source codec.Source) Point {
	var buf [p256CompressedLength]byte
	source.ReadBytesInto(buf[:])
	_, err := v.value.SetBytes(buf[:])
	if err != nil {
		panic("failed to unmarshal P256 point: " + err.Error())
	}
	return v
}

func (v *P256Point) IsNil() bool {
	return v == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type P384Point struct {
	value nistec.P384Point
}

func (v *P384Point) Curve() Curve {
	return P384
}

func (v *P384Point) New() Point {
	return &P384Point{*nistec.NewP384Point()}
}

func (v *P384Point) Clone() Point {
	return &P384Point{*nistec.NewP384Point().Set(&v.value)}
}

func (v *P384Point) Set(u Point) Point {
	v.value.Set(&u.(*P384Point).value)
	return v
}

func (v *P384Point) Add(p Point, q Point) Point {
	v.value.Add(&p.(*P384Point).value, &q.(*P384Point).value)
	return v
}

func (v *P384Point) Subtract(p Point, q Point) Point {
	negQ := nistec.NewP384Point().Negate(&q.(*P384Point).value)
	v.value.Add(&p.(*P384Point).value, negQ)
	return v
}

func (v *P384Point) ScalarBaseMult(x Scalar) Point {
	_, _ = v.value.ScalarBaseMult(x.Bytes())
	return v
}

func (v *P384Point) ScalarMult(x Scalar, q Point) Point {
	_, _ = v.value.ScalarMult(&q.(*P384Point).value, x.Bytes())
	return v
}

func (v *P384Point) Equal(q Point) bool {
	return subtle.ConstantTimeCompare(v.value.BytesCompressed(), q.(*P384Point).value.BytesCompressed()) == 1
}

func (v *P384Point) Bytes() []byte {
	return v.value.BytesCompressed()
}

func (v *P384Point) BytesUncompressed() []byte {
	return v.value.Bytes()
}

func (v *P384Point) SetBytes(x []byte) (Point, error) {
	if len(x) != p384CompressedLength {
		return nil, fmt.Errorf("invalid P384 point length: %d, expected: %d (compressed format)", len(x), p384CompressedLength)
	}
	_, err := v.value.SetBytes(x)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(v.value.BytesCompressed(), x) != 1 {
		return nil, fmt.Errorf("invalid P384 point: not in canonical form")
	}
	return v, nil
}

func (v *P384Point) MarshalTo(target codec.Target) {
	target.WriteBytes(v.value.BytesCompressed())
}

func (v *P384Point) UnmarshalFrom(source codec.Source) Point {
	var buf [p384CompressedLength]byte
	source.ReadBytesInto(buf[:])
	_, err := v.value.SetBytes(buf[:])
	if err != nil {
		panic("failed to unmarshal P384 point: " + err.Error())
	}
	return v
}

func (v *P384Point) IsNil() bool {
	return v == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type P521Point struct {
	value nistec.P521Point
}

func (v *P521Point) Curve() Curve {
	return P521
}

func (v *P521Point) New() Point {
	return &P521Point{*nistec.NewP521Point()}
}

func (v *P521Point) Clone() Point {
	return &P521Point{*nistec.NewP521Point().Set(&v.value)}
}

func (v *P521Point) Set(u Point) Point {
	v.value.Set(&u.(*P521Point).value)
	return v
}

func (v *P521Point) Add(p Point, q Point) Point {
	v.value.Add(&p.(*P521Point).value, &q.(*P521Point).value)
	return v
}

func (v *P521Point) Subtract(p Point, q Point) Point {
	negQ := nistec.NewP521Point().Negate(&q.(*P521Point).value)
	v.value.Add(&p.(*P521Point).value, negQ)
	return v
}

func (v *P521Point) ScalarBaseMult(x Scalar) Point {
	_, _ = v.value.ScalarBaseMult(x.Bytes())
	return v
}

func (v *P521Point) ScalarMult(x Scalar, q Point) Point {
	_, _ = v.value.ScalarMult(&q.(*P521Point).value, x.Bytes())
	return v
}

func (v *P521Point) Equal(q Point) bool {
	return subtle.ConstantTimeCompare(v.value.BytesCompressed(), q.(*P521Point).value.BytesCompressed()) == 1
}

func (v *P521Point) Bytes() []byte {
	return v.value.BytesCompressed()
}

func (v *P521Point) BytesUncompressed() []byte {
	return v.value.Bytes()
}

func (v *P521Point) SetBytes(x []byte) (Point, error) {
	if len(x) != p521CompressedLength {
		return nil, fmt.Errorf("invalid P521 point length: %d, expected: %d (compressed format)", len(x), p521CompressedLength)
	}
	_, err := v.value.SetBytes(x)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(v.value.BytesCompressed(), x) != 1 {
		return nil, fmt.Errorf("invalid P521 point: not in canonical form")
	}
	return v, nil
}

func (v *P521Point) MarshalTo(target codec.Target) {
	target.WriteBytes(v.value.BytesCompressed())
}

func (v *P521Point) UnmarshalFrom(source codec.Source) Point {
	var buf [p521CompressedLength]byte
	source.ReadBytesInto(buf[:])
	_, err := v.value.SetBytes(buf[:])
	if err != nil {
		panic("failed to unmarshal P521 point: " + err.Error())
	}
	return v
}

func (v *P521Point) IsNil() bool {
	return v == nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type Edward25519Point struct {
	value edwards25519.Point
}

func (v *Edward25519Point) Curve() Curve {
	return Edwards25519
}

func (v *Edward25519Point) New() Point {
	return &Edward25519Point{}
}

func (v *Edward25519Point) Clone() Point {
	var copy Edward25519Point
	copy.value.Set(&v.value)
	return &copy
}

func (v *Edward25519Point) Set(u Point) Point {
	v.value.Set(&u.(*Edward25519Point).value)
	return v
}

func (v *Edward25519Point) Add(p Point, q Point) Point {
	v.value.Add(&p.(*Edward25519Point).value, &q.(*Edward25519Point).value)
	return v
}

func (v *Edward25519Point) Subtract(p Point, q Point) Point {
	v.value.Subtract(&p.(*Edward25519Point).value, &q.(*Edward25519Point).value)
	return v
}

func (v *Edward25519Point) ScalarBaseMult(x Scalar) Point {
	xBytes := x.Bytes()
	slices.Reverse(xBytes) // edwards25519 expects little-endian, while Scalar is big-endian
	xConverted, err := edwards25519.NewScalar().SetCanonicalBytes(xBytes)
	if err != nil {
		// This should never happen, as a compatible instance of the Scalar abstraction will always be valid.
		panic("invalid scalar: " + err.Error())
	}
	_ = v.value.ScalarBaseMult(xConverted)
	return v
}

func (v *Edward25519Point) ScalarMult(x Scalar, q Point) Point {
	xBytes := x.Bytes()
	slices.Reverse(xBytes) // edwards25519 expects little-endian, while Scalar is big-endian
	xConverted, err := edwards25519.NewScalar().SetCanonicalBytes(xBytes)
	if err != nil {
		// This should never happen, as a compatible instance of the Scalar abstraction will always be valid.
		panic("invalid scalar bytes: " + err.Error())
	}
	_ = v.value.ScalarMult(xConverted, &q.(*Edward25519Point).value)
	return v
}

func (v *Edward25519Point) Equal(q Point) bool {
	return subtle.ConstantTimeCompare(v.Bytes(), q.(*Edward25519Point).Bytes()) == 1
}

func (v *Edward25519Point) Bytes() []byte {
	return v.value.Bytes()
}

func (v *Edward25519Point) SetBytes(x []byte) (Point, error) {
	_, err := v.value.SetBytes(x)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(v.value.Bytes(), x) != 1 {
		return nil, fmt.Errorf("invalid Edwards25519 point: not in canonical form")
	}
	return v, nil
}

func (v *Edward25519Point) MarshalTo(target codec.Target) {
	target.WriteBytes(v.value.Bytes())
}

func (v *Edward25519Point) UnmarshalFrom(source codec.Source) Point {
	var buf [edwards25519CompressedLength]byte
	source.ReadBytesInto(buf[:])
	_, err := v.value.SetBytes(buf[:])
	if err != nil {
		panic("failed to unmarshal Edwards25519 point: " + err.Error())
	}
	return v
}

func (v *Edward25519Point) IsNil() bool {
	return v == nil
}
