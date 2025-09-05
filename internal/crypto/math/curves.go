package math

import (
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/nistec"
	"github.com/smartcontractkit/smdkg/internal/codec"
)

var SupportedCurves = []Curve{
	P224,
	P256,
	P384,
	P521,
	Edwards25519,
}

var (
	// See:
	//  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
	//  - https://www.rfc-editor.org/rfc/rfc7748.html

	// NIST 800-186, Section3.2.1.2
	p224GroupOrder = NewModulus("26959946667150639794667015087019625940457807714424391721682722368061")

	// NIST 800-186, Section3.2.1.3
	p256GroupOrder = NewModulus("115792089210356248762697446949407573529996955224135760342422259061068512044369")

	// NIST 800-186, Section3.2.1.4
	p384GroupOrder = NewModulus("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643")

	// NIST 800-186, Section3.2.1.5
	p521GroupOrder = NewModulus("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449")

	// RFC 7748, Section 4.1
	edwards25519GroupOrder = NewModulus("7237005577332262213973186563042994240857116359379907606001950938285454250989")
)

const (
	p224CompressedLength         = 29
	p256CompressedLength         = 33
	p384CompressedLength         = 49
	p521CompressedLength         = 67
	edwards25519CompressedLength = 32
)

type p224Curve struct{}
type p256Curve struct{}
type p384Curve struct{}
type p521Curve struct{}
type edwards25519Curve struct{}

var P224 = &p224Curve{}
var P256 = &p256Curve{}
var P384 = &p384Curve{}
var P521 = &p521Curve{}
var Edwards25519 = &edwards25519Curve{}

func (c *p224Curve) internal()         {}
func (c *p256Curve) internal()         {}
func (c *p384Curve) internal()         {}
func (c *p521Curve) internal()         {}
func (c *edwards25519Curve) internal() {}

func (c *p224Curve) Name() string         { return "P224" }
func (c *p256Curve) Name() string         { return "P256" }
func (c *p384Curve) Name() string         { return "P384" }
func (c *p521Curve) Name() string         { return "P521" }
func (c *edwards25519Curve) Name() string { return "Edwards25519" }

func (c *p224Curve) GroupOrder() *Modulus         { return p224GroupOrder }
func (c *p256Curve) GroupOrder() *Modulus         { return p256GroupOrder }
func (c *p384Curve) GroupOrder() *Modulus         { return p384GroupOrder }
func (c *p521Curve) GroupOrder() *Modulus         { return p521GroupOrder }
func (c *edwards25519Curve) GroupOrder() *Modulus { return edwards25519GroupOrder }

func (c *p224Curve) Scalar() Scalar         { return NewScalar(p224GroupOrder) }
func (c *p256Curve) Scalar() Scalar         { return NewScalar(p256GroupOrder) }
func (c *p384Curve) Scalar() Scalar         { return NewScalar(p384GroupOrder) }
func (c *p521Curve) Scalar() Scalar         { return NewScalar(p521GroupOrder) }
func (c *edwards25519Curve) Scalar() Scalar { return NewScalar(edwards25519GroupOrder) }

func (c *p224Curve) Point() Point         { return &P224Point{*nistec.NewP224Point()} }
func (c *p256Curve) Point() Point         { return &P256Point{*nistec.NewP256Point()} }
func (c *p384Curve) Point() Point         { return &P384Point{*nistec.NewP384Point()} }
func (c *p521Curve) Point() Point         { return &P521Point{*nistec.NewP521Point()} }
func (c *edwards25519Curve) Point() Point { return &Edward25519Point{} }

func (c *p224Curve) Generator() Point { return &P224Point{*nistec.NewP224Point().SetGenerator()} }
func (c *p256Curve) Generator() Point { return &P256Point{*nistec.NewP256Point().SetGenerator()} }
func (c *p384Curve) Generator() Point { return &P384Point{*nistec.NewP384Point().SetGenerator()} }
func (c *p521Curve) Generator() Point { return &P521Point{*nistec.NewP521Point().SetGenerator()} }
func (c *edwards25519Curve) Generator() Point {
	return &Edward25519Point{*edwards25519.NewGeneratorPoint()}
}

func (c *p224Curve) ScalarBytes() int         { return 28 }
func (c *p256Curve) ScalarBytes() int         { return 32 }
func (c *p384Curve) ScalarBytes() int         { return 48 }
func (c *p521Curve) ScalarBytes() int         { return 66 }
func (c *edwards25519Curve) ScalarBytes() int { return 32 }

func (c *p224Curve) PointBytes() int         { return p224CompressedLength }
func (c *p256Curve) PointBytes() int         { return p256CompressedLength }
func (c *p384Curve) PointBytes() int         { return p384CompressedLength }
func (c *p521Curve) PointBytes() int         { return p521CompressedLength }
func (c *edwards25519Curve) PointBytes() int { return edwards25519CompressedLength }

func (c *p224Curve) MarshalTo(target codec.Target) { target.WriteBytes([]byte{curveToIndex(c)}) }
func (c *p256Curve) MarshalTo(target codec.Target) { target.WriteBytes([]byte{curveToIndex(c)}) }
func (c *p384Curve) MarshalTo(target codec.Target) { target.WriteBytes([]byte{curveToIndex(c)}) }
func (c *p521Curve) MarshalTo(target codec.Target) { target.WriteBytes([]byte{curveToIndex(c)}) }
func (c *edwards25519Curve) MarshalTo(target codec.Target) {
	target.WriteBytes([]byte{curveToIndex(c)})
}

func UnmarshalCurve(src codec.Source) Curve {
	var index [1]byte
	src.ReadBytesInto(index[:])
	if int(index[0]) >= len(SupportedCurves) {
		panic(fmt.Sprintf("curve lookup failed, index: %d", index))
	}
	return SupportedCurves[index[0]]
}

func CurveByName(name string) Curve {
	for _, curve := range SupportedCurves {
		if curve.Name() == name {
			return curve
		}
	}
	return nil
}

func curveToIndex(curve Curve) byte {
	for i, c := range SupportedCurves {
		if c == curve {
			return byte(i)
		}
	}
	panic("curve not found in SupportedCurves")
}
