package unsaferand

import (
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	mrand "math/rand"

	"time"
)

// UnsafeRand is a test implementation of io.Reader and cipher.Stream based on math/rand.Rand.
// The generated sequence is not cryptographically secure and should only be used for testing purposes.
// The underlying math.Rand is not safe for concurrent use.
type UnsafeRand struct {
	*mrand.Rand
}

var _ io.Reader = &UnsafeRand{}
var _ cipher.Stream = &UnsafeRand{}

// Initializes a new UnsafeRand that produces a deterministic randomness based on the given seed argument(s).
// The generated sequence is not cryptographically secure and should only be used for testing purposes.
// Deterministic behavior depends on the fmt.Sprintf("%#v", seedArgs...) representation of the passed arguments.
// Map iteration order is not guaranteed, so passing a map as a seed argument may lead to non-deterministic behavior.
func New(seedArgs ...any) *UnsafeRand {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%#v", seedArgs)

	seed := int64(h.Sum64())
	return &UnsafeRand{mrand.New(mrand.NewSource(seed))}
}

// Initializes a new UnsafeRand that produces non-deterministic randomness.
func NewNondeterministic() *UnsafeRand {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return &UnsafeRand{mrand.New(mrand.NewSource(time.Now().UnixNano()))}
	}
	seed := int64(binary.LittleEndian.Uint64(b[:]))
	return &UnsafeRand{mrand.New(mrand.NewSource(seed))}
}

// Unsafe implementation of the cipher.Stream interface, based on a local *rand.Rand.
// The generated sequence is not cryptographically secure and should only be used for testing purposes.
func (r *UnsafeRand) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("unsaferand: dst too short")
	}

	const chunkSize = 4096
	buffer := make([]byte, min(chunkSize, len(src)))

	for len(src) > 0 {
		n := min(chunkSize, len(src))
		_, _ = r.Read(buffer[:n]) // rand.Read never returns an error
		subtle.XORBytes(dst[:n], src[:n], buffer[:n])

		src = src[n:]
		dst = dst[n:]
	}
}
