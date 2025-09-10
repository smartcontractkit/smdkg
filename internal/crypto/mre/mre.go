package mre

import (
	"crypto/subtle"
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/xof"
)

// A single Ciphertext instance represents the ciphertexts encrypted for all recipients.
type Ciphertext = []byte

var _ codec.Codec[*ciphertext] = &ciphertext{}

// Internal structure to hold the ciphertexts for all recipients.
// Externally, the ciphertext is represented as a single byte slice.
type ciphertext struct {
	n  int
	Eₒ dkgtypes.P256PublicKey
	E  [][]byte
}

// MarshalTo encodes the ciphertext structure to the given target.
// The length field n is not encoded, it must be known to the decoder.
func (c *ciphertext) MarshalTo(target codec.Target) {
	target.Write(c.Eₒ)
	for _, Eᵢ := range c.E {
		// Each Eᵢ is length-prefixed, adding 8 bytes of overhead per Eᵢ.
		// Potential optimization: Consider a more compact (VESS-aware?) encoding to reduce the overhead.
		target.WriteLengthPrefixedBytes(Eᵢ)
	}
}

// UnmarshalFrom populates the ciphertext structure from the given source.
// Note that n must be set prior to calling this function.
func (c *ciphertext) UnmarshalFrom(src codec.Source) *ciphertext {
	c.Eₒ = codec.ReadObject(src, dkgtypes.P256PublicKey{})
	c.E = make([][]byte, c.n)
	for i := 0; i < c.n; i++ {
		c.E[i] = src.ReadLengthPrefixedBytes()
	}
	return c
}

func (c *ciphertext) IsNil() bool {
	return c == nil
}

// Given, a list of n plaintext messages m₁, m₂, ..., mₙ, and a list of n encryption keys ek₁, ek₂, ..., ekₙ of
// equal length, this function encrypts message mᵢ for the corresponding recipient i with encryption key ekᵢ.
//   - The function returns a ciphertext, which is a single byte slice encoding the ciphertexts for all recipients.
//   - The encryption is randomized using a 16-byte nonce, used to deterministically derive r.
//   - The function supports associated data with the field ad (but does not encrypt it).
//   - The function gracefully handles invalid encryption keys (passed as nil values). Recipients with invalid keys are
//     skipped, and the corresponding ciphertexts are set to nil.
func Encrypt(ek []dkgtypes.P256PublicKey, m [][]byte, ad []byte, nonce [16]byte) ([]byte, error) {
	if len(ek) != len(m) {
		return nil, fmt.Errorf("number of encryption keys (%d) must match number of messages (%d)", len(ek), len(m))
	}
	n := len(ek)

	// The encryption is randomized using a 16-byte nonce, used to deterministically derive the random scalar r.
	// Note that here r is implemented as a P256 key pair, giving easy access to the value of r and g ^ r.
	r, err := h_R(nonce)
	if err != nil {
		return nil, err
	}
	Eₒ := r.PublicKey // Eₒ = g ^ r

	// Initialize an ciphertext structure to hold Eₒ and all Eᵢ.
	ciphertext := &ciphertext{n, Eₒ, make([][]byte, n)}

	for i := 0; i < n; i++ {
		// Ensure that no message is nil.
		if m[i] == nil {
			return nil, fmt.Errorf("encrypting nil message (index %d) not supported", i)
		}

		// Gracefully handle invalid encryption keys.
		// If the public key is nil, we skip the encryption for this recipient and append a nil ciphertext.
		if !ek[i].IsValid() {
			continue
		}

		// Compute the shared ECDH secret between the local secret key and the recipient's public key.
		// The ECDH secret is computed as ekᵢ ^ r (the 32 bytes x-coordinate of the resulting point).
		ekᵢʳ, err := r.SecretKey.ECDH(ek[i])
		if err != nil {
			// Gracefully handle an encryption failure for a specific recipient. This is a defensive check, as we check
			// the validity of the public key above, and therefore expect the operation to succeed.
			continue
		}

		// Eᵢ := mᵢ xor H_enc(i, ek[i], E0, ekᵢʳ, ad)
		// Note that this is essentially a one-time pad encryption with no protection against tampering of the
		// ciphertext, it is intended to be that way.
		Eᵢ, err := h_Enc(i, ek[i], Eₒ, ekᵢʳ, ad, len(m[i]))
		if err != nil {
			return nil, err
		}
		subtle.XORBytes(Eᵢ, m[i], Eᵢ)

		// Store the ciphertext Eᵢ for the i-th recipient to the output.
		ciphertext.E[i] = Eᵢ
	}

	E, err := codec.Marshal(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ciphertext: %w", err)
	}
	return E, nil
}

// Decrypt decrypts the i'th of of an expected number of n ciphertexts in E using the decryption key dkᵢ. The
// ciphertext's index i is zero-based and must be in the range {0, 1, 2, ..., n-1}. The function attempts to decode all
// n ciphertexts, skipping empty ones. If parsing of E fails, an error is returned. Only if all ciphertexts are
// successfully parsed (they may be nil though), the function proceeds to decrypt the i'th ciphertext and return it.
// If an invalid decryption key or associated data ad is provided, the function returns a random "garbage" plaintext.
func Decrypt(n int, i int, Dᵢ dkgtypes.P256Keyring, E Ciphertext, ad []byte) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid number of ciphertexts: %d, must be positive", n)
	}
	if i < 0 || i >= n {
		return nil, fmt.Errorf("invalid ciphertext index: %d, must be in the range [0, %d)", i, n)
	}

	// Get the encryption key for the i'th recipient, ekᵢ := g ^ dkᵢ
	ekᵢ := Dᵢ.PublicKey()

	// Initialize a decoder to read the special value Eₒ and n ciphertexts.
	ciphertext, err := codec.Unmarshal(E, &ciphertext{n: n})
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: failed to decode: %w", err)
	}

	// Get the special Eₒ = g ^ r value.
	Eₒ := ciphertext.Eₒ

	// Get the i'th ciphertext
	Eᵢ := ciphertext.E[i]
	if Eᵢ == nil {
		return nil, fmt.Errorf("invalid ciphertext: decryption failed, nil ciphertext for index %d detected", i)
	}

	// Compute Eₒ ^ dkᵢ
	Eₒᶺdkᵢ, err := Dᵢ.ECDH(Eₒ)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: failed to compute ECDH shared secret: %w", err)
	}

	// Compute mᵢ := H_enc(i, ekᵢ, Eₒ, Eₒ ^ dkᵢ, ad)
	mᵢ, err := h_Enc(i, ekᵢ, Eₒ, Eₒᶺdkᵢ, ad, len(Eᵢ))
	if err != nil {
		return nil, err
	}
	// Compute mᵢ := mᵢ xor Eᵢ
	subtle.XORBytes(mᵢ, mᵢ, Eᵢ)

	return mᵢ, nil
}

// Returns the expected size of a MRE ciphertext encrypting a plaintext to n recipients.
// The parameter totalPlaintextSize is the sum of the lengths of all plaintexts.
func CiphertextSize(n int, totalPlaintextSize int) int {
	size := dkgtypes.P256CompressedPointLength
	size += n * codec.IntSize  // length prefixes for all Eᵢ
	size += totalPlaintextSize // length of all Eᵢ (one scalar per)
	return size
}

func h_Enc(i int, ekᵢ dkgtypes.P256PublicKey, Eₒ dkgtypes.P256PublicKey, ekᵢʳ []byte, ad []byte, digestLenBytes int) ([]byte, error) {
	h := xof.New("smartcontract.com/dkg/mre/hEnc")
	h.WriteInt(i)
	h.WriteBytes(ekᵢ.Bytes())
	h.WriteBytes(Eₒ.Bytes())
	h.WriteBytes(ekᵢʳ)
	h.WriteBytes(ad)

	out := make([]byte, digestLenBytes)
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func h_R(r [16]byte) (dkgtypes.P256KeyPair, error) {
	h := xof.New("smartcontract.com/dkg/mre/hR")
	h.WriteBytes(r[:])
	return dkgtypes.NewP256KeyPair(h)
}
