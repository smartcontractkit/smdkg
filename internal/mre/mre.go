package mre

import (
	"crypto/subtle"
	"fmt"

	"github.com/smartcontractkit/smdkg/internal/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/hash"
	"github.com/smartcontractkit/smdkg/internal/serialization"
)

// A single Ciphertext instance represents the ciphertexts encrypted for all recipients.
type Ciphertext = []byte

// Given, a list of n plaintext messages m₁, m₂, ..., mₙ, and a list of n encryption keys ek₁, ek₂, ..., ekₙ of
// equal length, this functions encryptions message mᵢ for the corresponding recipient i with encryption key ekᵢ.
//   - The function returns a ciphertext, which is a single byte slice encoding the ciphertexts for all recipients.
//   - The encryption is randomized using a 16-byte nonce, used to deterministically derive r.
//   - The function supports authenticating the additional data field ad (but does not encrypt it).
//   - The function gracefully handles invalid encryption keys (passed as nil values). Recipients with invalid keys are
//     skipped, and the corresponding ciphertexts are set to nil.
func Encrypt(ek []dkgtypes.P256PublicKey, m [][]byte, ad []byte, nonce [16]byte) ([]byte, error) {
	if len(ek) != len(m) {
		return nil, fmt.Errorf("number of encryption keys (%d) must match number of messages (%d)", len(ek), len(m))
	}
	n := len(ek)

	// The encryption is randomized using a 16-byte nonce, used to deterministically derive the random scalar r.
	// Note that here r is implemented as a P256 key pair, giving easy easy access to the value of r and g ^ r.
	r, err := h_R(nonce)
	if err != nil {
		return nil, err
	}
	Eₒ := r.PublicKey // Eₒ = g ^ r

	// Initialize an encoder to hold the ciphertexts for all recipients.
	encoder := serialization.NewEncoder()
	encoder.WriteBytes(Eₒ.Bytes()) // append the special Eₒ value to the ciphertext

	for i := 0; i < n; i++ {
		// Ensure that no message is nil.
		if m[i] == nil {
			return nil, fmt.Errorf("encrypting nil message (index %d) not supported", i)
		}

		// Gracefully handle invalid encryption keys.
		// If the public key is nil, we skip the encryption for this recipient and append a nil ciphertext.
		if !ek[i].IsValid() {
			encoder.WriteBytes(nil)
			continue
		}

		// Compute the shared ECDH secret between the local secret key and the recipient's public key.
		// The ECDH secret is computed as ekᵢ ^ r (the 32 bytes x-coordinate of the resulting point).
		ekᵢʳ, err := r.SecretKey.ECDH(ek[i])
		if err != nil {
			// Gracefully handle an encryption failure for a specific recipient. This is a defensive check, as we check
			// the validity of the public key above, and therefore expect the operation to succeed.
			encoder.WriteBytes(nil)
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

		// Append the ciphertext Eᵢ for the i-th recipient to the output.
		encoder.WriteBytes(Eᵢ)
	}

	E, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ciphertext: %w", err)
	}
	return E, nil
}

// Decrypt decrypts the i'th of of an expected number of n ciphertexts in E using the decryption key dkᵢ, and checks
// the integrity of the authenticated data ad. The ciphertext's index i is zero-based and must be in the range
// {0, 1, 2, ..., n-1}. The function attempts to decodes all n ciphertexts, skipping empty ones. If parsing of E fails,
// an error is returned. Only if all ciphertexts are successfully parsed (they may be nil though), the function proceeds
// to decrypt the i'th ciphertext and return it.
func Decrypt(n int, D dkgtypes.PrivateIdentity, E Ciphertext, ad []byte) ([]byte, error) {
	i := D.Index()

	if n <= 0 {
		return nil, fmt.Errorf("invalid number of ciphertexts: %d, must be positive", n)
	}
	if i >= n {
		return nil, fmt.Errorf("invalid ciphertext index: %d, must be in the range [0, %d)", i, n)
	}

	// Get the encryption key for the i'th recipient, ekᵢ := g ^ dkᵢ
	ekᵢ := D.PublicKey()

	// Initialize a decoder to read the special value Eₒ and n ciphertexts.
	decoder := serialization.NewDecoder(E)

	// Read the specical Eₒ = g ^ r value.
	Eₒ, err := dkgtypes.NewP256PublicKey(decoder.ReadBytes())
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: failed to unmarshal Eₒ: %w", err)
	}

	// Read all ciphertexts E₁, E₂, ..., Eₙ, storing the i'th ciphertext Eᵢ, that should be decrypted.
	var Eᵢ []byte
	for j := 0; j < n; j++ {
		if i == j {
			Eᵢ = decoder.ReadBytes()
			if Eᵢ == nil {
				return nil, fmt.Errorf("invalid ciphertext: decryption failed, nil ciphertext for index %d detected", i)
			}
		} else {
			// Skip the ciphertexts for other recipients, we don't need them.
			decoder.ReadBytes()
		}
	}

	// Check for ciphertext decoding errors.
	if err := decoder.Finish(); err != nil {
		return nil, err
	}

	// Compute Eₒ ^ dkᵢ
	Eₒᶺdkᵢ, err := D.ECDH(Eₒ)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: failed compute ECDH shared secret: %w", err)
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

func CiphertextSize(plaintextSizes []int) int {
	size := serialization.SizeOfEncodedBytesByLength(dkgtypes.P256CompressedPointLength)
	for _, sizeOfPlaintext := range plaintextSizes {
		size += serialization.SizeOfEncodedBytesByLength(sizeOfPlaintext)
	}
	return size
}

func h_Enc(i int, ekᵢ dkgtypes.P256PublicKey, Eₒ dkgtypes.P256PublicKey, ekᵢʳ []byte, ad []byte, digestLenBytes int) ([]byte, error) {
	h := hash.NewHash("smartcontract.com/dkg/mre/hEnc")
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
	h := hash.NewHash("smartcontract.com/dkg/mre/hR")
	h.WriteBytes(r[:])
	return dkgtypes.NewP256KeyPair(h)
}
