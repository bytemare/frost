package frost

import (
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"
)

// Session contains the public, long-term values needed to describe a FROST signing session.
//
// It is intended for applications that need to persist or transmit the public session material separately from a full
// Configuration. It does not contain secret key shares or nonce state.
type Session struct {
	VerificationKey       *ecc.Element           `json:"verificationKey"`
	SignerPublicKeyShares []*keys.PublicKeyShare `json:"signerPublicKeyShares"`
	Ciphersuite           Ciphersuite            `json:"ciphersuite"`
}
