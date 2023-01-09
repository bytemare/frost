package frost_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	"github.com/bytemare/frost/internal/shamir"
)

type ByteToHex []byte

func (j ByteToHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

func (j *ByteToHex) UnmarshalJSON(b []byte) error {
	bs := strings.Trim(string(b), "\"")

	dst, err := hex.DecodeString(bs)
	if err != nil {
		return err
	}

	*j = dst
	return nil
}

/*
	Test vectors as in the .json files
*/

type testVector struct {
	Config          *testVectorConfig          `json:"config"`
	Inputs          *testVectorInput           `json:"inputs"`
	RoundOneOutputs *testVectorRoundOneOutputs `json:"round_one_outputs"`
	RoundTwoOutputs *testVectorRoundTwoOutputs `json:"round_two_outputs"`
	FinalOutput     struct {
		Sig ByteToHex `json:"sig"`
	} `json:"final_output"`
}

type testVectorConfig struct {
	MaxParticipants string `json:"MAX_PARTICIPANTS"`
	NumParticipants string `json:"NUM_PARTICIPANTS"`
	MinParticipants string `json:"MIN_PARTICIPANTS"`
	Name            string `json:"name"`
	Group           string `json:"group"`
	Hash            string `json:"hash"`
}

type testVectorParticipantShare struct {
	ParticipantShare ByteToHex `json:"participant_share"`
	Identifier       int       `json:"identifier"`
}

type testVectorInput struct {
	ParticipantList             []int                        `json:"participant_list"`
	GroupSecretKey              ByteToHex                    `json:"group_secret_key"`
	GroupPublicKey              ByteToHex                    `json:"group_public_key"`
	Message                     ByteToHex                    `json:"message"`
	SharePolynomialCoefficients []ByteToHex                  `json:"share_polynomial_coefficients"`
	ParticipantShares           []testVectorParticipantShare `json:"participant_shares"`
}

type testVectorRoundOneOutputs struct {
	Outputs []testParticipant `json:"outputs"`
}

type testVectorSigShares struct {
	SigShare   ByteToHex `json:"sig_share"`
	Identifier int       `json:"identifier"`
}

type testVectorRoundTwoOutputs struct {
	Outputs []testVectorSigShares `json:"outputs"`
}

/*
	Parsed and deserialized vectors
*/

type test struct {
	Config          *testConfig
	Inputs          *testInput
	RoundOneOutputs *testRoundOneOutputs
	RoundTwoOutputs *testRoundTwoOutputs
	FinalOutput     []byte
}

type testConfig struct {
	Name            string
	ContextString   []byte
	MaxParticipants int
	NumParticipants int
	MinParticipants int
	Hash            hash.Hashing
	Group           group.Group
}

type testInput struct {
	ParticipantList             []*group.Scalar
	GroupSecretKey              *group.Scalar
	GroupPublicKey              *group.Element
	Message                     []byte
	SharePolynomialCoefficients []*group.Scalar
	Participants                []*shamir.Share
}

type testParticipant struct {
	HidingNonceRandomness  ByteToHex `json:"hiding_nonce_randomness"`
	BindingNonceRandomness ByteToHex `json:"binding_nonce_randomness"`
	HidingNonce            ByteToHex `json:"hiding_nonce"`
	BindingNonce           ByteToHex `json:"binding_nonce"`
	HidingNonceCommitment  ByteToHex `json:"hiding_nonce_commitment"`
	BindingNonceCommitment ByteToHex `json:"binding_nonce_commitment"`
	BindingFactorInput     ByteToHex `json:"binding_factor_input"`
	BindingFactor          ByteToHex `json:"binding_factor"`
	Identifier             int       `json:"identifier"`
}

type participant struct {
	ID                     *group.Scalar
	HidingNonce            *group.Scalar
	BindingNonce           *group.Scalar
	HidingNonceCommitment  *group.Element
	BindingNonceCommitment *group.Element
	BindingFactor          *group.Scalar
	HidingNonceRandomness  []byte
	BindingNonceRandomness []byte
	BindingFactorInput     []byte
}

type testRoundOneOutputs struct {
	Outputs []*participant
}

type testRoundTwoOutputs struct {
	Outputs []*shamir.Share
}
