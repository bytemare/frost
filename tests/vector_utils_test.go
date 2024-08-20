// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost"
)

type ParticipantList []*frost.Signer

func (p ParticipantList) Get(id uint64) *frost.Signer {
	for _, i := range p {
		if i.KeyShare.ID == id {
			return i
		}
	}

	return nil
}

func stringToUint(t *testing.T, s string) uint {
	i, err := strconv.ParseUint(s, 10, 0)
	if err != nil {
		t.Fatal(err)
	}

	return uint(i)
}

func decodeScalar(t *testing.T, g group.Group, enc []byte) *group.Scalar {
	scalar := g.NewScalar()
	if err := scalar.Decode(enc); err != nil {
		t.Fatal(err)
	}

	return scalar
}

func decodeElement(t *testing.T, g group.Group, enc []byte) *group.Element {
	element := g.NewElement()
	if err := element.Decode(enc); err != nil {
		t.Fatal(err)
	}

	return element
}

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

type testVectorInput struct {
	ParticipantList             []uint64                     `json:"participant_list"`
	GroupSecretKey              ByteToHex                    `json:"group_secret_key"`
	GroupPublicKey              ByteToHex                    `json:"group_public_key"`
	Message                     ByteToHex                    `json:"message"`
	SharePolynomialCoefficients []ByteToHex                  `json:"share_polynomial_coefficients"`
	ParticipantShares           []testVectorParticipantShare `json:"participant_shares"`
}

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

func (c testVectorConfig) decode(t *testing.T) *testConfig {
	threshold := stringToUint(t, c.MinParticipants)
	maxSigners := stringToUint(t, c.MaxParticipants)

	return &testConfig{
		Name:            c.Name,
		NumParticipants: stringToUint(t, c.NumParticipants),
		Configuration:   configToConfiguration(t, &c, threshold, maxSigners),
	}
}

type testVectorParticipantShare struct {
	ParticipantShare ByteToHex `json:"participant_share"`
	Identifier       uint64    `json:"identifier"`
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
	Identifier             uint64    `json:"identifier"`
}

type testVectorRoundOneOutputs struct {
	Outputs []testParticipant `json:"outputs"`
}

type testVectorSigShares struct {
	SigShare   ByteToHex `json:"sig_share"`
	Identifier uint64    `json:"identifier"`
}

type testVectorRoundTwoOutputs struct {
	Outputs []testVectorSigShares `json:"outputs"`
}

/*
	Parsed and deserialized vectors
*/

type testConfig struct {
	*frost.Configuration
	Name            string
	ContextString   []byte
	NumParticipants uint
}

type testInput struct {
	ParticipantList             []uint64
	GroupSecretKey              *group.Scalar
	GroupPublicKey              *group.Element
	Message                     []byte
	SharePolynomialCoefficients []*group.Scalar
	Participants                []*frost.KeyShare
}

type test struct {
	Config          *testConfig
	Inputs          *testInput
	RoundOneOutputs *testRoundOneOutputs
	RoundTwoOutputs *testRoundTwoOutputs
	FinalOutput     []byte
}

type participant struct {
	HidingNonce            *group.Scalar
	BindingNonce           *group.Scalar
	HidingNonceCommitment  *group.Element
	BindingNonceCommitment *group.Element
	BindingFactor          *group.Scalar
	HidingNonceRandomness  []byte
	BindingNonceRandomness []byte
	BindingFactorInput     []byte
	ID                     uint64
}

type testRoundOneOutputs struct {
	Outputs []*participant
}

type testRoundTwoOutputs struct {
	Outputs []*frost.SignatureShare
}

/*
	Parsing and decoding functions.
*/

func makeFrostConfig(c frost.Ciphersuite, threshold, maxSigners uint) *frost.Configuration {
	return &frost.Configuration{
		Ciphersuite:      c,
		Threshold:        uint64(threshold),
		MaxSigners:       uint64(maxSigners),
		GroupPublicKey:   nil,
		SignerPublicKeys: nil,
	}
}

func configToConfiguration(t *testing.T, c *testVectorConfig, threshold, maxSigners uint) *frost.Configuration {
	switch c.Group {
	case "ed25519":
		return makeFrostConfig(frost.Ed25519, threshold, maxSigners)
	case "ristretto255":
		return makeFrostConfig(frost.Ristretto255, threshold, maxSigners)
	case "P-256":
		return makeFrostConfig(frost.P256, threshold, maxSigners)
	case "secp256k1":
		return makeFrostConfig(frost.Secp256k1, threshold, maxSigners)
	default:
		t.Fatalf("group not supported: %s", c.Group)
	}

	return nil
}

func decodeParticipant(t *testing.T, g group.Group, tp *testParticipant) *participant {
	return &participant{
		ID:                     tp.Identifier,
		HidingNonceRandomness:  tp.HidingNonceRandomness,
		BindingNonceRandomness: tp.BindingNonceRandomness,
		HidingNonce:            decodeScalar(t, g, tp.HidingNonce),
		BindingNonce:           decodeScalar(t, g, tp.BindingNonce),
		HidingNonceCommitment:  decodeElement(t, g, tp.HidingNonceCommitment),
		BindingNonceCommitment: decodeElement(t, g, tp.BindingNonceCommitment),
		BindingFactorInput:     tp.BindingFactorInput,
		BindingFactor:          decodeScalar(t, g, tp.BindingFactor),
	}
}

func (i testVectorInput) decode(t *testing.T, g group.Group) *testInput {
	input := &testInput{
		GroupSecretKey:              decodeScalar(t, g, i.GroupSecretKey),
		GroupPublicKey:              decodeElement(t, g, i.GroupPublicKey),
		Message:                     i.Message,
		SharePolynomialCoefficients: make([]*group.Scalar, len(i.SharePolynomialCoefficients)+1),
		Participants:                make([]*frost.KeyShare, len(i.ParticipantShares)),
		ParticipantList:             make([]uint64, len(i.ParticipantList)),
	}

	for j, id := range i.ParticipantList {
		input.ParticipantList[j] = id
	}

	input.SharePolynomialCoefficients[0] = input.GroupSecretKey
	for j, coeff := range i.SharePolynomialCoefficients {
		input.SharePolynomialCoefficients[j+1] = decodeScalar(t, g, coeff)
	}

	for j, p := range i.ParticipantShares {
		secret := decodeScalar(t, g, p.ParticipantShare)
		public := g.Base().Multiply(secret)
		input.Participants[j] = &frost.KeyShare{
			Secret:         secret,
			GroupPublicKey: input.GroupPublicKey,
			PublicKeyShare: secretsharing.PublicKeyShare{
				PublicKey:  public,
				Commitment: nil,
				ID:         p.Identifier,
				Group:      g,
			},
		}
	}

	return input
}

func (o testVectorRoundOneOutputs) decode(t *testing.T, g group.Group) *testRoundOneOutputs {
	r := &testRoundOneOutputs{
		Outputs: make([]*participant, len(o.Outputs)),
	}

	for i, p := range o.Outputs {
		r.Outputs[i] = decodeParticipant(t, g, &p)
	}

	return r
}

func (o testVectorRoundTwoOutputs) decode(t *testing.T, g group.Group) *testRoundTwoOutputs {
	r := &testRoundTwoOutputs{
		Outputs: make([]*frost.SignatureShare, len(o.Outputs)),
	}

	for i, p := range o.Outputs {
		r.Outputs[i] = &frost.SignatureShare{
			SignerIdentifier: p.Identifier,
			SignatureShare:   decodeScalar(t, g, p.SigShare),
		}
	}

	return r
}

func (v testVector) decode(t *testing.T) *test {
	conf := v.Config.decode(t)
	inputs := v.Inputs.decode(t, conf.Ciphersuite.ECGroup())

	conf.GroupPublicKey = inputs.GroupPublicKey
	conf.SignerPublicKeys = make([]*frost.PublicKeyShare, len(inputs.Participants))

	for i, ks := range inputs.Participants {
		conf.SignerPublicKeys[i] = ks.Public()
	}

	if err := conf.Configuration.Init(); err != nil {
		t.Fatal(err)
	}

	return &test{
		Config:          conf,
		Inputs:          inputs,
		RoundOneOutputs: v.RoundOneOutputs.decode(t, conf.Ciphersuite.ECGroup()),
		RoundTwoOutputs: v.RoundTwoOutputs.decode(t, conf.Ciphersuite.ECGroup()),
		FinalOutput:     v.FinalOutput.Sig,
	}
}
