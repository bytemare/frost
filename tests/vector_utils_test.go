// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
)

type ParticipantList []*frost.Participant

func (p ParticipantList) Get(id *group.Scalar) *frost.Participant {
	for _, i := range p {
		if i.ParticipantInfo.KeyShare.Identifier.Equal(id) == 1 {
			return i
		}
	}

	return nil
}

type testVectorConfig struct {
	MaxParticipants string `json:"MAX_PARTICIPANTS"`
	NumParticipants string `json:"NUM_PARTICIPANTS"`
	MinParticipants string `json:"MIN_PARTICIPANTS"`
	Name            string `json:"name"`
	Group           string `json:"group"`
	Hash            string `json:"hash"`
}

func stringToInt(t *testing.T, s string) int {
	i, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		t.Fatal(err)
	}

	return int(i)
}

func configToConfiguration(t *testing.T, c *testVectorConfig) *frost.Configuration {
	switch c.Group {
	case "ristretto255":
		return frost.Ristretto255.Configuration()

	case "p256":
		return frost.P256.Configuration()
	default:
		t.Fatalf("group not supported: %s", c.Group)
	}

	return nil
}

func stringToGroup(t *testing.T, s string) group.Group {
	switch s {
	case "ristretto255":
		return group.Ristretto255Sha512
	default:
		t.Fatalf("group not supported: %s", s)
	}

	return 0
}

func stringToHash(t *testing.T, s string) hash.Hashing {
	switch s {
	case "SHA-512":
		return hash.SHA512
	default:
		t.Fatalf("hash not supported: %s", s)
	}

	return 0
}

func contextString(s string) []byte {
	switch s {
	case "ristretto255":
		return []byte("FROST-RISTRETTO255-SHA512-v11")
	default:
		return []byte("")
	}
}

func (c testVectorConfig) decode(t *testing.T) *testConfig {
	return &testConfig{
		MaxParticipants: stringToInt(t, c.MaxParticipants),
		NumParticipants: stringToInt(t, c.NumParticipants),
		MinParticipants: stringToInt(t, c.MinParticipants),
		Name:            c.Name,
		Configuration:   configToConfiguration(t, &c),
	}
}

type testConfig struct {
	*frost.Configuration
	Name            string
	ContextString   []byte
	MaxParticipants int
	NumParticipants int
	MinParticipants int
}

type testVectorInput struct {
	GroupSecretKey              ByteToHex   `json:"group_secret_key"`
	GroupPublicKey              ByteToHex   `json:"group_public_key"`
	Message                     ByteToHex   `json:"message"`
	SharePolynomialCoefficients []ByteToHex `json:"share_polynomial_coefficients"`
	Participants                struct {
		Num1 struct {
			ParticipantShare ByteToHex `json:"participant_share"`
		} `json:"1"`
		Num2 struct {
			ParticipantShare ByteToHex `json:"participant_share"`
		} `json:"2"`
		Num3 struct {
			ParticipantShare ByteToHex `json:"participant_share"`
		} `json:"3"`
	} `json:"participants"`
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

func (i testVectorInput) decode(t *testing.T, g group.Group) *testInput {
	input := &testInput{
		GroupSecretKey:              decodeScalar(t, g, i.GroupSecretKey),
		GroupPublicKey:              decodeElement(t, g, i.GroupPublicKey),
		Message:                     i.Message,
		SharePolynomialCoefficients: make([]*group.Scalar, len(i.SharePolynomialCoefficients)),
		Participants:                make([]*secretsharing.KeyShare, 3),
	}

	for j, coeff := range i.SharePolynomialCoefficients {
		input.SharePolynomialCoefficients[j] = decodeScalar(t, g, coeff)
	}

	input.Participants[0] = &secretsharing.KeyShare{
		Identifier: internal.IntegerToScalar(g, 1),
		SecretKey:  decodeScalar(t, g, i.Participants.Num1.ParticipantShare),
	}
	input.Participants[1] = &secretsharing.KeyShare{
		Identifier: internal.IntegerToScalar(g, 2),
		SecretKey:  decodeScalar(t, g, i.Participants.Num2.ParticipantShare),
	}
	input.Participants[2] = &secretsharing.KeyShare{
		Identifier: internal.IntegerToScalar(g, 3),
		SecretKey:  decodeScalar(t, g, i.Participants.Num3.ParticipantShare),
	}

	return input
}

type testInput struct {
	GroupSecretKey              *group.Scalar
	GroupPublicKey              *group.Element
	Message                     []byte
	SharePolynomialCoefficients []*group.Scalar
	Participants                []*secretsharing.KeyShare
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
}

func decodeParticipant(t *testing.T, g group.Group, id int, tp *testParticipant) *participant {
	return &participant{
		ID:                     internal.IntegerToScalar(g, id),
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

type testVectorRoundOneOutputs struct {
	ParticipantList string `json:"participant_list"`
	Participants    struct {
		Num1 testParticipant `json:"1"`
		Num3 testParticipant `json:"3"`
	} `json:"participants"`
}

func splitIDString(s string) []int {
	split := func(r rune) bool {
		return r == ',' || r == ' '
	}

	str := strings.FieldsFunc(s, split)
	ints := make([]int, len(str))
	for i, e := range str {
		j, err := strconv.Atoi(e)
		if err != nil {
			panic(nil)
		}
		ints[i] = j
	}

	return ints
}

func (o testVectorRoundOneOutputs) decode(t *testing.T, g group.Group) *testRoundOneOutputs {
	ids := splitIDString(o.ParticipantList)
	r := &testRoundOneOutputs{
		ParticipantList: make([]*group.Scalar, len(ids)),
		Participants:    make([]*participant, 2),
	}

	for i, id := range ids {
		r.ParticipantList[i] = internal.IntegerToScalar(g, id)
	}

	r.Participants[0] = decodeParticipant(t, g, 1, &o.Participants.Num1)
	r.Participants[1] = decodeParticipant(t, g, 3, &o.Participants.Num3)

	return r
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
	ParticipantList []*group.Scalar
	Participants    []*participant
}

type testVectorRoundTwoOutputs struct {
	ParticipantList string `json:"participant_list"`
	Participants    struct {
		Num1 struct {
			SigShare ByteToHex `json:"sig_share"`
		} `json:"1"`
		Num3 struct {
			SigShare ByteToHex `json:"sig_share"`
		} `json:"3"`
	} `json:"participants"`
}

func (o testVectorRoundTwoOutputs) decode(t *testing.T, g group.Group) *testRoundTwoOutputs {
	ids := splitIDString(o.ParticipantList)
	r := &testRoundTwoOutputs{
		make([]*group.Scalar, len(ids)),
		make([]*secretsharing.KeyShare, len(ids)),
	}

	for i, id := range ids {
		r.ParticipantList[i] = internal.IntegerToScalar(g, id)
	}

	r.Participants[0] = &secretsharing.KeyShare{
		Identifier: internal.IntegerToScalar(g, 1),
		SecretKey:  decodeScalar(t, g, o.Participants.Num1.SigShare),
	}
	r.Participants[1] = &secretsharing.KeyShare{
		Identifier: internal.IntegerToScalar(g, 3),
		SecretKey:  decodeScalar(t, g, o.Participants.Num3.SigShare),
	}

	return r
}

type testRoundTwoOutputs struct {
	ParticipantList []*group.Scalar
	Participants    []*secretsharing.KeyShare
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

func (v testVector) decode(t *testing.T) *test {
	conf := v.Config.decode(t)
	return &test{
		Config:          conf,
		Inputs:          v.Inputs.decode(t, conf.Ciphersuite.Group),
		RoundOneOutputs: v.RoundOneOutputs.decode(t, conf.Ciphersuite.Group),
		RoundTwoOutputs: v.RoundTwoOutputs.decode(t, conf.Ciphersuite.Group),
		FinalOutput:     v.FinalOutput.Sig,
	}
}

type test struct {
	Config          *testConfig
	Inputs          *testInput
	RoundOneOutputs *testRoundOneOutputs
	RoundTwoOutputs *testRoundTwoOutputs
	FinalOutput     []byte
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
