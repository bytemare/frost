// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"strconv"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/shamir"
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

func stringToInt(t *testing.T, s string) int {
	i, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		t.Fatal(err)
	}

	return int(i)
}

func stringToCiphersuite(t *testing.T, s string) frost.Ciphersuite {
	switch s {
	case "FROST(Ed25519, SHA-512)":
		return frost.Ed25519
	case "FROST(ristretto255, SHA-512)":
		return frost.Ristretto255
	case "FROST(P-256, SHA-256)":
		return frost.P256
	default:
		t.Fatalf("group not supported: %s", s)
	}

	return 0
}

func stringToGroup(t *testing.T, s string) group.Group {
	switch s {
	case "ed25519":
		return group.Edwards25519Sha512
	case "ristretto255":
		return group.Ristretto255Sha512
	case "P-256":
		return group.P256Sha256
	default:
		t.Fatalf("group not supported: %s", s)
	}

	return 0
}

func stringToHash(t *testing.T, s string) hash.Hashing {
	switch s {
	case "SHA-512":
		return hash.SHA512
	case "SHA-256":
		return hash.SHA256
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

func decodeParticipant(t *testing.T, g group.Group, tp *testParticipant) *participant {
	return &participant{
		ID:                     internal.IntegerToScalar(g, tp.Identifier),
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

func (c testVectorConfig) decode(t *testing.T) *testConfig {
	return &testConfig{
		MaxParticipants: stringToInt(t, c.MaxParticipants),
		NumParticipants: stringToInt(t, c.NumParticipants),
		MinParticipants: stringToInt(t, c.MinParticipants),
		Name:            c.Name,
		Ciphersuite:     stringToCiphersuite(t, c.Name),
		Group:           stringToGroup(t, c.Group),
		Hash:            stringToHash(t, c.Hash),
		ContextString:   contextString(c.Group),
	}
}

func (i testVectorInput) decode(t *testing.T, g group.Group) *testInput {
	input := &testInput{
		ParticipantList:             make([]*group.Scalar, len(i.ParticipantList)),
		GroupSecretKey:              decodeScalar(t, g, i.GroupSecretKey),
		GroupPublicKey:              decodeElement(t, g, i.GroupPublicKey),
		Message:                     i.Message,
		SharePolynomialCoefficients: make([]*group.Scalar, len(i.SharePolynomialCoefficients)),
		Participants:                make([]*shamir.KeyShare, len(i.ParticipantShares)),
	}

	for j, id := range i.ParticipantList {
		input.ParticipantList[j] = internal.IntegerToScalar(g, id)
	}

	for j, coeff := range i.SharePolynomialCoefficients {
		input.SharePolynomialCoefficients[j] = decodeScalar(t, g, coeff)
	}

	for j, p := range i.ParticipantShares {
		input.Participants[j] = &shamir.KeyShare{
			Identifier: internal.IntegerToScalar(g, p.Identifier),
			SecretKey:  decodeScalar(t, g, p.ParticipantShare),
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

type signatureShare struct {
	Identifier *group.Scalar
	SigShare   *group.Scalar
}

func (o testVectorRoundTwoOutputs) decode(t *testing.T, g group.Group) *testRoundTwoOutputs {
	r := &testRoundTwoOutputs{
		Outputs: make([]*signatureShare, len(o.Outputs)),
	}

	for i, p := range o.Outputs {
		r.Outputs[i] = &signatureShare{
			Identifier: internal.IntegerToScalar(g, p.Identifier),
			SigShare:   decodeScalar(t, g, p.SigShare),
		}
	}

	return r
}

func (v testVector) decode(t *testing.T) *test {
	conf := v.Config.decode(t)
	return &test{
		Config:          conf,
		Inputs:          v.Inputs.decode(t, conf.Group),
		RoundOneOutputs: v.RoundOneOutputs.decode(t, conf.Group),
		RoundTwoOutputs: v.RoundTwoOutputs.decode(t, conf.Group),
		FinalOutput:     v.FinalOutput.Sig,
	}
}
