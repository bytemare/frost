// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"fmt"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
)

var (
	maxParticipants              uint
	threshold                    uint
	ciphersuite                  frost.Ciphersuite
	participantsGeneratedInDKG   []*frost.Participant
	commitment                   *frost.Commitment
	groupPublicKeyGeneratedInDKG *group.Element
)

func Example_dkg() {
	// Each participant must be set to use the same configuration.
	if threshold == 0 || maxParticipants == 0 {
		maxParticipants = 5
		threshold = 3
	}

	if ciphersuite == 0 {
		ciphersuite = frost.Ristretto255
	}

	dkgCiphersuite := dkg.Ciphersuite(ciphersuite)

	// Step 1: Initialise each participant. Each participant must be given an identifier that MUST be unique among
	// all participants.
	participants := make([]*dkg.Participant, 0, maxParticipants)
	for i := range maxParticipants {
		p, err := dkgCiphersuite.NewParticipant(uint64(i+1), maxParticipants, threshold)
		if err != nil {
			panic(err)
		}

		participants = append(participants, p)
	}

	// Step 2: Call Start() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel.
	r1 := make([][]byte, 0, maxParticipants)
	for i := range maxParticipants {
		r1 = append(r1, participants[i].Start().Encode())
	}

	// Step 3: First, each participant collects all round1Data from all other participants, and decodes them using
	// NewRound1Data().
	// Then call Continue() on each participant providing them with the compiled data.
	accumulatedRound1Data := make([]*dkg.Round1Data, 0, maxParticipants)
	for i, r := range r1 {
		decodedRound1 := participants[i].NewRound1Data()
		if err := decodedRound1.Decode(r); err != nil {
			panic(err)
		}

		accumulatedRound1Data = append(accumulatedRound1Data, decodedRound1)
	}

	// This will return a dedicated package round2Data for each other participant that must be sent to them over a secure channel.
	// The intended receiver is specified in round2Data.
	// Execution MUST be aborted upon errors, and not rewound. If this fails you should probably investigate this.
	// Since we centrally simulate the setup here, we use a map to keep the messages for participant together.
	r2 := make(map[uint64][][]byte, maxParticipants)
	for _, participant := range participants {
		r, err := participant.Continue(accumulatedRound1Data)
		if err != nil {
			panic(err)
		}

		for id, data := range r {
			if r2[id] == nil {
				r2[id] = make([][]byte, 0, maxParticipants-1)
			}
			r2[id] = append(r2[id], data.Encode())
		}
	}

	// Step 3: First, collect all round2Data from all other participants intended to this participant, and decode them
	// using NewRound2Data().
	// Then call Finalize() on each participant providing the same input as for Continue() and the collected data from the second round.

	// This will, for each participant, return their secret key (which is a share of the global secret signing key),
	// the corresponding verification/public key, and the global public key.
	// In case of errors, execution MUST be aborted.

	keyShares := make([]*frost.KeyShare, maxParticipants)
	participantsGeneratedInDKG = make([]*frost.Participant, maxParticipants)

	for i, participant := range participants {
		accumulatedRound2Data := make([]*dkg.Round2Data, 0, maxParticipants)
		for _, r := range r2[participant.Identifier] {
			d := participant.NewRound2Data()
			if err := d.Decode(r); err != nil {
				panic(err)
			}

			accumulatedRound2Data = append(accumulatedRound2Data, d)
		}

		participantKeys, gpk, err := participant.Finalize(accumulatedRound1Data, accumulatedRound2Data)
		if err != nil {
			panic(err)
		}

		if groupPublicKeyGeneratedInDKG == nil {
			groupPublicKeyGeneratedInDKG = gpk
		}

		keyShare := &frost.KeyShare{
			ID:        participantKeys.Identifier,
			Secret:    participantKeys.SecretKey,
			PublicKey: participantKeys.PublicKey,
		}

		keyShares[i] = keyShare
		participantsGeneratedInDKG[i] = ciphersuite.Configuration(groupPublicKeyGeneratedInDKG).Participant(keyShare)
	}

	fmt.Println("Signing keys set up in DKG.")
	// Output: Signing keys set up in DKG.
}

// Example_signer shows the execution steps of a FROST participant.
func Example_signer() {
	maxParticipants = 5
	threshold = 3
	message := []byte("example message")
	ciphersuite = frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// See Example_dkg() on how to do generate these shares.
	Example_dkg()
	participant := participantsGeneratedInDKG[1]

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment.
	// Send this to the coordinator or all other participants over an authenticated
	// channel (confidentiality is not required).
	// A participant keeps an internal state during the protocol run across the two rounds.
	commitment = participant.Commit()
	if commitment.Identifier != participant.KeyShare.ID {
		panic("this is just a test and it failed")
	}

	// Step 2: collect the commitments from the other participants and coordinator-chosen the message to sign,
	// and finalize by signing the message. This is a dummy list since we have only one signer.
	commitments := make(frost.CommitmentList, 0, threshold)
	commitments = append(commitments, commitment)

	// Step 3: The participant receives the commitments from the other signer and the message to sign.
	// Sign produce a signature share to be sent back to the coordinator.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	signatureShare, err := participant.Sign(message, commitments)
	if err != nil {
		panic(err)
	}

	// This shows how to verify a single signature share
	if !participant.VerifySignatureShare(
		commitment,
		message,
		signatureShare,
		commitments,
	) {
		panic("signature share verification failed")
	}

	fmt.Println("Signing successful.")

	// Output: Signing keys set up in DKG.
	// Signing successful.
}

// Example_verification shows how to verify a FROST signature produced by multiple signers.
func Example_verification() {
	maxParticipants = 5
	threshold = 3

	message := []byte("example message")
	ciphersuite = frost.Ristretto255

	// The following sets up the signer pool and produces a signature to verify.
	Example_dkg()
	participants := participantsGeneratedInDKG[:threshold]
	commitments := make(frost.CommitmentList, threshold)
	signatureShares := make([]*frost.SignatureShare, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}
	for i, p := range participants {
		var err error
		signatureShares[i], err = p.Sign(message, commitments)
		if err != nil {
			panic(err)
		}
	}

	configuration := ciphersuite.Configuration(groupPublicKeyGeneratedInDKG)
	signature := configuration.AggregateSignatures(message, signatureShares, commitments)

	// Verify the signature
	conf := ciphersuite.Configuration(groupPublicKeyGeneratedInDKG)
	success := conf.VerifySignature(message, signature)

	if success {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}

	// Output: Signing keys set up in DKG.
	// Signature is valid.
}

// Example_coordinator shows the execution steps of a FROST coordinator.
func Example_coordinator() {
	/*
		The Coordinator is an entity with the following responsibilities:

		1. Determining which participants will participate (at least MIN_PARTICIPANTS in number);
		2. Coordinating rounds (receiving and forwarding inputs among participants); and
		3. Aggregating signature shares output by each participant, and publishing the resulting signature.

		Note that it is possible to deploy the protocol without a distinguished Coordinator.
	*/
	maxParticipants = 5
	threshold = 3

	message := []byte("example message")
	ciphersuite = frost.Ristretto255

	// 0. We suppose a previous run of a DKG with a setup of participants.
	Example_dkg()
	participants := participantsGeneratedInDKG[:threshold]
	groupPublicKey := groupPublicKeyGeneratedInDKG

	// Set up a coordinator.
	configuration := frost.Ristretto255.Configuration(groupPublicKey)

	// 1. Each participant generates its commitment and sends it to the aggregator.
	// Then send the message to be signed and the sorted received commitment list to each participant.
	commitments := make(frost.CommitmentList, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}

	commitments.Sort()

	// 2. Each participant signs the message and sends the resulting signature shares to the aggregator/coordinator,
	// which aggregates them to produce the final signature. This signature SHOULD be verified.
	var err error
	signatureShares := make([]*frost.SignatureShare, threshold)
	for i, participant := range participants {
		signatureShares[i], err = participant.Sign(message, commitments)
		if err != nil {
			panic(err)
		}
	}

	signature := configuration.AggregateSignatures(message, signatureShares[:], commitments)

	if !configuration.VerifySignature(message, signature) {
		// At this point one should try to identify which participant's signature share is invalid and act on it.
		// This verification is done as follows:
		for _, signatureShare := range signatureShares {
			// Verify whether we have the participants commitment
			commitmentI := commitments.Get(signatureShare.Identifier)
			if commitmentI == nil {
				panic("commitment not found")
			}

			if !configuration.VerifySignatureShare(commitmentI, message, signatureShare, commitments) {
				panic(fmt.Sprintf("participant %v produced an invalid signature share", signatureShare.Identifier))
			}
		}

		panic("Signature verification failed.")
	}

	fmt.Printf("Valid signature for %q.", message)

	// Output: Signing keys set up in DKG.
	// Valid signature for "example message".
}
