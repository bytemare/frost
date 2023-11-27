// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"encoding/hex"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/dkg"
)

var (
	participantGeneratedInDKG    *frost.Participant
	commitment                   *frost.Commitment
	groupPublicKeyGeneratedInDKG *group.Element
)

// Example_dkg shows the distributed key generation procedure that must be executed by each participant to build the secret key.
func Example_dkg() {
	// Each participant must be set to use the same configuration.
	maximumAmountOfParticipants := 1
	threshold := 1
	configuration := frost.Ristretto255.Configuration()

	// Step 1: Initialise your participant. Each participant must be given an identifier that MUST be unique among
	// all participants. For this example, this participant will have id = 1.
	participantIdentifier := configuration.IDFromInt(1)
	dkgParticipant := dkg.NewParticipant(
		configuration.Ciphersuite,
		participantIdentifier,
		maximumAmountOfParticipants,
		threshold,
	)

	// Step 2: Call Init() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel.
	round1Data := dkgParticipant.Init()
	if round1Data.SenderIdentifier.Equal(participantIdentifier) != 1 {
		panic("this is just a test, and it failed")
	}

	// Step 3: First, collect all round1Data from all other participants. Then call Continue() on each participant
	// providing them with the compiled data.
	accumulatedRound1Data := make([]*dkg.Round1Data, 0, maximumAmountOfParticipants)
	accumulatedRound1Data = append(accumulatedRound1Data, round1Data)

	// This will return a dedicated package for each other participant that must be sent to them over a secure channel.
	// The intended receiver is specified in the returned data.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	round2Data, err := dkgParticipant.Continue(accumulatedRound1Data)
	if err != nil {
		panic(err)
	} else if len(round2Data) != len(accumulatedRound1Data)-1 {
		panic("this is just a test, and it failed")
	}

	// Step 3: First, collect all round2Data from all other participants. Then call Finalize() on each participant
	// providing the same input as for Continue() and the collected data from the second round2.
	accumulatedRound2Data := round2Data

	// This will, for each participant, return their secret key (which is a share of the global secret signing key),
	// the corresponding verification key, and the global public key.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	var participantsSecretKey *group.Scalar
	participantsSecretKey, _, groupPublicKeyGeneratedInDKG, err = dkgParticipant.Finalize(
		accumulatedRound1Data,
		accumulatedRound2Data,
	)
	if err != nil {
		panic(err)
	}

	// It is important to set the group's public key.
	configuration.GroupPublicKey = groupPublicKeyGeneratedInDKG

	// Now you can build a Signing Participant for the FROST protocol with this ID and key.
	participantGeneratedInDKG = configuration.Participant(participantIdentifier, participantsSecretKey)

	fmt.Printf("Signing keys for participant set up. ID: %s\n", hex.EncodeToString(participantIdentifier.Encode()))

	// Output: Signing keys for participant set up. ID: 0100000000000000000000000000000000000000000000000000000000000000
}

// Example_signer shows the execution steps of a FROST participant.
func Example_signer() {
	// The following are your setup variables and configuration.
	numberOfParticipants := 1

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// See Example_dkg() on how to do generate these shares.
	Example_dkg()
	participant := participantGeneratedInDKG

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment.
	// Send this to the coordinator or all other participants over an authenticated
	// channel (confidentiality is not required).
	// A participant keeps an internal state during the protocol run across the two rounds.
	commitment = participant.Commit()
	if commitment.Identifier.Equal(participant.KeyShare.Identifier) != 1 {
		panic("this is just a test and it failed")
	}

	// Step 2: collect the commitments from the other participants and coordinator-chosen the message to sign,
	// and finalize by signing the message.
	message := []byte("example")
	commitments := make(frost.CommitmentList, 0, numberOfParticipants)
	commitments = append(commitments, commitment)

	// This will produce a signature share to be sent back to the coordinator.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	signatureShare, _ := participant.Sign(message, commitments)
	if !participant.VerifySignatureShare(
		commitment,
		participant.GroupPublicKey,
		signatureShare.SignatureShare,
		commitments,
		message,
	) {
		panic("this is a test and it failed")
	}

	fmt.Println("Signing successful.")

	// Output: Signing keys for participant set up. ID: 0100000000000000000000000000000000000000000000000000000000000000
	// Signing successful.
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

	// The following are your setup variables and configuration.
	const (
		maxParticipants      = 1
		numberOfParticipants = 1 // Must be >= to the threshold, and <= to the total number of participants.
	)

	// 0. We suppose a previous run of DKG with a setup of participants. Here we will only use 1 participant.
	Example_dkg()
	participant := participantGeneratedInDKG
	groupPublicKey := groupPublicKeyGeneratedInDKG

	// A coordinator CAN be a participant. In this instance, we chose it not to be one.
	configuration := frost.Ristretto255.Configuration(groupPublicKey)
	coordinator := configuration.Participant(nil, nil)

	// 1. Determine which participants will participate (at least MIN_PARTICIPANTS in number).
	//participantIdentifiers := [numberOfParticipants]*group.Scalar{
	//	participant.KeyShare.Identifier,
	//}
	participantPublicKeys := []*group.Element{
		participant.ParticipantInfo.PublicKey,
	}

	// 2. Receive the participant's commitments and sort the list. Then send the message to be signed and the sorted
	// received commitment list to each participant.
	commitments := frost.CommitmentList{
		participant.Commit(),
	}
	message := []byte("example")

	commitments.Sort()

	// 3. Collect the participants signature shares, and aggregate them to produce the final signature. This signature
	// SHOULD be verified.
	p1SignatureShare, _ := participant.Sign(message, commitments)
	signatureShares := [numberOfParticipants]*frost.SignatureShare{
		p1SignatureShare,
	}

	signature := coordinator.Aggregate(commitments, message, signatureShares[:])

	if !frost.Verify(configuration.Ciphersuite, message, signature, groupPublicKey) {
		fmt.Println("invalid signature")
		// At this point one should try to identify which participant's signature share is invalid and act on it.
		// This verification is done as follows:
		for i, signatureShare := range signatureShares {
			// Verify whether we have the participants commitment
			commitmentI := commitments.Get(signatureShare.Identifier)
			if commitmentI == nil {
				panic("commitment not found")
			}

			// Get the public key corresponding to the signature share's participant
			pki := participantPublicKeys[i-1]

			if !coordinator.VerifySignatureShare(
				commitmentI,
				pki,
				signatureShare.SignatureShare,
				commitments,
				message,
			) {
				fmt.Printf("participant %v produced an invalid signature share", signatureShare.Identifier.Encode())
			}
		}

		panic("Failed.")
	}

	fmt.Printf("Valid signature for %q.", message)

	// Output: Signing keys for participant set up. ID: 0100000000000000000000000000000000000000000000000000000000000000
	// Valid signature for "example".
}
