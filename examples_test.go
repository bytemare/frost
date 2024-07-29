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

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
)

var (
// participantsGeneratedInDKG   []*frost.Participant
// commitment                   *frost.Commitment
// groupPublicKeyGeneratedInDKG *group.Element
)

// Example_signer shows the execution steps of a FROST participant.
func Example_signer() {
	maxParticipants := 5
	threshold := 3
	message := []byte("example message")
	ciphersuite := frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// This example uses a centralised trusted dealer, but it is strongly recommended to use distributed key generation,
	// e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, maxParticipants, threshold)

	// Since we used a centralised key generation, we only take the first key share for our participant.
	participantSecretKeyShare := secretKeyShares[0]
	participant := ciphersuite.Participant(participantSecretKeyShare)
	commitments := make(frost.CommitmentList, threshold)

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment.
	// Send this to the coordinator or all other participants over an authenticated
	// channel (confidentiality is not required).
	// A participant keeps an internal state during the protocol run across the two rounds.
	// A participant can pre-compute multiple commitments in advance: these commitments can be shared, but the
	// participant keeps an internal state of corresponding values, so it must the same instance or a backup of it using
	commitment := participant.Commit()

	// Step 2: collect the commitments from the other participants and coordinator-chosen the message to sign,
	// and finalize by signing the message.
	commitments[0] = commitment

	// This is not part of a participant's flow, but we need to collect the commitments of the other participants.
	{
		for i := 1; i < threshold; i++ {
			commitments[i] = ciphersuite.Participant(secretKeyShares[i]).Commit()
		}
	}

	// Step 3: The participant receives the commitments from the other signer and the message to sign.
	// Sign produce a signature share to be sent back to the coordinator.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	signatureShare, err := participant.Sign(commitment.CommitmentID, message, commitments)
	if err != nil {
		panic(err)
	}

	// This shows how to verify a single signature share
	conf := ciphersuite.Configuration()
	if err = conf.VerifySignatureShare(commitment, message, signatureShare, commitments, groupPublicKey); err != nil {
		panic(fmt.Sprintf("signature share verification failed: %s", err))
	}

	fmt.Println("Signing successful.")

	// Output: Signing successful.
}

// Example_verification shows how to verify a FROST signature produced by multiple signers.
func Example_verification() {
	maxParticipants := 5
	threshold := 3
	message := []byte("example message")
	ciphersuite := frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// This example uses a centralised trusted dealer, but it is strongly recommended to use distributed key generation,
	// e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, maxParticipants, threshold)
	participantSecretKeyShares := secretKeyShares[:threshold]
	participants := make([]*frost.Participant, threshold)

	// Create a participant on each instance
	for i, ks := range participantSecretKeyShares {
		participants[i] = ciphersuite.Participant(ks)
	}

	// Pre-commit
	commitments := make(frost.CommitmentList, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}

	commitments.Sort()

	// Sign
	signatureShares := make([]*frost.SignatureShare, threshold)
	for i, p := range participants {
		var err error
		signatureShares[i], err = p.Sign(commitments[i].CommitmentID, message, commitments)
		if err != nil {
			panic(err)
		}
	}

	// A coordinator, proxy, assembles the shares
	configuration := ciphersuite.Configuration()
	signature := configuration.AggregateSignatures(message, signatureShares, commitments, groupPublicKey)

	// Verify the signature
	conf := ciphersuite.Configuration()
	success := conf.VerifySignature(message, signature, groupPublicKey)

	if success {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}

	// Output: Signature is valid.
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
	maxParticipants := 5
	threshold := 3
	message := []byte("example message")
	ciphersuite := frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// This example uses a centralised trusted dealer, but it is strongly recommended to use distributed key generation,
	// e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, maxParticipants, threshold)
	participantSecretKeyShares := secretKeyShares[:threshold]
	participants := make([]*frost.Participant, threshold)

	// Create a participant on each instance
	for i, ks := range participantSecretKeyShares {
		participants[i] = ciphersuite.Participant(ks)
	}

	// Pre-commit
	commitments := make(frost.CommitmentList, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}

	commitments.Sort()

	// Sign
	signatureShares := make([]*frost.SignatureShare, threshold)
	for i, p := range participants {
		var err error
		signatureShares[i], err = p.Sign(commitments[i].CommitmentID, message, commitments)
		if err != nil {
			panic(err)
		}
	}

	// Set up a coordinator, and assemble the shares.
	configuration := ciphersuite.Configuration()
	signature := configuration.AggregateSignatures(message, signatureShares, commitments, groupPublicKey)

	// Verify the signature and identify potential foul players.
	if !configuration.VerifySignature(message, signature, groupPublicKey) {
		// At this point one should try to identify which participant's signature share is invalid and act on it.
		// This verification is done as follows:
		for _, signatureShare := range signatureShares {
			// Verify whether we have the participants commitment
			commitmentI := commitments.Get(signatureShare.Identifier)
			if commitmentI == nil {
				panic("commitment not found")
			}

			if err := configuration.VerifySignatureShare(commitmentI, message, signatureShare, commitments, groupPublicKey); err != nil {
				panic(
					fmt.Sprintf(
						"participant %v produced an invalid signature share: %s",
						signatureShare.Identifier,
						err,
					),
				)
			}
		}

		panic("Signature verification failed.")
	}

	fmt.Printf("Valid signature for %q.", message)

	// Output: Valid signature for "example message".
}
