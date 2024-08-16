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
	"github.com/bytemare/frost/commitment"
	"github.com/bytemare/frost/debug"
)

// Example_signer shows the execution steps of a FROST participant.
func Example_signer() {
	maxSigners := uint64(5)
	threshold := uint64(3)
	message := []byte("example message")
	ciphersuite := frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// This example uses a centralised trusted dealer, but it is strongly recommended to use distributed key generation,
	// e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)

	// Since we used a centralised key generation, we only take the first key share for our participant.
	participantSecretKeyShare := secretKeyShares[0]

	// At key generation, each participant must send their public key share to the coordinator, and the collection must
	// be broadcast to every participant.
	publicKeyShares := make([]*frost.PublicKeyShare, len(secretKeyShares))
	for i, sk := range secretKeyShares {
		publicKeyShares[i] = sk.Public()
	}

	// This is how to set up the Configuration for FROST, the same for every signer and the coordinator.
	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		panic(err)
	}

	// Instantiate the participant.
	participant, err := configuration.Signer(participantSecretKeyShare)
	if err != nil {
		panic(err)
	}

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment for a
	// a signature. Every commitment has an identifier that must be provided to Sign() to use that commitment.
	// Send this to the coordinator or all other participants over an authenticated
	// channel (confidentiality is not required).
	// A participant keeps an internal state during the protocol run across the two rounds.
	// A participant can pre-compute multiple commitments in advance: these commitments can be shared, but the
	// participant keeps an internal state of corresponding values, so it must the same instance or a backup of it using
	// the serialization functions.
	com := participant.Commit()

	// Step 2: collect the commitments from the other participants and coordinator-chosen the message to sign,
	// and finalize by signing the message.
	commitments := make(commitment.List, threshold)
	commitments[0] = com

	// This is not part of a participant's flow, but we need to collect the commitments of the other participants.
	{
		for i := uint64(1); i < threshold; i++ {
			signer, err := configuration.Signer(secretKeyShares[i])
			if err != nil {
				panic(err)
			}

			commitments[i] = signer.Commit()

		}
	}

	// Step 3: The participant receives the commitments from the other signers and the message to sign.
	// Sign produces a signature share to be sent back to the coordinator.
	// Execution MUST be aborted upon errors.
	signatureShare, err := participant.Sign(com.CommitmentID, message, commitments)
	if err != nil {
		panic(err)
	}

	// This shows how to verify a single signature share
	if err = configuration.VerifySignatureShare(signatureShare, message, commitments); err != nil {
		panic(fmt.Sprintf("signature share verification failed: %s", err))
	}

	fmt.Println("Signing successful.")

	// Output: Signing successful.
}

// Example_coordinator shows how to aggregate signature shares into the final signature, and verify a FROST signature
// produced by multiple signers.
func Example_coordinator() {
	maxSigners := uint64(5)
	threshold := uint64(3)
	message := []byte("example message")
	ciphersuite := frost.Ristretto255

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// The following block uses a centralised trusted dealer to do this, but it is strongly recommended to use
	// distributed key generation, e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, groupPublicKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	participantSecretKeyShares := secretKeyShares[:threshold]
	participants := make([]*frost.Signer, threshold)

	// At key generation, each participant must send their public key share to the coordinator, and the collection must
	// be broadcast to every participant.
	publicKeyShares := make([]*frost.PublicKeyShare, len(secretKeyShares))
	for i, sk := range secretKeyShares {
		publicKeyShares[i] = sk.Public()
	}

	// This is how to set up the Configuration for FROST, the same for every signer and the coordinator.
	configuration := &frost.Configuration{
		Ciphersuite:      ciphersuite,
		Threshold:        threshold,
		MaxSigners:       maxSigners,
		GroupPublicKey:   groupPublicKey,
		SignerPublicKeys: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		panic(err)
	}

	// Create a participant on each instance
	for i, ks := range participantSecretKeyShares {
		signer, err := configuration.Signer(ks)
		if err != nil {
			panic(err)
		}

		participants[i] = signer
	}

	// Pre-commit
	commitments := make(commitment.List, threshold)
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

	// Everything above was a simulation of commitment and signing rounds to produce the signature shares.
	// The following shows how to aggregate these shares, and if verification fails, how to identify a misbehaving signer.

	// The coordinator assembles the shares. If the verify argument is set to true, AggregateSignatures will internally
	// verify each signature share and return an error on the first that is invalid. It will also verify whether the
	// signature is valid.
	signature, err := configuration.AggregateSignatures(message, signatureShares, commitments, true)
	if err != nil {
		panic(err)
	}

	// Verify the signature and identify potential foul players. Note that since we set verify to true when calling
	// AggregateSignatures, the following is redundant.
	// Anyone can verify the signature given the ciphersuite parameter, message, and the group public key.
	if err = frost.VerifySignature(ciphersuite, message, signature, groupPublicKey); err != nil {
		// At this point one should try to identify which participant's signature share is invalid and act on it.
		// This verification is done as follows:
		for _, signatureShare := range signatureShares {
			if err := configuration.VerifySignatureShare(signatureShare, message, commitments); err != nil {
				panic(
					fmt.Sprintf(
						"participant %v produced an invalid signature share: %s",
						signatureShare.SignerIdentifier,
						err,
					),
				)
			}
		}

		fmt.Println(err)
		panic("Signature verification failed.")
	}

	fmt.Println("Signature is valid.")

	// Output: Signature is valid.
}
