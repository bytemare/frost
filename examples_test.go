package frost_test

import (
	"encoding/hex"
	"fmt"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/frost"
	"github.com/bytemare/frost/dkg"
	"github.com/bytemare/frost/internal"
	"github.com/bytemare/frost/internal/schnorr"
)

// ExampleDKG shows the distributed key generation procedure that must be executed by each participant to build the secret key.
func ExampleDKG() {
	// Each participant must be set to use the same configuration.
	maximumAmountOfParticipants := 5
	threshold := 3
	configuration := frost.Ristretto255.Configuration()

	// Step 1: Initialise your participant. Each participant must be given an identifier that MUST be unique among
	// all participants. For this example, this participant will have id = 1.
	id, err := configuration.IDFromInt(1)
	if err != nil {
		panic(err)
	}

	participant := dkg.NewParticipant(configuration.Ciphersuite, id, maximumAmountOfParticipants, threshold)

	// Step 2: Call Init() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel.
	round1Data := participant.Init()

	// Step 3: First, collect all round1Data from all other participants. Then call Continue() on each participant
	// providing them with the compiled data.
	accumulatedRound1Data := make([]*dkg.Round1Data, maximumAmountOfParticipants)

	// This will return a dedicated package for each other participant that must be sent to them over a secure channel.
	// The intended receiver is specified in the returned data.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	round2Data, _ := participant.Continue(accumulatedRound1Data)

	// Step 3: First, collect all round2Data from all other participants. Then call Finalize() on each participant
	// providing the same input as for Continue() and the collected data from the second round2.
	accumulatedRound2Data := make([]*dkg.Round2Data, maximumAmountOfParticipants)

	// This will, for each participant, return their secret key (which is a share of the global secret signing key),
	// the corresponding verification key, and the global public key.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	participantsSecretKey, participantsVerificationKey, groupPublicKey, _ := participant.Finalize(accumulatedRound1Data, accumulatedRound2Data)

	// Now you can build a Signing Participant for the FROST protocol with this ID and key.
	signingParticipant := configuration.Participant(id, participantsSecretKey)
}

func ExampleFrost_Signer() {
	// The following are your setup variables and configuration.
	numberOfParticipants := 2
	configuration := frost.Ristretto255.Configuration()

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// See ExampleDKG() on how to do generate these shares.
	var participantsSecretKey, participantIdentifier *group.Scalar
	participant := configuration.Participant(participantIdentifier, participantsSecretKey)

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment.
	// Send this to the coordinator or all other participants over an authenticated
	// channel (confidentiality is not required).
	// A participant keeps an internal state during the protocol run across the two rounds.
	commitment := participant.Commit()

	// Step 2: collect the commitments from the other participants and coordinator-chosen the message to sign,
	// and finalize by signing the message.
	message := []byte("example")
	commitments := make(internal.CommitmentList, numberOfParticipants)

	// This will produce a signature share to be sent back to the coordinator.
	// We ignore the error for the demo, but execution MUST be aborted upon errors.
	signatureShare, _ := participant.Sign(message, commitments)
}

func ExampleFrost_Coordinator() {
	/*
		The Coordinator is an entity with the following responsibilities:

		1. Determining which participants will participate (at least MIN_PARTICIPANTS in number);
		2. Coordinating rounds (receiving and forwarding inputs among participants); and
		3. Aggregating signature shares output by each participant, and publishing the resulting signature.

		Note that it is possible to deploy the protocol without a distinguished Coordinator.
	*/

	// The following are your setup variables and configuration.
	const (
		maxParticipants      = 3
		numberOfParticipants = 2 // Must be >= to the threshold, and <= to the total number of participants.
	)
	configuration := frost.Ristretto255.Configuration()

	// This simulates
	var (
		participantPublicKeys []*group.Element
		groupPublicKey        *group.Element
	)

	// A coordinator CAN be a participant. In this instance, we chose it not to be one.
	coordinator := configuration.Participant(nil, nil)

	// 1. Determine which participants will participate (at least MIN_PARTICIPANTS in number).
	var participantIdentifiers [numberOfParticipants]*group.Scalar

	// 2. Receive the participant's commitments and sort the list. Then send the message to be signed and the sorted
	// received commitment list to each participant.
	var commitments internal.CommitmentList
	message := []byte("example")

	commitments.Sort()

	// 3. Collect the participants signature shares, and aggregate them to produce the final signature. This signature
	// SHOULD be verified.
	var signatureShares [numberOfParticipants]*SignatureShare
	signature := coordinator.Aggregate(commitments, message, signatureShares[:])

	if !schnorr.Verify(configuration.Ciphersuite, message, signature, groupPublicKey) {
		fmt.Println("invalid signature")
		// At this point one should try to identify which participant's signature share is invalid and act on it.
		// This verification is done as followed:
		for i, signatureShare := range signatureShares {
			// Verify whether we have the participants commitment
			commitment := commitments.Get(signatureShare.Identifier)
			if commitment == nil {
				panic("commitment not found")
			}

			// Get the public key corresponding to the signature share's participant
			pki := participantPublicKeys[i-1]

			if !coordinator.VerifySignatureShare(commitment, pki, signatureShare.SignatureShare, commitments, message) {
				fmt.Printf("participant %v produced an invalid signature share", signatureShare.Identifier.Encode())
			}
		}

		panic("Failed.")
	}

	fmt.Printf("Valid signature for %q: %v", message, hex.EncodeToString(signature.Encode()))
}
