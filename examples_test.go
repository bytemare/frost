// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
)

// Example_signer shows the execution steps of a FROST participant.
func Example_signer() {
	maxSigners := uint16(5)
	threshold := uint16(3)
	message := []byte("example message")
	ciphersuite := frost.Default

	// We assume you already have a pool of participants with distinct non-zero identifiers in [1:maxSingers]
	// and their signing share.
	// This example uses a centralised trusted dealer, but it is strongly recommended to use distributed key generation,
	// e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, verificationKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)

	// Since we used a centralised key generation, we only take the first key share for our participant.
	participantSecretKeyShare := secretKeyShares[0]

	// At key generation, each participant must send their public key share to the coordinator, and the collection must
	// be broadcast to every participant.
	publicKeyShares := make([]*keys.PublicKeyShare, len(secretKeyShares))
	for i, sk := range secretKeyShares {
		publicKeyShares[i] = sk.Public()
	}

	// This is how to set up the Configuration for FROST, the same for every signer and the coordinator.
	// Note that every configuration setup for a Signer needs the public key shares of all other signers participating
	// in a signing session (at least for the Sign() step).
	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	if err := configuration.Init(); err != nil {
		panic(err)
	}

	// Instantiate the participant using its secret share.
	// A participant (or Signer) can be backed up by serialization, and directly instantiated from that backup.
	participant, err := configuration.Signer(participantSecretKeyShare)
	if err != nil {
		panic(err)
	}

	// Step 1: call Commit() on each participant. This will return the participant's single-use commitment for a
	// signature (which is independent of the future message to sign).
	// Send this to the coordinator or all other participants (depending on your setup) over an authenticated
	// channel (confidentiality is not required).
	// A participant (or Signer) keeps an internal state during the protocol run across the two rounds.
	// A participant can pre-compute multiple commitments in advance: these commitments can be shared, but the
	// participant keeps an internal state of corresponding values, so it must the same instance or a backup of it using
	// the serialization functions.
	com := participant.Commit()

	// Step 2: collect the commitments from the other participants and coordinator-chosen message to sign,
	// and finalize by signing the message.
	commitments := make(frost.CommitmentList, threshold)
	commitments[0] = com

	// This is not part of a participant's flow, but we need to collect the commitments of the other participants for
	// the demo.
	{
		for i := uint16(1); i < threshold; i++ {
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
	signatureShare, err := participant.Sign(message, commitments)
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

// Example_coordinator shows how to aggregate signature shares produced by signers into the final signature
// and verify a final FROST signature.
func Example_coordinator() {
	maxSigners := uint16(5)
	threshold := uint16(3)
	message := []byte("example message")
	ciphersuite := frost.Default

	// We assume you already have a pool of participants with distinct non-zero identifiers and their signing share.
	// The following block uses a centralised trusted dealer to do this, but it is strongly recommended to use
	// distributed key generation, e.g. from github.com/bytemare/dkg, which is compatible with FROST.
	secretKeyShares, verificationKey, _ := debug.TrustedDealerKeygen(ciphersuite, nil, threshold, maxSigners)
	participantSecretKeyShares := secretKeyShares[:threshold]
	participants := make([]*frost.Signer, threshold)

	// At key generation, each participant must send their public key share to the coordinator, and the collection must
	// be broadcast to every participant.
	publicKeyShares := make([]*keys.PublicKeyShare, len(secretKeyShares))
	for i, sk := range secretKeyShares {
		publicKeyShares[i] = sk.Public()
	}

	// This is how to set up the Configuration for FROST, the same for every signer and the coordinator.
	configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicKeyShares,
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
	commitments := make(frost.CommitmentList, threshold)
	for i, p := range participants {
		commitments[i] = p.Commit()
	}

	commitments.Sort()

	// Sign
	signatureShares := make([]*frost.SignatureShare, threshold)
	for i, p := range participants {
		var err error
		signatureShares[i], err = p.Sign(message, commitments)
		if err != nil {
			panic(err)
		}
	}

	// Everything above was a simulation of commitment and signing rounds to produce the signature shares.
	// The following shows how to aggregate these shares, and if verification fails, how to identify a misbehaving signer.

	// The coordinator assembles the shares. If the verify argument is set to true, AggregateSignatures will internally
	// verify each signature share and return an error on the first that is invalid. It will also verify whether the
	// output signature is valid.
	signature, err := configuration.AggregateSignatures(message, signatureShares, commitments, true)
	if err != nil {
		panic(err)
	}

	// Verify the signature and identify potential foul players. Note that since we set verify to true when calling
	// AggregateSignatures, the following is redundant.
	// Anyone can verify the signature given the ciphersuite parameter, message, and the group public key.
	if err = frost.VerifySignature(ciphersuite, message, signature, verificationKey); err != nil {
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

// Example_key_generation shows how to create keys in a threshold setup with a centralized trusted dealer.
// - a decentralised protocol described in the original FROST paper
func Example_key_generation_centralised_trusted_dealer() {
	maxSigners := uint16(5)
	threshold := uint16(3)
	ciphersuite := frost.Default

	optionnalSecretKey := ciphersuite.Group().NewScalar().Random()
	keyShares, verificationKey, vssCommitment := debug.TrustedDealerKeygen(
		ciphersuite,
		optionnalSecretKey,
		threshold,
		maxSigners,
	)

	fmt.Printf("Created %d key shares with %d vss commitments and %d verification key.",
		len(keyShares),
		len(vssCommitment),
		len([]*ecc.Element{verificationKey}), // yes that line is ugly but it's pretext to use the variable produced.
	)

	// Output: Created 5 key shares with 3 vss commitments and 1 verification key.
}

// Example_key_generation shows how to create keys in a threshold setup with distributed key generation described in
// the original FROST paper.
func Example_key_generation_decentralised() {
	fmt.Println("Visit github.com/bytemare/dkg for an example and documentation.")
	// Output: Visit github.com/bytemare/dkg for an example and documentation.
}

// Example_existing_keys shows how to import existing keys in their canonical byte encoding.
func Example_existing_keys() {
	ciphersuite := frost.Ristretto255
	id := 5
	signerSecretKey := "941c0685dc7c567dd206a39bce556008367fdf633b56c010cde5561435f75b0e"
	signerPublicKey := "d4b9a3acda8acb133c1eff7b99838908c3f9271569c734591ac8f609f321d01a"
	verificationKey := "4400e5808c12c6ef9dc751135acf76edfa73780c08e766537bb6c49bea591872"

	fmt.Println("Decoding to key share:")
	fmt.Printf("- signer identifier: %d\n", id)
	fmt.Printf("- signer secret key: %s\n", signerSecretKey)
	fmt.Printf("- signer public key: %s\n", signerPublicKey)
	fmt.Printf("- global verification key: %s\n", verificationKey)

	// First, let's rebuilt a public key share.
	signerPublicKeyBytes, err := hex.DecodeString(signerPublicKey)
	if err != nil {
		fmt.Println(err)
	}

	signerPublicKeyShare, err := frost.NewPublicKeyShare(ciphersuite, uint16(id), signerPublicKeyBytes)
	if err != nil {
		fmt.Println(err)
	}

	encodedPublicKeyShare := hex.EncodeToString(signerPublicKeyShare.Encode())
	fmt.Printf(
		"Decoded individual elements to a public key share, and re-encoded as a whole: %s\n",
		encodedPublicKeyShare,
	)

	// Now, we rebuilt a private key share.
	signerSecretKeyBytes, err := hex.DecodeString(signerSecretKey)
	if err != nil {
		fmt.Println(err)
	}

	verificationKeyBytes, err := hex.DecodeString(verificationKey)
	if err != nil {
		fmt.Println(err)
	}

	signerKeyShare, err := frost.NewKeyShare(
		ciphersuite,
		uint16(id),
		signerSecretKeyBytes,
		signerPublicKeyBytes,
		verificationKeyBytes,
	)
	if err != nil {
		fmt.Println(err)
	}

	encodedKeyShare := hex.EncodeToString(signerKeyShare.Encode())
	fmt.Printf("Decoded individual elements to a secret key share, and re-encoded as a whole: %s\n", encodedKeyShare)

	if !strings.HasPrefix(encodedKeyShare, encodedPublicKeyShare) {
		fmt.Println(
			"Something went wrong when re-encoding: the public key share must be part of the private key share.",
		)
	}

	// Output: Decoding to key share:
	//- signer identifier: 5
	//- signer secret key: 941c0685dc7c567dd206a39bce556008367fdf633b56c010cde5561435f75b0e
	//- signer public key: d4b9a3acda8acb133c1eff7b99838908c3f9271569c734591ac8f609f321d01a
	//- global verification key: 4400e5808c12c6ef9dc751135acf76edfa73780c08e766537bb6c49bea591872
	//Decoded individual elements to a public key share, and re-encoded as a whole: 01050000000000d4b9a3acda8acb133c1eff7b99838908c3f9271569c734591ac8f609f321d01a
	//Decoded individual elements to a secret key share, and re-encoded as a whole: 01050000000000d4b9a3acda8acb133c1eff7b99838908c3f9271569c734591ac8f609f321d01a941c0685dc7c567dd206a39bce556008367fdf633b56c010cde5561435f75b0e4400e5808c12c6ef9dc751135acf76edfa73780c08e766537bb6c49bea591872
}

// Example_key_deserialization shows how to encode and decode scalars (e.g. secret keys) and elements (e.g. public keys).
// Note you must know the group beforehand.
func Example_key_deserialization() {
	ciphersuite := frost.Ristretto255
	group := ciphersuite.Group()

	// Private keys and scalars.
	privateKeyHex := "941c0685dc7c567dd206a39bce556008367fdf633b56c010cde5561435f75b0e"
	privateKey := group.NewScalar()

	// You can directly decode a hex string to a scalar.
	if err := privateKey.DecodeHex(privateKeyHex); err != nil {
		fmt.Println(err)
	}

	// Or you can use byte slices.
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Println(err)
	}

	if err = privateKey.Decode(privateKeyBytes); err != nil {
		fmt.Println(err)
	}

	if privateKeyHex != privateKey.Hex() {
		fmt.Println("something went wrong re-encoding the scalar in hex, which should yield the same output")
	}

	if !bytes.Equal(privateKeyBytes, privateKey.Encode()) {
		fmt.Println("something went wrong re-encoding the scalar in bytes, which should yield the same output")
	}

	// Same thing for public keys and group elements.
	publicKeyHex := "d4b9a3acda8acb133c1eff7b99838908c3f9271569c734591ac8f609f321d01a"
	publicKey := group.NewElement()

	// You can directly decode a hex string to an element.
	if err = publicKey.DecodeHex(publicKeyHex); err != nil {
		panic(err)
	}

	// Or you can use byte slices.
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		panic(err)
	}

	if err = publicKey.Decode(publicKeyBytes); err != nil {
		panic(err)
	}

	if publicKeyHex != publicKey.Hex() {
		fmt.Println("something went wrong re-encoding the element in hex, which should yield the same output")
	}

	if !bytes.Equal(publicKeyBytes, publicKey.Encode()) {
		fmt.Println("something went wrong re-encoding the element in bytes, which should yield the same output")
	}

	// Output:
}

// Example_deserialize shows how to encode and decode a FROST messages.
func Example_deserialize() {
	verificationKeyHex := "74144431f64b052a173c2505e4224a6cc5f3e81d587d4f23369e1b2b1fd0d427"
	publicKeySharesHex := []string{
		"010100000000003c5ff80cd593a3b7e9007fdbc2b8fe6caee380e7d23eb7ba35160a5b7a51cb08",
		"0102000000000002db540a823f17b975d9eb206ccfbcf3a7667a0365ec1918fa2c3bb69acb105c",
		"010300000000008cff0ae1ded90e77095b55218d3632cd90b669d05c888bca26093681e5250870",
	}

	g := frost.Default.Group()
	verificationKey := g.NewElement()
	if err := verificationKey.DecodeHex(verificationKeyHex); err != nil {
		fmt.Println(err)
	}

	publicKeyShares := make([]*keys.PublicKeyShare, len(publicKeySharesHex))
	for i, p := range publicKeySharesHex {
		publicKeyShares[i] = new(keys.PublicKeyShare)
		if err := publicKeyShares[i].DecodeHex(p); err != nil {
			fmt.Println(err)
		}
	}

	// This is how to set up the Configuration for FROST, the same for every signer and the coordinator.
	// Note that every configuration setup for a Signer needs the public key shares of all other signers participating
	// in a signing session (at least for the Sign() step).
	configuration := &frost.Configuration{
		Ciphersuite:           frost.Default,
		Threshold:             2,
		MaxSigners:            3,
		VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicKeyShares,
	}

	// Decoding a commitment.
	commitment1Hex := "01963090de7d665c5101009073f1a30f4fb9a84275206002fc4394aea7a6cbaf944a7b2f0ae" +
		"9143f39fe62808704f776fccfc0080e90e59fdf9bf0156141732728d41fb15554b46a037a40"
	commitment2Hex := "017615b41957cca8d70200c2d3d3e8133d18daf95aee5371f397771118be5f3917058502637" +
		"0fa893828462400bfab522a542010e70b2b6d4eb388f92b47d6e01abbc16ea24aed5b4fb652"

	commitment1 := new(frost.Commitment)
	if err := commitment1.DecodeHex(commitment1Hex); err != nil {
		fmt.Println(err)
	}

	commitment2 := new(frost.Commitment)
	if err := commitment2.DecodeHex(commitment2Hex); err != nil {
		fmt.Println(err)
	}

	// You can individually check a commitment
	if err := configuration.ValidateCommitment(commitment1); err != nil {
		fmt.Println(err)
	}

	// You can then assemble these commitments to build a list.
	commitmentList := make(frost.CommitmentList, 2)
	commitmentList[0] = commitment1
	commitmentList[1] = commitment2

	encodedCommitmentListBytes := commitmentList.Encode()
	encodedCommitmentListHex := hex.EncodeToString(encodedCommitmentListBytes)

	// Note that the commitments are the same, but serializing using a CommitmentList is slightly different (3 bytes more)
	// since it has a length prefix header.
	commitmentListHex := "010200" +
		"01963090de7d665c5101009073f1a30f4fb9a84275206002fc4394aea7a6cbaf944a7b2f0ae" +
		"9143f39fe62808704f776fccfc0080e90e59fdf9bf0156141732728d41fb15554b46a037a40" +
		"017615b41957cca8d70200c2d3d3e8133d18daf95aee5371f397771118be5f3917058502637" +
		"0fa893828462400bfab522a542010e70b2b6d4eb388f92b47d6e01abbc16ea24aed5b4fb652"

	if commitmentListHex != encodedCommitmentListHex {
		fmt.Println(
			"something went wrong when re-encoding the first commitment list, which should yield the same output",
		)
	}

	// Decoding a whole commitment list.
	decodedCommitmentList, err := frost.DecodeList(encodedCommitmentListBytes)
	if err != nil {
		fmt.Println(err)
	}

	reEncodedListBytes := decodedCommitmentList.Encode()
	if !bytes.Equal(reEncodedListBytes, encodedCommitmentListBytes) {
		fmt.Println(
			"something went wrong when re-encoding the second commitment list, which should yield the same output",
		)
	}

	// Output:
}
