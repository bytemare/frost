// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

var errInvalidSignature = errors.New("invalid Signature")

// Signature represent a Schnorr signature.
type Signature struct {
	R *group.Element
	Z *group.Scalar
}

// AggregateSignatures allows a coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid, deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the signer from the set of allowed participants in future runs of FROST. If verify
// is set to true, AggregateSignatures will automatically verify the signature shares and produced signatures, and will
// return an error with the first encountered invalid signature share.
func (c *Configuration) AggregateSignatures(
	message []byte,
	sigShares []*SignatureShare,
	commitments List,
	verify bool,
) (*Signature, error) {
	if !c.verified {
		if err := c.verify(); err != nil {
			return nil, err
		}
	}

	groupCommitment, bindingFactors, err := c.prepSigShareCheck(message, commitments, c.GroupPublicKey)
	if err != nil {
		return nil, err
	}

	if verify {
		for _, share := range sigShares {
			if err = c.verifySignatureShare(share, message, commitments,
				groupCommitment, bindingFactors); err != nil {
				return nil, err
			}
		}
	}

	// Aggregate signatures
	z := group.Group(c.Ciphersuite).NewScalar()
	for _, share := range sigShares {
		z.Add(share.SignatureShare)
	}

	signature := &Signature{
		R: groupCommitment,
		Z: z,
	}

	if verify {
		if err = VerifySignature(c.Ciphersuite, message, signature, c.GroupPublicKey); err != nil {
			return nil, err
		}
	}

	return signature, nil
}

// VerifySignatureShare verifies a signature share. sigShare is the signer's signature share to be verified.
//
// The CommitmentList must be sorted in ascending order by identifier.
func (c *Configuration) VerifySignatureShare(
	sigShare *SignatureShare,
	message []byte,
	commitments List,
) error {
	if !c.verified {
		if err := c.verify(); err != nil {
			return err
		}
	}

	groupCommitment, bindingFactors, err := c.prepSigShareCheck(message, commitments, c.GroupPublicKey)
	if err != nil {
		return err
	}

	return c.verifySignatureShare(sigShare, message, commitments, groupCommitment, bindingFactors)
}

func (c *Configuration) prepSigShareCheck(message []byte,
	commitments List,
	groupPublicKey *group.Element,
) (*group.Element, BindingFactors, error) {
	if !c.verified {
		if err := c.verify(); err != nil {
			return nil, nil, err
		}
	}

	if err := commitments.Verify(c.group, c.Threshold); err != nil {
		return nil, nil, fmt.Errorf("invalid list of commitments: %w", err)
	}

	groupCommitment, bindingFactors := commitments.GroupCommitmentAndBindingFactors(
		groupPublicKey,
		message,
	)

	return groupCommitment, bindingFactors, nil
}

func (c *Configuration) getSignerPubKey(id uint64) *group.Element {
	for _, pks := range c.SignerPublicKeys {
		if pks.ID == id {
			return pks.PublicKey
		}
	}

	return nil
}

func (c *Configuration) verifySignatureShare(
	sigShare *SignatureShare,
	message []byte,
	commitments List,
	groupCommitment *group.Element,
	bindingFactors BindingFactors,
) error {
	com := commitments.Get(sigShare.SignerIdentifier)
	if com == nil {
		return fmt.Errorf("commitment not registered for signer %q", sigShare.SignerIdentifier)
	}

	pk := c.getSignerPubKey(sigShare.SignerIdentifier)
	if pk == nil {
		return fmt.Errorf("public key not registered for signer %q", sigShare.SignerIdentifier)
	}

	participants := commitments.ParticipantsScalar()

	lambdaChall, err := internal.ComputeChallengeFactor(
		c.group,
		groupCommitment,
		nil,
		sigShare.SignerIdentifier,
		message,
		participants,
		c.GroupPublicKey,
	)
	if err != nil {
		return fmt.Errorf("can't compute challenge: %w", err)
	}

	// Commitment KeyShare: r = g(h + b*f + l*s)
	bindingFactor := bindingFactors[sigShare.SignerIdentifier]
	commShare := com.HidingNonce.Copy().Add(com.BindingNonce.Copy().Multiply(bindingFactor))
	r := commShare.Add(pk.Copy().Multiply(lambdaChall))
	l := c.group.Base().Multiply(sigShare.SignatureShare)

	if l.Equal(r) != 1 {
		return fmt.Errorf("invalid signature share for signer %d", sigShare.SignerIdentifier)
	}

	return nil
}

// VerifySignature returns whether the signature of the message is valid under publicKey.
func VerifySignature(c Ciphersuite, message []byte, signature *Signature, publicKey *group.Element) error {
	g := c.ECGroup()
	if g == 0 {
		return internal.ErrInvalidCiphersuite
	}

	ch := internal.SchnorrChallenge(g, message, signature.R, publicKey)
	r := signature.R.Copy().Add(publicKey.Copy().Multiply(ch))
	l := g.Base().Multiply(signature.Z)

	// Clear the cofactor for Edwards25519.
	if g == group.Edwards25519Sha512 {
		cofactor := group.Edwards25519Sha512.NewScalar().SetUInt64(8)
		l.Multiply(cofactor)
		r.Multiply(cofactor)
	}

	if l.Equal(r) != 1 {
		return errInvalidSignature
	}

	return nil
}
