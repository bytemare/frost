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

// AggregateSignatures enables a coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid, deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the signer from the set of allowed participants in future runs of FROST. If verify
// is set to true, AggregateSignatures will automatically verify the signature shares and the output signature, and will
// return an error with the first encountered invalid signature share.
func (c *Configuration) AggregateSignatures(
	message []byte,
	sigShares []*SignatureShare,
	commitments CommitmentList,
	verify bool,
) (*Signature, error) {
	groupCommitment, bindingFactors, participants, err := c.PrepareSignatureShareVerification(message, commitments)
	if err != nil {
		return nil, err
	}

	if verify {
		for _, share := range sigShares {
			if err = c.verifySignatureShare(share, message, commitments, participants,
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
			// difficult to reach, because if all shares are valid, the final signature is valid.
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
	commitments CommitmentList,
) error {
	groupCommitment, bindingFactors, participants, err := c.PrepareSignatureShareVerification(message, commitments)
	if err != nil {
		return err
	}

	return c.verifySignatureShare(sigShare, message, commitments, participants, groupCommitment, bindingFactors)
}

func (c *Configuration) PrepareSignatureShareVerification(message []byte,
	commitments CommitmentList,
) (*group.Element, BindingFactors, []*group.Scalar, error) {
	if !c.verified {
		if err := c.verify(); err != nil {
			return nil, nil, nil, err
		}
	}

	commitments.Sort()

	// Validate general consistency of the commitment list.
	if err := c.ValidateCommitmentList(commitments); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid list of commitments: %w", err)
	}

	groupCommitment, bindingFactors := commitments.GroupCommitmentAndBindingFactors(c.GroupPublicKey, message)
	participants := commitments.ParticipantsScalar()

	return groupCommitment, bindingFactors, participants, nil
}

func (c *Configuration) getSignerPubKey(id uint64) *group.Element {
	for _, pks := range c.SignerPublicKeys {
		if pks.ID == id {
			return pks.PublicKey
		}
	}

	return nil
}

func (c *Configuration) validateSignatureShareLight(sigShare *SignatureShare) error {
	if sigShare == nil {
		return errors.New("nil signature share")
	}

	if sigShare.SignatureShare == nil || sigShare.SignatureShare.IsZero() {
		return errors.New("invalid signature share (nil or zero)")
	}

	return nil
}

func (c *Configuration) validateSignatureShareExtensive(sigShare *SignatureShare) error {
	if err := c.validateSignatureShareLight(sigShare); err != nil {
		return err
	}

	if sigShare.SignerIdentifier == 0 {
		return errors.New("signature share's signer identifier is 0 (invalid)")
	}

	if sigShare.SignerIdentifier > c.MaxSigners {
		return fmt.Errorf(
			"signature share has invalid ID %d, above authorized range [1:%d]",
			sigShare.SignerIdentifier,
			c.MaxSigners,
		)
	}

	if sigShare.Group != c.group {
		return fmt.Errorf("signature share has invalid group parameter, want %s got %s", c.group, sigShare.Group)
	}

	if c.getSignerPubKey(sigShare.SignerIdentifier) == nil {
		return fmt.Errorf("no public key registered for signer %d", sigShare.SignerIdentifier)
	}

	return nil
}

func (c *Configuration) verifySignatureShare(
	sigShare *SignatureShare,
	message []byte,
	commitments CommitmentList,
	participants []*group.Scalar,
	groupCommitment *group.Element,
	bindingFactors BindingFactors,
) error {
	if err := c.validateSignatureShareExtensive(sigShare); err != nil {
		return err
	}

	com := commitments.Get(sigShare.SignerIdentifier)
	if com == nil {
		return fmt.Errorf("commitment for signer %d is missing", sigShare.SignerIdentifier)
	}

	pk := c.getSignerPubKey(sigShare.SignerIdentifier)
	lambda := internal.Lambda(c.group, sigShare.SignerIdentifier, participants)
	lambdaChall := c.challenge(lambda, message, groupCommitment)

	// Commitment KeyShare: r = g(h + b*f + l*s)
	bindingFactor := bindingFactors[sigShare.SignerIdentifier]
	commShare := com.HidingNonceCommitment.Copy().Add(com.BindingNonceCommitment.Copy().Multiply(bindingFactor))
	r := commShare.Add(pk.Copy().Multiply(lambdaChall))
	l := c.group.Base().Multiply(sigShare.SignatureShare)

	if l.Equal(r) != 1 {
		return fmt.Errorf("invalid signature share for signer %d", sigShare.SignerIdentifier)
	}

	return nil
}
