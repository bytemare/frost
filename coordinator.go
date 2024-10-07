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

	"github.com/bytemare/ecc"

	"github.com/bytemare/frost/internal"
)

var errInvalidSignature = errors.New("invalid Signature")

// Signature represents a Schnorr signature.
type Signature struct {
	R     *ecc.Element `json:"r"`
	Z     *ecc.Scalar  `json:"z"`
	Group ecc.Group    `json:"group"`
}

// Clear overwrites the original values with default ones.
func (s *Signature) Clear() {
	s.R.Identity()
	s.Z.Zero()
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
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return nil, err
		}
	}

	groupCommitment, bindingFactors, participants, err := c.prepareSignatureShareVerification(message, commitments)
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

	// Aggregate signatures.
	signature, err := c.sumShares(sigShares, groupCommitment)
	if err != nil {
		return nil, err
	}

	// Verify the final signature. Failure is unlikely to happen, as the signature is valid if the signature shares are.
	if verify {
		if err = VerifySignature(c.Ciphersuite, message, signature, c.GroupPublicKey); err != nil {
			return nil, err
		}
	}

	return signature, nil
}

func (c *Configuration) sumShares(shares []*SignatureShare, groupCommitment *ecc.Element) (*Signature, error) {
	z := ecc.Group(c.Ciphersuite).NewScalar()

	for _, sigShare := range shares {
		if err := c.validateSignatureShareLight(sigShare); err != nil {
			return nil, err
		}

		z.Add(sigShare.SignatureShare)
	}

	return &Signature{
		Group: c.group,
		R:     groupCommitment,
		Z:     z,
	}, nil
}

// VerifySignatureShare verifies a signature share. sigShare is the signer's signature share to be verified.
//
// The CommitmentList must be sorted in ascending order by identifier.
func (c *Configuration) VerifySignatureShare(
	sigShare *SignatureShare,
	message []byte,
	commitments CommitmentList,
) error {
	if !c.verified || !c.keysVerified {
		if err := c.Init(); err != nil {
			return err
		}
	}

	groupCommitment, bindingFactors, participants, err := c.prepareSignatureShareVerification(message, commitments)
	if err != nil {
		return err
	}

	return c.verifySignatureShare(sigShare, message, commitments, participants, groupCommitment, bindingFactors)
}

func (c *Configuration) prepareSignatureShareVerification(message []byte,
	commitments CommitmentList,
) (*ecc.Element, BindingFactors, []*ecc.Scalar, error) {
	commitments.Sort()

	// Validate general consistency of the commitment list.
	if err := c.ValidateCommitmentList(commitments); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid list of commitments: %w", err)
	}

	groupCommitment, bindingFactors := commitments.groupCommitmentAndBindingFactors(c.GroupPublicKey, message)
	participants := commitments.ParticipantsScalar()

	return groupCommitment, bindingFactors, participants, nil
}

func (c *Configuration) validateSignatureShareLight(sigShare *SignatureShare) error {
	if sigShare == nil {
		return errors.New("nil signature share")
	}

	if sigShare.SignatureShare == nil || sigShare.SignatureShare.IsZero() {
		return errors.New("invalid signature share (nil or zero scalar)")
	}

	return nil
}

func (c *Configuration) validateSignatureShareExtensive(sigShare *SignatureShare) error {
	if err := c.validateSignatureShareLight(sigShare); err != nil {
		return err
	}

	if err := c.validateIdentifier(sigShare.SignerIdentifier); err != nil {
		return fmt.Errorf("invalid identifier for signer in signature share, the %w", err)
	}

	if sigShare.Group != c.group {
		return fmt.Errorf("signature share has invalid group parameter, want %s got %d", c.group, sigShare.Group)
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
	participants []*ecc.Scalar,
	groupCommitment *ecc.Element,
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
	lambda := internal.ComputeLambda(c.group, sigShare.SignerIdentifier, participants)
	lambdaChall := c.challenge(lambda, message, groupCommitment)

	// Commitment KeyShare: r = g(h + b*f + l*s)
	bindingFactor := bindingFactors[sigShare.SignerIdentifier]
	commShare := com.HidingNonceCommitment.Copy().Add(com.BindingNonceCommitment.Copy().Multiply(bindingFactor))
	r := commShare.Add(pk.Copy().Multiply(lambdaChall))
	l := c.group.Base().Multiply(sigShare.SignatureShare)

	if !l.Equal(r) {
		return fmt.Errorf("invalid signature share for signer %d", sigShare.SignerIdentifier)
	}

	return nil
}
