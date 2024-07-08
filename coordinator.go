// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

// AggregateSignatures allows the coordinator to produce the final signature given all signature shares.
//
// Before aggregation, each signature share must be a valid, deserialized element. If that validation fails the
// coordinator must abort the protocol, as the resulting signature will be invalid.
// The CommitmentList must be sorted in ascending order by identifier.
//
// The coordinator should verify this signature using the group public key before publishing or releasing the signature.
// This aggregate signature will verify if and only if all signature shares are valid. If an invalid share is identified
// a reasonable approach is to remove the participant from the set of allowed participants in future runs of FROST.
func (c Configuration) AggregateSignatures(msg []byte, sigShares []*SignatureShare, coms CommitmentList) *Signature {
	coms.Sort()

	// Compute binding factors
	bindingFactorList := c.computeBindingFactors(coms, c.GroupPublicKey.Encode(), msg)

	// Compute group commitment
	groupCommitment := c.computeGroupCommitment(coms, bindingFactorList)

	// Compute aggregate signature
	z := c.Ciphersuite.Group.NewScalar()
	for _, share := range sigShares {
		z.Add(share.SignatureShare)
	}

	return &Signature{
		R: groupCommitment,
		Z: z,
	}
}

// VerifySignatureShare verifies a signature share.
// commitment, pki, and sigShareI are, respectively, commitment, public key, and signature share of
// the participant whose share is to be verified.
//
// The CommitmentList must be sorted in ascending order by identifier.
func (c Configuration) VerifySignatureShare(com *Commitment,
	message []byte,
	sigShare *SignatureShare,
	commitments CommitmentList,
) bool {
	bindingFactor, _, lambdaChall, err := c.do(message, commitments, com.Identifier)
	if err != nil {
		panic(err)
	}

	if com.Identifier != sigShare.Identifier {
		panic(nil)
	}

	// Commitment KeyShare
	commShare := com.HidingNonce.Copy().Add(com.BindingNonce.Copy().Multiply(bindingFactor))

	// Compute relation values
	l := c.Ciphersuite.Group.Base().Multiply(sigShare.SignatureShare)
	r := commShare.Add(com.PublicKey.Multiply(lambdaChall))

	return l.Equal(r) == 1
}
