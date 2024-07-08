package frost_test

import (
	"fmt"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
	"testing"
)

func dkgMakeParticipants(t *testing.T, ciphersuite dkg.Ciphersuite, maxSigners, threshold int) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, maxSigners)
	for i := range uint64(maxSigners) {
		p, err := ciphersuite.NewParticipant(i+1, uint(maxSigners), uint(threshold))
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func simulateDKG(t *testing.T, g group.Group, maxSigners, threshold int) ([]*frost.KeyShare, *group.Element) {
	c := dkg.Ciphersuite(g)

	// valid r1DataSet set with and without own package
	participants := dkgMakeParticipants(t, c, maxSigners, threshold)
	r1 := make([]*dkg.Round1Data, maxSigners)

	// Step 1: Start and assemble packages.
	for i := range maxSigners {
		r1[i] = participants[i].Start()
	}

	pubKey, err := dkg.GroupPublicKey(c, r1)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Continue and assemble + triage packages.
	r2 := make(map[uint64][]*dkg.Round2Data, maxSigners)
	for i := range maxSigners {
		r, err := participants[i].Continue(r1)
		if err != nil {
			t.Fatal(err)
		}

		for id, data := range r {
			if r2[id] == nil {
				r2[id] = make([]*dkg.Round2Data, 0, maxSigners-1)
			}
			r2[id] = append(r2[id], data)
		}
	}

	// Step 3: Clean the proofs.
	// This must be called by each participant on their copy of the r1DataSet.
	for _, d := range r1 {
		d.ProofOfKnowledge.Clear()
	}

	// Step 4: Finalize and test outputs.
	keyShares := make([]*frost.KeyShare, 0, maxSigners)

	for _, p := range participants {
		keyShare, gpk, err := p.Finalize(r1, r2[p.Identifier])
		if err != nil {
			t.Fatal()
		}

		if gpk.Equal(pubKey) != 1 {
			t.Fatalf("expected same public key")
		}

		if keyShare.PublicKey.Equal(g.Base().Multiply(keyShare.SecretKey)) != 1 {
			t.Fatal("expected equality")
		}

		if err := dkg.VerifyPublicKey(c, p.Identifier, keyShare.PublicKey, r1); err != nil {
			t.Fatal(err)
		}

		keyShares = append(keyShares, &frost.KeyShare{
			ID:        keyShare.Identifier,
			Secret:    keyShare.SecretKey,
			PublicKey: keyShare.PublicKey,
		})
	}

	{
		groupSecretKey, err := frost.Ciphersuite(g).Configuration(pubKey).RecoverGroupSecret(keyShares)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(groupSecretKey.Hex())
	}

	return keyShares, pubKey
}
