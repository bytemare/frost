package frost

import (
	"encoding/binary"
	"fmt"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

func noncesEncodedLength(g group.Group, n map[uint64][2]*group.Scalar) int {
	nbNonces := len(n)
	return nbNonces + nbNonces*2*g.ScalarLength()
}

// Backup serializes the client with its long term values, containing its secret share.
func (p *Participant) Backup() []byte {
	g := p.KeyShare.Group
	ks := p.KeyShare.Encode()
	nLen := noncesEncodedLength(g, p.Nonces)
	out := make([]byte, 1, 1+2+2+g.ScalarLength()+len(ks)+nLen)
	out[0] = byte(g)
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(ks)))
	binary.LittleEndian.PutUint16(out[3:5], uint16(len(p.Nonces)))
	out = append(out, ks...)
	for id, nonces := range p.Nonces {
		out = append(out, internal.Concatenate(internal.UInt64LE(id), nonces[0].Encode(), nonces[1].Encode())...)
	}

	return out
}

// Recover attempts to deserialize the encoded backup data into a Participant.
func (p *Participant) Recover(data []byte) error {
	if len(data) < 5 {
		return internal.ErrInvalidLength
	}

	g := group.Group(data[0])
	if !Ciphersuite(g).Available() {
		return internal.ErrInvalidCiphersuite
	}

	ksLen := int(binary.LittleEndian.Uint16(data[1:3]))
	nN := int(binary.LittleEndian.Uint16(data[3:5]))
	nLen := nN + nN*2*g.ScalarLength()

	if len(data) != 1+2+2+g.ScalarLength()+ksLen+nLen {
		return internal.ErrInvalidLength
	}

	lambda := g.NewScalar()
	if err := lambda.Decode(data[5 : 5+g.ScalarLength()]); err != nil {
		return fmt.Errorf("failed to decode key share: %w", err)
	}

	keyShare := new(KeyShare)
	if err := keyShare.Decode(data[5+g.ScalarLength() : 5+g.ScalarLength()+ksLen]); err != nil {
		return fmt.Errorf("failed to decode key share: %w", err)
	}

	step := 8 + 2*g.ScalarLength()

	nonces := make(map[uint64][2]*group.Scalar)
	for i := 5 + g.ScalarLength() + ksLen; i < len(data); i += step {
		id := binary.LittleEndian.Uint64(data[i : i+8])

		n0 := g.NewScalar()
		if err := n0.Decode(data[i+8 : i+8+g.ScalarLength()]); err != nil {
			return err
		}

		n1 := g.NewScalar()
		if err := n1.Decode(data[i+8 : i+8+g.ScalarLength()]); err != nil {
			return err
		}

		nonces[id] = [2]*group.Scalar{n0, n1}
	}

	p.KeyShare = keyShare
	p.Lambda = lambda
	p.Nonces = nonces
	p.Configuration = *Ciphersuite(g).Configuration()

	return nil
}

// Encode returns a compact byte encoding of the signature share.
func (s SignatureShare) Encode() []byte {
	share := s.SignatureShare.Encode()

	out := make([]byte, 8+len(share))
	copy(out, internal.UInt64LE(s.Identifier))
	copy(out[8:], share)

	return out
}

// DecodeSignatureShare takes a byte string and attempts to decode it to return the signature share.
func (c Configuration) DecodeSignatureShare(data []byte) (*SignatureShare, error) {
	g := c.Ciphersuite.Group

	if len(data) != 8+g.ScalarLength() {
		return nil, errDecodeSignatureShare
	}

	s := &SignatureShare{
		Identifier:     internal.UInt64FromLE(data[:8]),
		SignatureShare: g.NewScalar(),
	}

	if err := s.SignatureShare.Decode(data[8:]); err != nil {
		return nil, fmt.Errorf("failed to decode signature share: %w", err)
	}

	return s, nil
}
