// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package frost

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/frost/internal"
)

const (
	encConf            = byte(1)
	encSigner          = byte(2)
	encSigShare        = byte(3)
	encSig             = byte(4)
	encPubKeyShare     = byte(5)
	encNonceCommitment = byte(6)
	encLambda          = byte(7)
)

var (
	errInvalidConfigEncoding = errors.New(
		"the threshold in the encoded configuration is higher than the number of maximum participants",
	)
	errZeroIdentifier = errors.New("identifier cannot be 0")
)

func encodedLength(encID byte, g group.Group, other ...uint64) uint64 {
	eLen := uint64(g.ElementLength())
	sLen := uint64(g.ScalarLength())

	switch encID {
	case encConf:
		return 1 + 3*8 + eLen + other[0]
	case encSigner:
		return other[0] + 2 + 2 + 2 + other[1] + other[2] + other[3]
	case encSigShare:
		return 1 + 8 + uint64(g.ScalarLength())
	case encSig:
		return eLen + uint64(g.ScalarLength())
	case encPubKeyShare:
		return 1 + 8 + 4 + eLen + other[0]
	case encNonceCommitment:
		return 8 + 2*sLen + EncodedSize(g)
	case encLambda:
		return 32 + sLen
	default:
		panic("encoded id not recognized")
	}
}

// Encode serializes the Configuration into a compact byte slice.
func (c *Configuration) Encode() []byte {
	g := group.Group(c.Ciphersuite)
	pksLen := encodedLength(encPubKeyShare, g, c.Threshold*uint64(g.ElementLength()))
	size := encodedLength(encConf, g, uint64(len(c.SignerPublicKeys))*pksLen)
	out := make([]byte, 25, size)
	out[0] = byte(g)
	binary.LittleEndian.PutUint64(out[1:9], c.Threshold)
	binary.LittleEndian.PutUint64(out[9:17], c.MaxSigners)
	binary.LittleEndian.PutUint64(out[17:25], uint64(len(c.SignerPublicKeys)))

	out = append(out, c.GroupPublicKey.Encode()...)

	for _, pk := range c.SignerPublicKeys {
		out = append(out, pk.Encode()...)
	}

	return out
}

type confHeader struct {
	g                     group.Group
	h, t, n, nPks, length uint64
}

func (c *Configuration) decodeHeader(data []byte) (*confHeader, error) {
	if len(data) <= 25 {
		return nil, internal.ErrInvalidLength
	}

	cs := Ciphersuite(data[0])
	if !cs.Available() {
		return nil, internal.ErrInvalidCiphersuite
	}

	g := group.Group(data[0])
	t := binary.LittleEndian.Uint64(data[1:9])
	n := binary.LittleEndian.Uint64(data[9:17])
	nPks := binary.LittleEndian.Uint64(data[17:25])
	pksLen := encodedLength(encPubKeyShare, g, t*uint64(g.ElementLength()))
	length := encodedLength(encConf, g, nPks*pksLen)

	if t > n {
		return nil, errInvalidConfigEncoding
	}

	return &confHeader{
		g:      g,
		h:      25,
		t:      t,
		n:      n,
		nPks:   nPks,
		length: length,
	}, nil
}

func (c *Configuration) decode(header *confHeader, data []byte) error {
	if uint64(len(data)) != header.length {
		return internal.ErrInvalidLength
	}

	gpk := header.g.NewElement()
	if err := gpk.Decode(data[header.h : header.h+uint64(header.g.ElementLength())]); err != nil {
		return fmt.Errorf("could not decode group public key: %w", err)
	}

	offset := header.h + uint64(header.g.ElementLength())
	pksLen := encodedLength(encPubKeyShare, header.g, header.t*uint64(header.g.ElementLength()))
	pks := make([]*PublicKeyShare, header.nPks)

	for j := range header.nPks {
		pk := new(PublicKeyShare)
		if err := pk.Decode(data[offset : offset+pksLen]); err != nil {
			return fmt.Errorf("could not decode signer public key share for signer %d: %w", j, err)
		}

		offset += pksLen
		pks[j] = pk
	}

	conf := &Configuration{
		Ciphersuite:      Ciphersuite(header.g),
		Threshold:        header.t,
		MaxSigners:       header.n,
		GroupPublicKey:   gpk,
		SignerPublicKeys: pks,
	}

	if err := conf.verify(); err != nil {
		return err
	}

	c.Ciphersuite = conf.Ciphersuite
	c.Threshold = conf.Threshold
	c.MaxSigners = conf.MaxSigners
	c.GroupPublicKey = gpk
	c.SignerPublicKeys = pks
	c.group = group.Group(conf.Ciphersuite)
	c.verified = true

	return nil
}

// Decode deserializes the input data into the Configuration, or returns an error.
func (c *Configuration) Decode(data []byte) error {
	header, err := c.decodeHeader(data)
	if err != nil {
		return err
	}

	return c.decode(header, data)
}

// Encode serializes the client with its long term values, containing its secret share. This is useful for saving state
// and backup.
func (s *Signer) Encode() []byte {
	g := s.KeyShare.Group
	ks := s.KeyShare.Encode()
	nCommitments := len(s.NonceCommitments)
	nLambdas := len(s.LambdaRegistry)
	conf := s.Configuration.Encode()
	outLength := encodedLength(
		encSigner,
		g,
		uint64(len(conf)),
		uint64(len(ks)),
		uint64(nCommitments)*encodedLength(encNonceCommitment, g),
		uint64(nLambdas)*encodedLength(encLambda, g),
	)
	out := make([]byte, len(conf)+6, outLength)

	copy(out, conf)
	binary.LittleEndian.PutUint16(out[len(conf):len(conf)+2], uint16(len(ks)))        // key share length
	binary.LittleEndian.PutUint16(out[len(conf)+2:len(conf)+4], uint16(nCommitments)) // number of commitments
	binary.LittleEndian.PutUint16(out[len(conf)+4:len(conf)+6], uint16(nLambdas))     // number of lambda entries

	out = append(out, ks...) // key share

	for k, v := range s.LambdaRegistry {
		b, err := hex.DecodeString(k)
		if err != nil {
			panic(fmt.Sprintf("failed te revert hex encoding to bytes of %s", k))
		}

		out = append(out, b...)
		out = append(out, v.Encode()...)
	}

	for id, com := range s.NonceCommitments {
		out = append(out, internal.Concatenate(internal.UInt64LE(id),
			com.HidingNonce.Encode(),
			com.BindingNonce.Encode(),
			com.Commitment.Encode())...)
	}

	return out
}

// Decode attempts to deserialize the encoded backup data into the Signer.
func (s *Signer) Decode(data []byte) error {
	conf := new(Configuration)

	header, err := conf.decodeHeader(data)
	if err != nil {
		return err
	}

	if err = conf.decode(header, data[:header.length]); err != nil {
		return err
	}

	if uint64(len(data)) <= header.length+6 {
		return internal.ErrInvalidLength
	}

	ksLen := uint64(binary.LittleEndian.Uint16(data[header.length : header.length+2]))
	nCommitments := uint64(binary.LittleEndian.Uint16(data[header.length+2 : header.length+4]))
	nLambdas := uint64(binary.LittleEndian.Uint16(data[header.length+4 : header.length+6]))
	g := conf.group
	nLen := encodedLength(encNonceCommitment, g)
	lLem := encodedLength(encLambda, g)

	length := encodedLength(encSigner, g, header.length, ksLen, nCommitments*nLen, nLambdas*lLem)
	if uint64(len(data)) != length {
		return internal.ErrInvalidLength
	}

	offset := header.length + 6

	keyShare := new(KeyShare)
	if err := keyShare.Decode(data[offset : offset+ksLen]); err != nil {
		return fmt.Errorf("failed to decode key share: %w", err)
	}

	offset += ksLen
	stop := offset + nLambdas*lLem
	lambdaRegistry := make(internal.LambdaRegistry, lLem)

	for offset < stop {
		key := data[offset : offset+32]
		offset += 32

		lambda := g.NewScalar()
		if err := lambda.Decode(data[offset : offset+uint64(g.ScalarLength())]); err != nil {
			return fmt.Errorf("failed to decode lambda: %w", err)
		}

		lambdaRegistry[hex.EncodeToString(key)] = lambda
		offset += uint64(g.ScalarLength())
	}

	commitments := make(map[uint64]*Nonce)
	comLen := EncodedSize(g)

	for offset < uint64(len(data)) {
		id := binary.LittleEndian.Uint64(data[offset : offset+8])

		if _, exists := commitments[id]; exists {
			return fmt.Errorf("multiple encoded commitments with the same id: %d", id)
		}

		offset += 8

		hs := g.NewScalar()
		if err = hs.Decode(data[offset : offset+uint64(g.ScalarLength())]); err != nil {
			return fmt.Errorf("can't decode hiding nonce for commitment %d: %w", id, err)
		}

		offset += uint64(g.ScalarLength())

		bs := g.NewScalar()
		if err = bs.Decode(data[offset : offset+uint64(g.ScalarLength())]); err != nil {
			return fmt.Errorf("can't decode binding nonce for commitment %d: %w", id, err)
		}

		offset += uint64(g.ScalarLength())

		com := new(Commitment)
		if err = com.Decode(data[offset : offset+comLen]); err != nil {
			return fmt.Errorf("can't decode nonce commitment %d: %w", id, err)
		}

		offset += comLen

		commitments[id] = &Nonce{
			HidingNonce:  hs,
			BindingNonce: bs,
			Commitment:   com,
		}
	}

	s.KeyShare = keyShare
	s.LambdaRegistry = lambdaRegistry
	s.NonceCommitments = commitments
	s.Configuration = conf

	return nil
}

// Encode returns a compact byte encoding of the signature share.
func (s *SignatureShare) Encode() []byte {
	share := s.SignatureShare.Encode()

	out := make([]byte, encodedLength(encSigShare, s.Group))
	out[0] = byte(s.Group)
	binary.LittleEndian.PutUint64(out[1:9], s.SignerIdentifier)
	copy(out[9:], share)

	return out
}

// Decode takes a byte string and attempts to decode it to return the signature share.
func (s *SignatureShare) Decode(data []byte) error {
	if len(data) < 1 {
		return internal.ErrInvalidLength
	}

	c := Ciphersuite(data[0])

	g := c.ECGroup()
	if g == 0 {
		return internal.ErrInvalidCiphersuite
	}

	if uint64(len(data)) != encodedLength(encSigShare, g) {
		return internal.ErrInvalidLength
	}

	id := binary.LittleEndian.Uint64(data[1:9])
	if id == 0 {
		return errZeroIdentifier
	}

	share := g.NewScalar()
	if err := share.Decode(data[9:]); err != nil {
		return fmt.Errorf("failed to decode signature share: %w", err)
	}

	s.Group = g
	s.SignerIdentifier = id
	s.SignatureShare = share

	return nil
}

// Encode serializes the signature into a byte string.
func (s *Signature) Encode() []byte {
	r := s.R.Encode()
	z := s.Z.Encode()
	r = slices.Grow(r, len(z))

	return append(r, z...)
}

// Decode attempts to deserialize the encoded input into the signature in the group.
func (s *Signature) Decode(c Ciphersuite, data []byte) error {
	g := c.ECGroup()
	if g == 0 {
		return internal.ErrInvalidCiphersuite
	}

	eLen := g.ElementLength()

	if uint64(len(data)) != encodedLength(encSig, g) {
		return internal.ErrInvalidLength
	}

	s.R = g.NewElement()
	if err := s.R.Decode(data[:eLen]); err != nil {
		return fmt.Errorf("invalid signature - decoding R: %w", err)
	}

	s.Z = g.NewScalar()
	if err := s.Z.Decode(data[eLen:]); err != nil {
		return fmt.Errorf("invalid signature - decoding Z: %w", err)
	}

	return nil
}
