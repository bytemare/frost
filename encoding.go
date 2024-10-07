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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/encoding"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/frost/internal"
)

const (
	encConf byte = iota + 1
	encSigner
	encSigShare
	encSig
	encPubKeyShare
	encNonceCommitment
	encLambda
	encCommitment

	errFmt = "%w: %w"
)

var (
	errInvalidConfigEncoding = errors.New(
		"the threshold in the encoded configuration is higher than the number of maximum participants",
	)
	errZeroIdentifier = errors.New("identifier cannot be 0")

	errDecodeConfigurationPrefix  = errors.New("failed to decode Configuration")
	errDecodeSignerPrefix         = errors.New("failed to decode Signer")
	errDecodeCommitmentPrefix     = errors.New("failed to decode Commitment")
	errDecodeSignatureSharePrefix = errors.New("failed to decode SignatureShare")
	errDecodeSignaturePrefix      = errors.New("failed to decode Signature")
	errDecodeCommitmentListPrefix = errors.New("failed to decode CommitmentList")

	errDecodeProofR = errors.New("invalid encoding of R proof")
	errDecodeProofZ = errors.New("invalid encoding of z proof")
)

func encodedLength(encID byte, g ecc.Group, other ...int) (int, int) {
	eLen := g.ElementLength()
	sLen := g.ScalarLength()
	var header, tail int

	switch encID {
	case encConf:
		header = 1 + 3*2       // group, threshold, max, n signer public key shares
		tail = eLen + other[0] // verification key, signer public key shares
	case encSigner:
		_ = other[3]                          // #nosec G602 -- false positive
		header = other[0] + 6                 // conf length, length key share, n commitments, n lambdas
		tail = other[1] + other[2] + other[3] // #nosec G602 -- key share, lambdas, nonce commitments
	case encSigShare:
		header = 1 + 2 // group, signer id
		tail = sLen    // signature share
	case encSig:
		header = 1
		tail = eLen + sLen // R, z
	case encPubKeyShare:
		header = 1 + 2 + 4     // group, signer id, length VSS commitment
		tail = eLen + other[0] // public key, vss commitment
	case encNonceCommitment:
		header = 8 // commitment id
		_, com := encodedLength(encCommitment, g)
		tail = 2*sLen + com // nonces, commitment
	case encLambda:
		header = 0
		tail = 32 + sLen // SHA256 hash of identifier key, lambda
	case encCommitment:
		header = 1 + 8 + 2 // group, commitment ID, signer id
		tail = 2 * eLen    // nonce commitments
	default:
		panic("encoded id not recognized")
	}

	return header, header + tail
}

// Encode serializes the Configuration into a compact byte slice.
func (c *Configuration) Encode() []byte {
	g := ecc.Group(c.Ciphersuite)
	_, pksLen := encodedLength(encPubKeyShare, g, int(c.Threshold)*g.ElementLength())
	header, size := encodedLength(encConf, g, len(c.SignerPublicKeyShares)*pksLen)
	out := make([]byte, header, size)
	out[0] = byte(g)
	binary.LittleEndian.PutUint16(out[1:3], c.Threshold)
	binary.LittleEndian.PutUint16(out[3:5], c.MaxSigners)
	binary.LittleEndian.PutUint16(out[5:7], uint16(len(c.SignerPublicKeyShares)))

	out = append(out, c.GroupPublicKey.Encode()...)

	for _, pk := range c.SignerPublicKeyShares {
		out = append(out, pk.Encode()...)
	}

	return out
}

type confHeader struct {
	g                             ecc.Group
	h, t, n, pksLen, nPks, length int
}

func (c *Configuration) decodeHeader(data []byte) (*confHeader, error) {
	if len(data) <= 7 {
		return nil, fmt.Errorf(errFmt, errDecodeConfigurationPrefix, internal.ErrInvalidLength)
	}

	cs := Ciphersuite(data[0])
	if !cs.Available() {
		return nil, fmt.Errorf(errFmt, errDecodeConfigurationPrefix, internal.ErrInvalidCiphersuite)
	}

	g := ecc.Group(data[0])
	t := int(binary.LittleEndian.Uint16(data[1:3]))
	n := int(binary.LittleEndian.Uint16(data[3:5]))
	nPks := int(binary.LittleEndian.Uint16(data[5:7]))
	_, pksLen := encodedLength(encPubKeyShare, g, t*g.ElementLength())
	_, length := encodedLength(encConf, g, nPks*pksLen)

	if t == 0 || t > n {
		return nil, fmt.Errorf(errFmt, errDecodeConfigurationPrefix, errInvalidConfigEncoding)
	}

	return &confHeader{
		g:      g,
		h:      7,
		t:      t,
		n:      n,
		pksLen: pksLen,
		nPks:   nPks,
		length: length,
	}, nil
}

func (c *Configuration) decode(header *confHeader, data []byte) error {
	if len(data) != header.length {
		return internal.ErrInvalidLength
	}

	gpk := header.g.NewElement()
	if err := gpk.Decode(data[header.h : header.h+header.g.ElementLength()]); err != nil {
		return fmt.Errorf("%w: could not decode group public key: %w", errDecodeConfigurationPrefix, err)
	}

	offset := header.h + header.g.ElementLength()
	pks := make([]*keys.PublicKeyShare, header.nPks)

	conf := &Configuration{
		Ciphersuite:           Ciphersuite(header.g),
		Threshold:             uint16(header.t),
		MaxSigners:            uint16(header.n),
		GroupPublicKey:        gpk,
		SignerPublicKeyShares: pks,
		group:                 header.g,
		verified:              false,
		keysVerified:          false,
	}

	if err := conf.verifyConfiguration(); err != nil {
		return fmt.Errorf(errFmt, errDecodeConfigurationPrefix, err)
	}

	for j := range header.nPks {
		pk := new(keys.PublicKeyShare)
		if err := pk.Decode(data[offset : offset+header.pksLen]); err != nil {
			return fmt.Errorf(
				"%w: could not decode signer public key share for signer %d: %w",
				errDecodeConfigurationPrefix,
				j,
				err,
			)
		}

		offset += header.pksLen
		pks[j] = pk
	}

	if err := conf.verifySignerPublicKeyShares(); err != nil {
		return fmt.Errorf(errFmt, errDecodeConfigurationPrefix, err)
	}

	c.Ciphersuite = conf.Ciphersuite
	c.Threshold = conf.Threshold
	c.MaxSigners = conf.MaxSigners
	c.GroupPublicKey = gpk
	c.SignerPublicKeyShares = pks
	c.group = ecc.Group(conf.Ciphersuite)
	c.verified = true
	c.keysVerified = true

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

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (c *Configuration) Hex() string {
	return hex.EncodeToString(c.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (c *Configuration) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeConfigurationPrefix, err)
	}

	return c.Decode(b)
}

// UnmarshalJSON decodes data into c, or returns an error.
func (c *Configuration) UnmarshalJSON(data []byte) error {
	shadow := new(configurationShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeConfigurationPrefix, err)
	}

	c2 := (*Configuration)(shadow)
	if err := c2.Init(); err != nil {
		return fmt.Errorf(errFmt, errDecodeConfigurationPrefix, err)
	}

	*c = *c2

	return nil
}

// Encode serializes the client with its long term values, containing its secret share. This is useful for saving state
// and backup.
func (s *Signer) Encode() []byte {
	g := s.KeyShare.Group()
	keyShare := s.KeyShare.Encode()
	nCommitments := len(s.NonceCommitments)
	nLambdas := len(s.LambdaRegistry)
	conf := s.Configuration.Encode()
	_, lambdaLength := encodedLength(encLambda, g)
	_, ncLength := encodedLength(encNonceCommitment, g)
	header, size := encodedLength(
		encSigner,
		g,
		len(conf),
		len(keyShare),
		nLambdas*lambdaLength,
		nCommitments*ncLength,
	)
	out := make([]byte, header, size)

	copy(out, conf)
	binary.LittleEndian.PutUint16(out[len(conf):len(conf)+2], uint16(len(keyShare)))  // key share length
	binary.LittleEndian.PutUint16(out[len(conf)+2:len(conf)+4], uint16(nCommitments)) // number of commitments
	binary.LittleEndian.PutUint16(out[len(conf)+4:len(conf)+6], uint16(nLambdas))     // number of lambda entries

	out = append(out, keyShare...)

	for k, v := range s.LambdaRegistry {
		b, err := hex.DecodeString(k)
		if err != nil {
			panic("failed te revert hex encoding to bytes of " + k)
		}

		out = append(out, b...)
		out = append(out, v.Value.Encode()...)
	}

	for id, com := range s.NonceCommitments {
		out = append(out, internal.Concatenate(internal.UInt64LE(id),
			com.HidingNonce.Encode(),
			com.BindingNonce.Encode(),
			com.Commitment.Encode())...)
	}

	return out
}

func (n *Nonce) decode(g ecc.Group, id uint64, comLen int, data []byte) error {
	sLen := g.ScalarLength()
	offset := g.ScalarLength()

	hn := g.NewScalar()
	if err := hn.Decode(data[:offset]); err != nil {
		return fmt.Errorf("can't decode hiding nonce for commitment %d: %w", id, err)
	}

	bn := g.NewScalar()
	if err := bn.Decode(data[offset : offset+sLen]); err != nil {
		return fmt.Errorf("can't decode binding nonce for commitment %d: %w", id, err)
	}

	offset += sLen

	com := new(Commitment)
	if err := com.Decode(data[offset : offset+comLen]); err != nil {
		return fmt.Errorf("can't decode nonce commitment %d: %w", id, err)
	}

	n.HidingNonce = hn
	n.BindingNonce = bn
	n.Commitment = com

	return nil
}

func (n *Nonce) populate(ns *nonceShadow) {
	n.HidingNonce = ns.HidingNonce
	n.BindingNonce = ns.BindingNonce
	n.Commitment = (*Commitment)(ns.commitmentShadow)
}

// UnmarshalJSON decodes data into n, or returns an error.
func (n *Nonce) UnmarshalJSON(data []byte) error {
	shadow := new(nonceShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, err)
	}

	n.populate(shadow)

	return nil
}

// Decode attempts to deserialize the encoded backup data into the Signer.
func (s *Signer) Decode(data []byte) error {
	conf := new(Configuration)

	header, err := conf.decodeHeader(data)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
	}

	if err = conf.decode(header, data[:header.length]); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
	}

	if len(data) <= header.length+6 {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, errInvalidLength)
	}

	ksLen := int(binary.LittleEndian.Uint16(data[header.length : header.length+2]))
	nCommitments := int(binary.LittleEndian.Uint16(data[header.length+2 : header.length+4]))
	nLambdas := int(binary.LittleEndian.Uint16(data[header.length+4 : header.length+6]))
	g := conf.group
	_, nLen := encodedLength(encNonceCommitment, g)
	_, lLem := encodedLength(encLambda, g)

	_, length := encodedLength(encSigner, g, header.length, ksLen, nCommitments*nLen, nLambdas*lLem)
	if len(data) != length {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, errInvalidLength)
	}

	offset := header.length + 6

	keyShare := new(keys.KeyShare)
	if err = keyShare.Decode(data[offset : offset+ksLen]); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
	}

	if err = conf.ValidateKeyShare(keyShare); err != nil {
		return fmt.Errorf("%w: invalid key share: %w", errDecodeSignerPrefix, err)
	}

	offset += ksLen
	stop := offset + nLambdas*lLem

	lambdaRegistry := make(internal.LambdaRegistry, lLem)
	if err = lambdaRegistry.Decode(g, data[offset:stop]); err != nil {
		return fmt.Errorf("%w: failed to decode lambda registry in signer: %w", errDecodeSignerPrefix, err)
	}

	offset = stop
	commitments := make(map[uint64]*Nonce)
	_, comLen := encodedLength(encCommitment, g)
	_, nComLen := encodedLength(encNonceCommitment, g)

	for offset < len(data) {
		// commitment ID
		id := binary.LittleEndian.Uint64(data[offset : offset+8])

		if _, exists := commitments[id]; exists {
			return fmt.Errorf("%w: multiple encoded commitments with the same id: %d", errDecodeSignerPrefix, id)
		}

		n := new(Nonce)
		if err = n.decode(g, id, comLen, data[offset+8:]); err != nil {
			return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
		}

		commitments[id] = n
		offset += nComLen
	}

	s.KeyShare = keyShare
	s.LambdaRegistry = lambdaRegistry
	s.NonceCommitments = commitments
	s.Configuration = conf

	return nil
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (s *Signer) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (s *Signer) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
	}

	return s.Decode(b)
}

// UnmarshalJSON decodes data into s, or returns an error.
func (s *Signer) UnmarshalJSON(data []byte) error {
	shadow := new(signerShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignerPrefix, err)
	}

	*s = Signer(*shadow)

	return nil
}

// Encode returns the serialized byte encoding of a participant's commitment.
func (c *Commitment) Encode() []byte {
	hNonce := c.HidingNonceCommitment.Encode()
	bNonce := c.BindingNonceCommitment.Encode()

	header, size := encodedLength(encCommitment, c.Group)
	out := make([]byte, header, size)
	out[0] = byte(c.Group)
	binary.LittleEndian.PutUint64(out[1:9], c.CommitmentID)
	binary.LittleEndian.PutUint16(out[9:11], c.SignerID)
	out = append(out, hNonce...)
	out = append(out, bNonce...)

	return out
}

// Decode attempts to deserialize the encoded commitment given as input, and to return it.
func (c *Commitment) Decode(data []byte) error {
	if len(data) < 11 {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, errInvalidLength)
	}

	g := ecc.Group(data[0])
	if !g.Available() {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, errInvalidCiphersuite)
	}

	_, size := encodedLength(encCommitment, g)
	if len(data) != size {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, errInvalidLength)
	}

	cID := binary.LittleEndian.Uint64(data[1:9])

	pID := binary.LittleEndian.Uint16(data[9:11])
	if pID == 0 {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, errZeroIdentifier)
	}

	offset := 11

	hn := g.NewElement()
	if err := hn.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("%w: invalid encoding of hiding nonce commitment: %w", errDecodeCommitmentPrefix, err)
	}

	offset += g.ElementLength()

	bn := g.NewElement()
	if err := bn.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return fmt.Errorf("%w: invalid encoding of binding nonce commitment: %w", errDecodeCommitmentPrefix, err)
	}

	c.Group = g
	c.CommitmentID = cID
	c.SignerID = pID
	c.HidingNonceCommitment = hn
	c.BindingNonceCommitment = bn

	return nil
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (c *Commitment) Hex() string {
	return hex.EncodeToString(c.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (c *Commitment) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, err)
	}

	return c.Decode(b)
}

// UnmarshalJSON decodes data into c, or returns an error.
func (c *Commitment) UnmarshalJSON(data []byte) error {
	shadow := new(commitmentShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeCommitmentPrefix, err)
	}

	*c = Commitment(*shadow)

	return nil
}

// Encode returns a compact byte encoding of the signature share.
func (s *SignatureShare) Encode() []byte {
	share := s.SignatureShare.Encode()

	_, size := encodedLength(encSigShare, s.Group)
	out := make([]byte, size)
	out[0] = byte(s.Group)
	binary.LittleEndian.PutUint16(out[1:3], s.SignerIdentifier)
	copy(out[3:], share)

	return out
}

// Decode takes a byte string and attempts to decode it to return the signature share.
func (s *SignatureShare) Decode(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, errInvalidLength)
	}

	c := Ciphersuite(data[0])

	g := c.Group()
	if g == 0 {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, errInvalidCiphersuite)
	}

	_, size := encodedLength(encSigShare, g)
	if len(data) != size {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, errInvalidLength)
	}

	id := binary.LittleEndian.Uint16(data[1:3])
	if id == 0 {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, errZeroIdentifier)
	}

	share := g.NewScalar()
	if err := share.Decode(data[3:]); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, err)
	}

	s.Group = g
	s.SignerIdentifier = id
	s.SignatureShare = share

	return nil
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (s *SignatureShare) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (s *SignatureShare) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, err)
	}

	return s.Decode(b)
}

// UnmarshalJSON decodes data into s, or returns an error.
func (s *SignatureShare) UnmarshalJSON(data []byte) error {
	shadow := new(signatureShareShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignatureSharePrefix, err)
	}

	*s = SignatureShare(*shadow)

	return nil
}

// Encode serializes the signature into a byte string.
func (s *Signature) Encode() []byte {
	h, l := encodedLength(encSig, s.Group)
	out := make([]byte, h, l)
	out[0] = byte(s.Group)
	out = append(out, s.R.Encode()...)
	out = append(out, s.Z.Encode()...)

	return out
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (s *Signature) Decode(data []byte) error {
	if len(data) <= 1 {
		return fmt.Errorf(errFmt, errDecodeSignaturePrefix, errInvalidLength)
	}

	if !Ciphersuite(data[0]).Available() {
		return fmt.Errorf(errFmt, errDecodeSignaturePrefix, errInvalidCiphersuite)
	}

	g := ecc.Group(data[0])
	_, expectedLength := encodedLength(encSig, g)

	if len(data) != expectedLength {
		return fmt.Errorf(errFmt, errDecodeSignaturePrefix, errInvalidLength)
	}

	r := g.NewElement()
	if err := r.Decode(data[1 : 1+g.ElementLength()]); err != nil {
		return fmt.Errorf("%w: %w: %w", errDecodeSignaturePrefix, errDecodeProofR, err)
	}

	z := g.NewScalar()
	if err := z.Decode(data[1+g.ElementLength():]); err != nil {
		return fmt.Errorf("%w: %w: %w", errDecodeSignaturePrefix, errDecodeProofZ, err)
	}

	s.Group = g
	s.R = r
	s.Z = z

	return nil
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (s *Signature) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (s *Signature) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errDecodeSignaturePrefix, err)
	}

	return s.Decode(b)
}

// UnmarshalJSON decodes data into s, or returns an error.
func (s *Signature) UnmarshalJSON(data []byte) error {
	shadow := new(signatureShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf(errFmt, errDecodeSignaturePrefix, err)
	}

	*s = Signature(*shadow)

	return nil
}

// decoding helpers

type shadowInit interface {
	init(g ecc.Group)
}

type configurationShadow Configuration

func (c *configurationShadow) init(g ecc.Group) {
	c.GroupPublicKey = g.NewElement()
}

type signerShadow Signer

func (s *signerShadow) init(g ecc.Group) {
	s.KeyShare = &keys.KeyShare{
		Secret:         g.NewScalar(),
		GroupPublicKey: g.NewElement(),
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey:     g.NewElement(),
			VssCommitment: nil,
			ID:            0,
			Group:         g,
		},
	}
	s.Configuration = &Configuration{
		GroupPublicKey:        g.NewElement(),
		SignerPublicKeyShares: nil,
		Threshold:             0,
		MaxSigners:            0,
		Ciphersuite:           0,
		group:                 0,
		verified:              false,
		keysVerified:          false,
	}
	s.NonceCommitments = make(map[uint64]*Nonce)
}

type nonceShadow struct {
	HidingNonce       *ecc.Scalar `json:"hidingNonce"`
	BindingNonce      *ecc.Scalar `json:"bindingNonce"`
	*commitmentShadow `json:"commitment"`
}

func (n *nonceShadow) init(g ecc.Group) {
	n.HidingNonce = g.NewScalar()
	n.BindingNonce = g.NewScalar()
	n.commitmentShadow = new(commitmentShadow)
	n.commitmentShadow.init(g)
}

type commitmentShadow Commitment

func (c *commitmentShadow) init(g ecc.Group) {
	c.HidingNonceCommitment = g.NewElement()
	c.BindingNonceCommitment = g.NewElement()
	c.Group = g
}

type signatureShareShadow SignatureShare

func (s *signatureShareShadow) init(g ecc.Group) {
	s.SignatureShare = g.NewScalar()
}

type signatureShadow Signature

func (s *signatureShadow) init(g ecc.Group) {
	s.R = g.NewElement()
	s.Z = g.NewScalar()
}

func unmarshalJSON(data []byte, target shadowInit) error {
	g, err := encoding.JSONReGetGroup(string(data))
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	target.init(g)

	if err = json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
