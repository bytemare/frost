# :snowflake: FROST

[![frost](https://github.com/bytemare/frost/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/frost/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/frost.svg)](https://pkg.go.dev/github.com/bytemare/frost)
[![codecov](https://codecov.io/gh/bytemare/frost/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/frost)

```
  import "github.com/bytemare/frost"
```

This package implements [RFC9591 - The FROST Flexible Round-Optimized Schnorr Threshold](https://datatracker.ietf.org/doc/rfc9591/) protocol.
FROST provides Two-Round Threshold Schnorr Signatures.

The Ristretto255, Edwards25519, Secp256k1, and NIST elliptic curve groups are fully supported.

The [FROST Distributed Key Generation](https://github.com/bytemare/dkg) protocol produces compatible keys, as described
in the [original work](https://eprint.iacr.org/2020/852.pdf).

### Requirements

- When communicating at protocol execution, network channels don't need to be confidential but *MUST* be authenticated. This
  package verifies a lot of things with regard to the correctness to the protocol, but it assumes that signers and coordinators
  really communicate with the relevant peer.
- Long-term fixed configuration values *MUST* be known to all participant signers and coordinators (i.e. the ciphersuite,
  threshold and maximum amount of signers, and the public key for signature verification)
- For every signing session, at least the public key shares of all other participants *MUST* be known to all participant
  signers and coordinators (which can be a subset t-among-n of the initial key generation setup)
- Data provided to these functions (especially when received over the network) *MUST* be deserialized using the corresponding
  decoding functions. If data deserialization/decoding fails for a signer, protocol execution must be aborted.
- Identifiers (for participants/signers) *MUST* be between 1 and n, which is the maximum amount of participants defined at key generation.

#### Supported Ciphersuites

| ID | Name                       | Backend                       |
|----|----------------------------|-------------------------------|
| 1  | Ristretto255 (recommended) | github.com/gtank/ristretto255 |
| 3  | P-256                      | filippo.io/nistec             |
| 4  | P-384                      | filippo.io/nistec             |
| 5  | P-521                      | filippo.io/nistec             |
| 6  | Edwards25519               | filippo.io/edwards25519       |
| 7  | Secp256k1                  | github.com/bytemare/secp256k1 |

The groups, scalars (secret keys and nonces), and group elements (public keys and commitments) are opaque objects that
expose all necessary cryptographic and serialization functions.
If you have existing cryptographic material in their canonical encodings, they can of course be imported.

## Usage

Usage examples and comments can be found in [examples_test.go](https://github.com/bytemare/frost/blob/main/examples_test.go).

### Key Generation

The [FROST Distributed Key Generation](https://github.com/bytemare/dkg) is recommended to produce key material for all
participants in the setup. This package also puts out KeyShares and PublicKeyShares ready to use with this FROST implementation.
It also ensures correct identifier generation compatible with FROST.

It is heavily recommended to use the same instances for distributed key generation and signing, as this will avoid that
the secret key material leaves that instance.

For testing and debugging _only_, the [debug package](https://github.com/bytemare/frost/debug) provides a centralised
key generation with a trusted dealer.

### Key Management

If the [DKG](https://github.com/bytemare/dkg) package was used to generate keys, signers can use the produced KeyShare
and must communicate their PublicKeyShare to the coordinator and other signers.

It is easy to encode and decode these key shares and public key shares for transmission and storage,
using the ```Encode()``` and ```Decode()``` methods (or hexadecimal or JSON marshalling).

#### Import existing identifiers and keys

Existing key material (e.g. identifiers, secret public, public keys) that has been generated otherwise (or transmitted or backed up)
and encoded in their canonical byte representation can be imported.

To create a ```KeyShare``` and ```PublicKeyShare``` from individually encoded secret and public keys, use the
```keys.NewKeyShare()``` and ```NewPublicKeyShare()``` functions, respectively.
If a ```KeyShare``` or ```PublicKeyShare``` have been encoded using their respective ```Encode()``` method, they can be
easily recovered using the corresponding ```Decode()``` method. 

More generally, to decode an element (or point) in the Ristretto255 group,
```go
import (
    "https://github.com/bytemare/ecc"
)

bytesPublicKey := []byte{1, 2, 3, ...}

g := ecc.Ristretto255Sha512

publicKey := g.NewElement()
if err := publicKey.Decode(bytesPublicKey); err != nil {
	return fmt.Errorf("can't decode public key: %w", err)
}
```

The same goes for secret keys (or scalars),
```go
import (
    "https://github.com/bytemare/ecc"
)

bytesSecretKey := []byte{1, 2, 3, ...}

g := ecc.Ristretto255Sha512

secretKey := g.NewScalar()
if err := secretKey.Decode(bytesSecretKey); err != nil {
	return fmt.Errorf("can't decode secret key: %w", err)
}
```

and any other byte or json encoded structure.

### Setup

Both signers and coordinators must first instantiate a ```Configuration``` with the long-term fixed values as used at 
key generation:
- the ciphersuite (see the frost.Ciphersuite values for available ciphersuites)
- threshold (t) and maximum amount of signers (n)
- the global public key for signature verification (as put out at key generation)

Then add the PublicKeyShares of the participants (or signers). For simplicity, it is recommended to add all PublicKeyShares
of the all participants from the key generation step. It is sufficient, though, to only use the shares for the signers that
will participate in a signing session (which can be a subset _t among n_).

```go
configuration := &frost.Configuration{
		Ciphersuite:           ciphersuite,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
        VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicKeyShares,
	}

if err := configuration.Init(); err != nil {
    return err
}
```

This configuration can be encoded for transmission and offline storage, and re-instantiated using its
```Encode()``` and ```Decode()``` methods. This avoids having to store the parameters separately.

#### Signers

Once the configuration is initialised, setting up a signer is straightforward, using the ```Signer()``` method
and providing the signer's ```KeyShare```.

### Protocol execution

FROST is a two round signing protocol, in which the first round can be asynchronously pre-computed, so that signing can
actually be done in one round when necessary.

#### First Round: Signer commitment
- Signers commit to internal nonces, by calling the ```commitment := signer.Commit()``` method, which returns one commitment
and stores corresponding nonces internally. In this manner, signers can produce many commitments before signing sessions start.
Note that a commitment is not function of the future message to sign, so a signer can produce them without knowing the message in advance.
- Signers send these commitments to either a coordinator or all other signers.
- The coordinator (or all other signers) collect these commitments, into a list. The coordinator can prepare such lists
for each future message to be signed, a list containing a single commitment from each signer. These commitments must
not be reused.

#### Second Round: Signing
- The coordinator broadcasts the message to be signed and a list of commitments, one from each signer, to each signer.
- The signers sign the message ```sigShare, err := signer.Sign(message, commitmentList)```, each producing their signature share.
- These signature shares must then be shared and aggregated to produce the final signature,
```signature, err := configuration.AggregateSignatures(message, sigShares, commitmentList, true)```.

#### Coordinator

The coordinator does not have any secret or private information, and must never have. It is also assumed to behave honestly.

Commitments received by signers have an identifier, which allows for triage and registration. Commitments must only be
used once. The coordinator may further hedge against nonce-reuse by tracking the nonce commitments used for a given group key.

If the ```verify``` argument in the ```AggregateSignatures()``` is set to ```true``` (which is recommended), signature shares are thoroughly verified.
Upon error or invalid share, the error message indicates the first invalid share it encountered.
A coordinator should always verify the signature after ```AggregateSignatures()``` if the ```verify``` argument has been set to ```false```.

If verification fails, the coordinator can then check signature shares individually to deter the misbehaving signer, leveraging the authenticated channel associated to them.
That signer can then be denied of further contributions.

### Resumption and storage

Configurations, keys, commitments, commitment lists, and even signers can be serialized for transmission and storage,
and re-instantiated from them. To decode, just create that object and use its ```Decode()``` method.

For example, to back up a signer with its private keys and commitments, use:
```go
bytes := signer.Encode()
```

To re-instantiate that same signer from the byte string, do:
```go
// bytes := signer.Encode()

signer := new(frost.Signer)
if err := signer.Decode(bytes); err != nil {
	return err
}
```

Keep in mind that signer encoding embeds the private key and secret nonces, and that they must be secured accordingly.

## Notes

Signers have local secret data and state, offline and during protocol execution:
- the long term secret key
- the internally stored commitment nonces, maintained between commitment and signature

- FROST is _not robust_ by design.
  - This means that there is a misbehaving participant if signature aggregation fails
  (or if the output signature is not valid), in which case the protocol should be aborted and the problem investigated
  (you shouldn't have a compromised or misbehaving participant in a sane infrastructure).
  - Misbehaving signers can DOS the protocol by providing wrong sig shares or not contributing.
- The coordinator may further hedge against nonce-reuse by tracking the nonce commitments used for a given group key
- For message pre-hashing, see [RFC](https://datatracker.ietf.org/doc/rfc9591)

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/frost.svg)](https://pkg.go.dev/github.com/bytemare/frost)

You can find the godoc documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/frost).

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/frost/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
