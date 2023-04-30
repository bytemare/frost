# Distributed Key Generation

This package implements a Distributed Key Generation. It builds on the 2-round Pederson DGK and extends it with
zero-knowledge proofs to protect against rogue-key attacks, as defined in [FROST](https://eprint.iacr.org/2020/852.pdf).

This effectively generates keys among participants without the need of a trusted dealer or third-party. These keys are
compatible for use in FROST.

### References

- Pederson introduced the [first DKG protocol](https://link.springer.com/chapter/10.1007/3-540-46416-6_47), based on Feldman's Verifiable Secret Sharing.
- Komlo & Goldberg [add zero-knowledge proofs](https://eprint.iacr.org/2020/852.pdf) to the Ped-DKG.

## Usage

### Assumptions

- All parties are identified with unique IDs.
- Communicate over confidential, authenticated, and secure channels.
- All participants honestly follow the protocol (they can, nevertheless, identify the misbehaving participant).

### Setup

Use the same ciphersuite for the DKG and FROST.

### Error handling

In case of an identified misbehaving participant, abort the protocol immediately. If this happens there might be a serious
problem that must be investigated. One may re-run the protocol after excluding that participant and solving the problem.

### Protocol

The following steps describe how to run the DKG among participants. For each participant:
1. Run Init()
    - this returns a round 1 package
    - send/broadcast this package to every participant
  (this might include the very same participant, in which case it should discard it)
2. Collect all the r1 packages from other participants
3. Run Continue() with the collection of r1 packages
    - this returns round 2 packages, one destined to each other participant
    - send these packages to their destined participant
4. Collect all round 2 packages destined to the participant
5. Run Finalize() with the collected round 1 and round 2 packages
    - returns the participant's own secret signing share, 
      the corresponding verification share, and the group's public key
6. Erase all intermediary values received and computed by the participants (including in their states)
7. Optionally, compute the verification keys for each other participant and store them

## Possible extensions

- Laing and Stinson [refine Repairable Threshold Schemes](https://eprint.iacr.org/2017/1155.pdf) to enable a participant to securely reconstruct a lost share with help from their peers.
- Herzberg et al. propose [Proactive Secret Sharing](https://www.researchgate.net/profile/Amir-Herzberg/publication/221355399_Proactive_Secret_Sharing_Or_How_to_Cope_With_Perpetual_Leakage/links/02e7e52e0ecf4dbae1000000/Proactive-Secret-Sharing-Or-How-to-Cope-With-Perpetual-Leakage.pdf), allowing for shares to be rotated without impact on the secret key.
- Gennaro et al. improve on the Ped-DKG and propose a [more robust version called New-DKG](https://link.springer.com/article/10.1007/s00145-006-0347-3).
- Canetti et al. extend New-DKG to make it [secure against adaptive adversaries](https://link.springer.com/content/pdf/10.1007/3-540-48405-1_7.pdf).
- Jarecki and Lysyanskaya present the [erasure-free model](https://www.iacr.org/archive/eurocrypt2000/1807/18070223-new.pdf) for threshold schemes secure against adaptive adversaries.
