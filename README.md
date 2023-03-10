# FROST
[![frost](https://github.com/bytemare/frost/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/frost/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/frost.svg)](https://pkg.go.dev/github.com/bytemare/frost)
[![codecov](https://codecov.io/gh/bytemare/frost/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/frost)

```
  import "github.com/bytemare/frost"
```

This package implements [FROST](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost).

It is currently in active development, and utterly useless.

#### What is frost?

> FROST reduces network overhead during threshold signing operations while employing a novel technique to protect
> against forgery attacks applicable to prior Schnorr-based threshold signature constructions. FROST signatures can be
> issued after a threshold number of entities cooperate to compute a signature, allowing for improved distribution of
> trust and redundancy with respect to a secret key.

#### References
- [The original paper](https://eprint.iacr.org/2020/852.pdf) from @chelseakomlo and Ian Goldberg.
- [The Github repo](https://github.com/cfrg/draft-irtf-cfrg-frost) where the draft is being specified.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/frost.svg)](https://pkg.go.dev/github.com/bytemare/frost)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/frost) and [the project wiki](https://github.com/bytemare/frost/wiki) .

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/frost/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
