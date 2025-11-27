# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.3.2](https://github.com/pando85/soft-fido2/tree/v0.3.2) - 2025-11-27

### Added

- Implement support for `maxMsgSize` option ([b1ed04c](https://github.com/pando85/soft-fido2/commit/b1ed04c4b46b531bed84425f9034a3e3a040720c))

### Fixed

- Return none if client_pin option is not configured ([f48a161](https://github.com/pando85/soft-fido2/commit/f48a1610bb8f8a49ce49d31938af6af7fa9d0fc2))
- CBOR serialization at get_info CTAP command ([7c73038](https://github.com/pando85/soft-fido2/commit/7c73038197676d43e7c4a91d8bcd82e0298bbc51))

## [v0.3.1](https://github.com/pando85/soft-fido2/tree/v0.3.1) - 2025-11-24

### Fixed

- SecBytes deserialization to properly handle CBOR byte instead of expecting arrays ([510d761](https://github.com/pando85/soft-fido2/commit/510d7616c2a2a4eff7a813a39783b2ddf25835bf))

## [v0.3.0](https://github.com/pando85/soft-fido2/tree/v0.3.0) - 2025-11-23

### Added

- Secure private key with secstr lib ([9fcb6cc](https://github.com/pando85/soft-fido2/commit/9fcb6cccc366afe9fc627be8316a383175ee78aa))
  - **BREAKING**: This commit introduces the use of the `secstr` library
to securely handle private keys in memory. This change Credential API
now uses `SecStr` for storing private keys, enhancing security by
minimizing the risk of sensitive data exposure.

### Refactor

- Reorder imports following style guide ([811bd22](https://github.com/pando85/soft-fido2/commit/811bd2228ed0e0f76177c63e15479c01fb00f28d))

## [v0.2.1](https://github.com/pando85/soft-fido2/tree/v0.2.1) - 2025-11-23

### Fixed

- Use timeout_ms from requests in transport layer ([e65b981](https://github.com/pando85/soft-fido2/commit/e65b9815fb44e5c14a54bd904e1cd592e577b53f))

## [v0.2.0](https://github.com/pando85/soft-fido2/tree/v0.2.0) - 2025-11-21

### Added

- Add `constant_sign_count` config param to Authenticator ([40fe112](https://github.com/pando85/soft-fido2/commit/40fe112ddeee250af65a2164746e4a87fdad3c3e))

### Documentation

- Fix readme header and badges ([3c3c680](https://github.com/pando85/soft-fido2/commit/3c3c6802a8cc71bea3de73bab55f5e5e453805b2))

## [v0.1.0](https://github.com/pando85/soft-fido2/tree/v0.1.0) - 2025-11-20

### Added

- Expose enumarate_rps and credential_count callbacks ([9d59f4a](https://github.com/pando85/soft-fido2/commit/9d59f4ad7203afe8ce6ef73ce6db6491a6eaf4e3))
- Expose custom CTAP command handler API ([d151290](https://github.com/pando85/soft-fido2/commit/d151290ab2148637be5b50979edee72eba3b8c85))
- Implement embedded system optimizations (Phases 1-4) ([de2983f](https://github.com/pando85/soft-fido2/commit/de2983ff61f3d6e7068276cc90a4b5a167bdd9bd))
- Add embedded example and documentation (Phase 5) ([91c064d](https://github.com/pando85/soft-fido2/commit/91c064d0978743e75db0214eed7214a1736bd9a4))
- Complete full no_std support for soft-fido2-ctap ([ea35a86](https://github.com/pando85/soft-fido2/commit/ea35a865db94dd8688b8a4b04fab19e965226b31))

### Fixed

- Make clippy happy ([bfdb000](https://github.com/pando85/soft-fido2/commit/bfdb000d70db60fb575a65f47669ad98be8deb57))

### Refactor

- Clean repo, docs and reorder imports ([d09e57b](https://github.com/pando85/soft-fido2/commit/d09e57ba56f0a7839b5c8870930d8524497221eb))
- Remove debug traces in examples ([16f3631](https://github.com/pando85/soft-fido2/commit/16f36316e75ebbda833f859e86a014b14afe6c14))

### Testing

- Refactor e2e clean spaghetti code and remove repeated tests ([e248141](https://github.com/pando85/soft-fido2/commit/e248141a0d287b5171165ba6853fec6381cd3612))

## [v0.0.0](https://github.com/pando85/soft-fido2/tree/v0.0.0) - 2025-11-19

Initial release
