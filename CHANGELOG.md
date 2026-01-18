# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.10.1](https://github.com/pando85/soft-fido2/tree/v0.10.1) - 2026-01-18

### Build

- ci: Add renovate ([e818960](https://github.com/pando85/soft-fido2/commit/e818960144b3faf69025a27c383f715e56c53ca2))
- deps: Update pre-commit hook adrienverge/yamllint to v1.38.0 ([260048b](https://github.com/pando85/soft-fido2/commit/260048b08caa279fdb5cf2f9c55718f09410aed2))
- deps: Update pre-commit hook alessandrojcm/commitlint-pre-commit-hook to v9.24.0 ([bb9483e](https://github.com/pando85/soft-fido2/commit/bb9483e686434a184301196cb09f35c7bb381a83))
- deps: Update Rust crate spin to 0.10 ([7ce2987](https://github.com/pando85/soft-fido2/commit/7ce29875628961c4149f6b502404d6dbbbfab299))
- deps: Update Rust crate hex-literal to v1 ([d82b80f](https://github.com/pando85/soft-fido2/commit/d82b80fc8e38cca1ad79a731e5171d3f635b1087))
- deps: Update Rust crate thiserror to v2 ([777b874](https://github.com/pando85/soft-fido2/commit/777b8747767573803f6bfc2cb61fd7057a05e64d))
- deps: Update actions/cache action to v5 ([4f6caca](https://github.com/pando85/soft-fido2/commit/4f6caca8cc0ce062826628d392089ae455de07d2))
- deps: Update actions/checkout action to v6 ([ca60422](https://github.com/pando85/soft-fido2/commit/ca604220d731c2795deb209bda225382806e1063))
- deps: Update Rust crate nix to 0.30 ([f86d0cc](https://github.com/pando85/soft-fido2/commit/f86d0cc7c8c41e26ab1f50481bac636bb3646530))
- deps: Update nix to 0.30 ([d646557](https://github.com/pando85/soft-fido2/commit/d646557a2152429a5c5036d6fb4d701cea642288))

## [v0.10.0](https://github.com/pando85/soft-fido2/tree/v0.10.0) - 2025-12-17

### Fixed

- Security hardening on PIN protocol v2 implementation ([2ed87b6](https://github.com/pando85/soft-fido2/commit/2ed87b66588572fa46b5d6ba044a62301f06426e), [097bf3e](https://github.com/pando85/soft-fido2/commit/097bf3eb7a3ca2995bcb57646b20603b7938d839) and [3dad6df](https://github.com/pando85/soft-fido2/commit/3dad6dffdde61e0b213c306acc4e9bf342e67fae))

## [v0.9.0](https://github.com/pando85/soft-fido2/tree/v0.9.0) - 2025-12-10

### Added

- Add full pin support ([39078ff](https://github.com/pando85/soft-fido2/commit/39078fff3291f54efa3f2a3dd2813d35b3f20d62))

### Fixed

- Add zeroized to short live secrets ([7d65c22](https://github.com/pando85/soft-fido2/commit/7d65c22b9a6bdd7eb1b78080ee863e12b5e07e21))

### Refactor

- Add descriptive names to commands and keys in cred mgmt ([8092786](https://github.com/pando85/soft-fido2/commit/809278640adea55b89dc9966dd38b1300e632144))

### Testing

- Add nostd suite ([593b1b2](https://github.com/pando85/soft-fido2/commit/593b1b29cd1563bf6f199bf58bd00010835a9e3a))

## [v0.8.0](https://github.com/pando85/soft-fido2/tree/v0.8.0) - 2025-12-10

### Fixed

- Clean callbacks interface ([a184b8f](https://github.com/pando85/soft-fido2/commit/a184b8f701a9553c6bc3ec0fb6c5a89423c1ccec))
  - **BREAKING**: `write_credential` and `read_credential` fingerprints have being updated.

## [v0.7.0](https://github.com/pando85/soft-fido2/tree/v0.7.0) - 2025-12-08

### Added

- Make HID device configurable ([812e1a0](https://github.com/pando85/soft-fido2/commit/812e1a056553a9c4e06554db2e9d962b9a71cd3e))

### Documentation

- Add client capability info to README ([5f491a1](https://github.com/pando85/soft-fido2/commit/5f491a12459f5e745672c81f209b97d997610203))
- Add projects section ([22fcbce](https://github.com/pando85/soft-fido2/commit/22fcbce46e28ab02ac1afeaec39c16d28608d311))

### Refactor

- Remove AI slop ([3523468](https://github.com/pando85/soft-fido2/commit/3523468c046a97ad111a7ef9bc7e3d9f9cf58e5f))
- Clean unnecessary usb feature gates ([d00f774](https://github.com/pando85/soft-fido2/commit/d00f774db9176c3e9f2aa99ea0338153eac2cbad))

## [v0.6.1](https://github.com/pando85/soft-fido2/tree/v0.6.1) - 2025-12-05

### Fixed

- Check UV capability correctly in makeCredential ([d89c3f0](https://github.com/pando85/soft-fido2/commit/d89c3f0aba648fc74d494cf44301b9791d36f365))

## [v0.6.0](https://github.com/pando85/soft-fido2/tree/v0.6.0) - 2025-12-05

### Refactor

- Unify types between soft-fido2 and CTAP module ([41db80a](https://github.com/pando85/soft-fido2/commit/41db80ab0b7ae19996db7a4d3e6018e946a38c91))

### Testing

- Add update user information e2e tests ([e93bb52](https://github.com/pando85/soft-fido2/commit/e93bb529ad6db93fd8939be266822a0e5a95fc43))

## [v0.5.0](https://github.com/pando85/soft-fido2/tree/v0.5.0) - 2025-12-02

### Added

- Add client manage credential commands and fix manage cred perm ([27cf48a](https://github.com/pando85/soft-fido2/commit/27cf48a07ea87d334bf5f25552875d68569fab7b))

### Fixed

- Strictly implement FIDO 2.2 make_credentials ([f5d7fa3](https://github.com/pando85/soft-fido2/commit/f5d7fa3ca067187c25b96b2766dbb71d5bf2128e))
- Strictly implement FIDO 2.2 get_assertion ([a73a5d9](https://github.com/pando85/soft-fido2/commit/a73a5d9d33bdfde9ee16438cca787cfc5f86bd37))

### Documentation

- Simplify README ([6197659](https://github.com/pando85/soft-fido2/commit/61976595b9433806312f9d111c1e60e5194833da))
- Add version 2.2 support to readme ([52d4106](https://github.com/pando85/soft-fido2/commit/52d4106d65a12db31fd4a2474e3a2b0b0afdb048))
- Add FIDO version 2.2 commented ([8cabe71](https://github.com/pando85/soft-fido2/commit/8cabe712ac2cbbee2dc58d8680410c9d776344ab))

## [v0.4.4](https://github.com/pando85/soft-fido2/tree/v0.4.4) - 2025-12-01

### Revert

- Remove serde bytes from User.id and use ctap types on client ([f397be1](https://github.com/pando85/soft-fido2/commit/f397be1111d4f5e1ad69562ac8a4a40e49e8ecb2))

## [v0.4.3](https://github.com/pando85/soft-fido2/tree/v0.4.3) - 2025-11-30

### Refactor

- Reorder make_credential user verification logic ([b8f952c](https://github.com/pando85/soft-fido2/commit/b8f952c17c83c1f71b1c82938ff45725ba53d200))

## [v0.4.2](https://github.com/pando85/soft-fido2/tree/v0.4.2) - 2025-11-30

### Fixed

- Ensure CHANGELOG commit IDs are correct on release process ([5630cf3](https://github.com/pando85/soft-fido2/commit/5630cf36ccb841b9e90d43c1dfae3b78329dc829))
- Remove dbg statement ([665f9bf](https://github.com/pando85/soft-fido2/commit/665f9bf5de6eeb2504628e1d6620fc96b4528787))

## [v0.4.1](https://github.com/pando85/soft-fido2/tree/v0.4.1) - 2025-11-30

### Added

- Implement getUvRetries subcommand ([24da133](https://github.com/pando85/soft-fido2/commit/24da133a4cbac71c467bb20bb05222fad93db361))

### Fixed

- Remove FIDO_2_2 version ([302c087](https://github.com/pando85/soft-fido2/commit/302c087f5746b0b13dbfe0c92c5de7821644b05b))
- Use canonical CBOR field order in PublicKeyCredentialDescriptor ([7a72c11](https://github.com/pando85/soft-fido2/commit/7a72c11a1d409244b338bdddba214e7b030392e9))
- Use canonical CBOR field order in Credential ([f81cdcc](https://github.com/pando85/soft-fido2/commit/f81cdcc8918a810b79b6d5cfaefd8dfffa719983))

## [v0.4.0](https://github.com/pando85/soft-fido2/tree/v0.4.0) - 2025-11-29

### Added

- Add getPinUvAuthTokenUsingUvWithPermissions and enhance PIN protocol v2 support ([dcd529c](https://github.com/pando85/soft-fido2/commit/dcd529cbb30312bc59744943117a54092336ab18))
- Reimplement getAssertion command for FIDO 2.2 spec compliance ([304c2af](https://github.com/pando85/soft-fido2/commit/304c2affa7d1a6104f1b63c1f30d0ef4ebdaa411))
- Add FIDO 2.2 to get_info supported versions ([f4452a8](https://github.com/pando85/soft-fido2/commit/f4452a896f3117b84c36ede384f7f80dd7fdcdfb))
- Handle config CTAP commands as UnsupportedOption ([476d85f](https://github.com/pando85/soft-fido2/commit/476d85fce01073650da0c0e3d1eb8a4a9a0d9811))
- Implement delete credentials in reset command ([dd01329](https://github.com/pando85/soft-fido2/commit/dd013297374297f4c7e8f8e8569dd9dfc4eae57d))

### Refactor

- Reorganize .gitignore into standard sections ([a8f28c5](https://github.com/pando85/soft-fido2/commit/a8f28c54a6c956ed58780e00eb55ae6be3b3bc03))

### Testing

- Add Mozilla authenticator crate compatibility tests ([ffc5329](https://github.com/pando85/soft-fido2/commit/ffc5329dccea6ed71da933ca72cf24711dbf11c2))

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
