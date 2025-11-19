# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.2.3](https://github.com/pando85/rust-keylib/tree/v0.2.3) - 2025-11-17

### Fixed

- ci: Change arm64 prebuild binaries to arm runner ([0599ecc](https://github.com/pando85/rust-keylib/commit/0599ecccd0f015564ed0356e25eaab40a0b1e818))
- Force char to be u8 on all platform for cross compilation consistency ([6737338](https://github.com/pando85/rust-keylib/commit/6737338ce44026227b8e07ae9e9f578b4ebcf9e5))

## [v0.2.2](https://github.com/pando85/rust-keylib/tree/v0.2.2) - 2025-11-17

### Fixed

- Force char to be u8 on all platform for cross compilation consistency ([6737338](https://github.com/pando85/rust-keylib/commit/6737338ce44026227b8e07ae9e9f578b4ebcf9e5))

## [v0.2.1](https://github.com/pando85/rust-keylib/tree/v0.2.1) - 2025-11-14

### Added

- Add ci release and remove Cargo.lock from repo ([c6f7a13](https://github.com/pando85/rust-keylib/commit/c6f7a13ad5d5c7a35320a7502bfb4e9e718e0ef2))
- Add support for Authenticator config ([1aac1b3](https://github.com/pando85/rust-keylib/commit/1aac1b333894880a03490815664032894850a2f6))
- Add support for custom commands and example credential mgmt ([ee737ab](https://github.com/pando85/rust-keylib/commit/ee737ab485ea5a1bfcaf3a7da538f80ed8b9299b))
- Add support to configure firmware version ([5dece2e](https://github.com/pando85/rust-keylib/commit/5dece2e5fc2112295d9d34a98e0de7db579f3e84))
- Add support for serialize/deserialize Credentials ([87c97a0](https://github.com/pando85/rust-keylib/commit/87c97a095d4f57795be7e17bed596e971e15879d))
- Add support for user name and display name ([0dd0b8e](https://github.com/pando85/rust-keylib/commit/0dd0b8e23143b9cdbc79a67318a2e0c96c4aa7d7))
- Add bundled feature to keylib crate ([7f59ae9](https://github.com/pando85/rust-keylib/commit/7f59ae926f4d4cfdd180f62479733fffc157f39d))

### Fixed

- Remove clippy `--all-features` in CI ([cf05a59](https://github.com/pando85/rust-keylib/commit/cf05a59eaea1261de7fa110caeaca3b7d96dd9fa))
- Prevent cache corruption and enable workflow chaining ([3a1d20a](https://github.com/pando85/rust-keylib/commit/3a1d20a04ab3c157ed9bfd4747a0d846aacf5762))
- Add explicit type annotation for union field access ([421b3eb](https://github.com/pando85/rust-keylib/commit/421b3ebbdff441747e0ee0ea8c5b1e010ae0a64d))
- Disable prebuild concurrent jobs ([f26ea85](https://github.com/pando85/rust-keylib/commit/f26ea85372ad4fd3b3fb9442cb26778e97d04a25))
- Disable logs from Zig library ([9df5a61](https://github.com/pando85/rust-keylib/commit/9df5a61738adcfcc6373200d07430728c09b6ce6))
- Transport core dump and support for transport read timeout ([79b7d26](https://github.com/pando85/rust-keylib/commit/79b7d269141d6107bc0b9b8584479484e73bbdf8))
- Support alwaysUv config in ziglib ([aad0ca0](https://github.com/pando85/rust-keylib/commit/aad0ca0d1be857e2796222ae85e3825c263b4b4a))
- Enable constSignCount in Authenticator through keylib bindings ([e7aad44](https://github.com/pando85/rust-keylib/commit/e7aad4472b3f4f2768526cbb366919d9be925cf3))
- Remove duplicated struct RelyingParty ([86591b4](https://github.com/pando85/rust-keylib/commit/86591b4a52f6381722889afb84c02ab601097add))

### Documentation

- Add v0.1.0 release notes ([92ebc65](https://github.com/pando85/rust-keylib/commit/92ebc65491ffd83d7215f472f6b025185c40ba6f))

### Refactor

- Update Rust to edition 2024 ([f3b07ba](https://github.com/pando85/rust-keylib/commit/f3b07baf7297a9c796c140d5f6d666bac59ee09f))

## [v0.2.0](https://github.com/pando85/rust-keylib/tree/v0.2.0) - 2025-11-14

### Added

- Add ci release and remove Cargo.lock from repo ([c6f7a13](https://github.com/pando85/rust-keylib/commit/c6f7a13ad5d5c7a35320a7502bfb4e9e718e0ef2))
- Add support for Authenticator config ([1aac1b3](https://github.com/pando85/rust-keylib/commit/1aac1b333894880a03490815664032894850a2f6))
- Add support for custom commands and example credential mgmt ([ee737ab](https://github.com/pando85/rust-keylib/commit/ee737ab485ea5a1bfcaf3a7da538f80ed8b9299b))
- Add support to configure firmware version ([5dece2e](https://github.com/pando85/rust-keylib/commit/5dece2e5fc2112295d9d34a98e0de7db579f3e84))
- Add support for serialize/deserialize Credentials ([87c97a0](https://github.com/pando85/rust-keylib/commit/87c97a095d4f57795be7e17bed596e971e15879d))
- Add support for user name and display name ([0dd0b8e](https://github.com/pando85/rust-keylib/commit/0dd0b8e23143b9cdbc79a67318a2e0c96c4aa7d7))

### Fixed

- Remove clippy `--all-features` in CI ([cf05a59](https://github.com/pando85/rust-keylib/commit/cf05a59eaea1261de7fa110caeaca3b7d96dd9fa))
- Prevent cache corruption and enable workflow chaining ([3a1d20a](https://github.com/pando85/rust-keylib/commit/3a1d20a04ab3c157ed9bfd4747a0d846aacf5762))
- Add explicit type annotation for union field access ([421b3eb](https://github.com/pando85/rust-keylib/commit/421b3ebbdff441747e0ee0ea8c5b1e010ae0a64d))
- Disable prebuild concurrent jobs ([f26ea85](https://github.com/pando85/rust-keylib/commit/f26ea85372ad4fd3b3fb9442cb26778e97d04a25))
- Disable logs from Zig library ([9df5a61](https://github.com/pando85/rust-keylib/commit/9df5a61738adcfcc6373200d07430728c09b6ce6))
- Transport core dump and support for transport read timeout ([79b7d26](https://github.com/pando85/rust-keylib/commit/79b7d269141d6107bc0b9b8584479484e73bbdf8))
- Support alwaysUv config in ziglib ([aad0ca0](https://github.com/pando85/rust-keylib/commit/aad0ca0d1be857e2796222ae85e3825c263b4b4a))
- Enable constSignCount in Authenticator through keylib bindings ([e7aad44](https://github.com/pando85/rust-keylib/commit/e7aad4472b3f4f2768526cbb366919d9be925cf3))
- Remove duplicated struct RelyingParty ([86591b4](https://github.com/pando85/rust-keylib/commit/86591b4a52f6381722889afb84c02ab601097add))

### Documentation

- Add v0.1.0 release notes ([92ebc65](https://github.com/pando85/rust-keylib/commit/92ebc65491ffd83d7215f472f6b025185c40ba6f))

### Refactor

- Update Rust to edition 2024 ([f3b07ba](https://github.com/pando85/rust-keylib/commit/f3b07baf7297a9c796c140d5f6d666bac59ee09f))

## [v0.1.3](https://github.com/pando85/rust-keylib/tree/v0.1.3) - 2025-11-09

### Added

- Add ci release and remove Cargo.lock from repo ([c6f7a13](https://github.com/pando85/rust-keylib/commit/c6f7a13ad5d5c7a35320a7502bfb4e9e718e0ef2))

### Fixed

- Remove clippy `--all-features` in CI ([cf05a59](https://github.com/pando85/rust-keylib/commit/cf05a59eaea1261de7fa110caeaca3b7d96dd9fa))
- Prevent cache corruption and enable workflow chaining ([3a1d20a](https://github.com/pando85/rust-keylib/commit/3a1d20a04ab3c157ed9bfd4747a0d846aacf5762))
- Add explicit type annotation for union field access ([421b3eb](https://github.com/pando85/rust-keylib/commit/421b3ebbdff441747e0ee0ea8c5b1e010ae0a64d))

### Documentation

- Add v0.1.0 release notes ([92ebc65](https://github.com/pando85/rust-keylib/commit/92ebc65491ffd83d7215f472f6b025185c40ba6f))

### Refactor

- Update Rust to edition 2024 ([f3b07ba](https://github.com/pando85/rust-keylib/commit/f3b07baf7297a9c796c140d5f6d666bac59ee09f))

## [v0.1.2](https://github.com/pando85/rust-keylib/tree/v0.1.2) - 2025-11-09

### Added

- Add ci release and remove Cargo.lock from repo ([c6f7a13](https://github.com/pando85/rust-keylib/commit/c6f7a13ad5d5c7a35320a7502bfb4e9e718e0ef2))

### Fixed

- Remove clippy `--all-features` in CI ([cf05a59](https://github.com/pando85/rust-keylib/commit/cf05a59eaea1261de7fa110caeaca3b7d96dd9fa))
- Prevent cache corruption and enable workflow chaining ([3a1d20a](https://github.com/pando85/rust-keylib/commit/3a1d20a04ab3c157ed9bfd4747a0d846aacf5762))

### Documentation

- Add v0.1.0 release notes ([92ebc65](https://github.com/pando85/rust-keylib/commit/92ebc65491ffd83d7215f472f6b025185c40ba6f))

## [v0.1.1](https://github.com/pando85/rust-keylib/tree/v0.1.1) - 2025-11-09

### Added

- Add ci release and remove Cargo.lock from repo ([c6f7a13](https://github.com/pando85/rust-keylib/commit/c6f7a13ad5d5c7a35320a7502bfb4e9e718e0ef2))

### Fixed

- Remove clippy `--all-features` in CI ([cf05a59](https://github.com/pando85/rust-keylib/commit/cf05a59eaea1261de7fa110caeaca3b7d96dd9fa))

### Documentation

- Add v0.1.0 release notes ([92ebc65](https://github.com/pando85/rust-keylib/commit/92ebc65491ffd83d7215f472f6b025185c40ba6f))

## [v0.1.0](https://github.com/pando85/rust-keylib/tree/v0.1.0) - 2025-11-09

Initial release of rust-keylib, providing Rust FFI bindings for the
[keylib](https://github.com/Zig-Sec/keylib) C API.
