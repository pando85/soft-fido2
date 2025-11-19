CARGO_TARGET_DIR ?= target
CARGO_TARGET ?= x86_64-unknown-linux-gnu
PKG_BASE_NAME ?= keylib-${CARGO_TARGET}
PROJECT_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' ./Cargo.toml | head -n1)

.DEFAULT: help
.PHONY: help
help:	## Show this help menu.
	@echo "Usage: make [TARGET ...]"
	@echo ""
	@@egrep -h "#[#]" $(MAKEFILE_LIST) | sed -e 's/\\$$//' | awk 'BEGIN {FS = "[:=].*?#[#] "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

.PHONY: build
build:	## compile keylib
build:
	cargo build

# Pre-commit targets
.PHONY: pre-commit-install
pre-commit-install: ## install pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg

.PHONY: pre-commit
pre-commit: ## run pre-commit on all files
	pre-commit run --all-files

# Rust formatting and linting targets
.PHONY: fmt
fmt: ## format Rust code using cargo fmt
	cargo fmt

.PHONY: fmt-check
fmt-check: ## check Rust code formatting
	cargo fmt -- --check

.PHONY: clippy
clippy: ## run clippy linter on Rust code
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: clippy-fix
clippy-fix: ## run clippy with automatic fixes
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

.PHONY: lint
lint: fmt-check clippy ## run all linting checks (fmt + clippy)

.PHONY: lint-fix
lint-fix: fmt clippy-fix ## run all linting with automatic fixes

.PHONY: test
test:	## run tests
test: lint
	cargo test

.PHONY: test-e2e
test-e2e:	## run E2E WebAuthn tests (requires UHID permissions)
	cargo test -- --ignored

.PHONY: test-all
test-all:	## run all tests including E2E
test-all: test test-e2e

.PHONY: update-version
update-version: ## update version from VERSION file in all Cargo.toml manifests
update-version: */Cargo.toml
	@VERSION=$$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1); \
	sed -i -E "s/(keylib-[a-z0-9-]+ = \{ path = \"[^\"]+\", version = )\"[^\"]+\"/\1\"$$VERSION\"/g" Cargo.toml && \
	cargo update --workspace ;

.PHONY: update-changelog
update-changelog:	## automatically update changelog based on commits
	git cliff -t v$(PROJECT_VERSION) -u -p CHANGELOG.md

.PHONY: publish
publish:	## publish crate
	cargo publish --workspace
