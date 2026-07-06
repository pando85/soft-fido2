---
name: release
description: Prepare and publish a new release. Use when the user asks to release, cut a release, or publish a new version.
---

## Purpose

Release a new version of soft-fido2 using the release script and CI pipeline.

## When to use

Use this skill when:
- The user asks to release a new version
- The user asks to cut a release or publish
- The user asks to tag a new version

## Prerequisites

Before releasing, verify:

1. **Working tree is clean** -- no uncommitted changes
2. **Local checkout points at the latest default-branch commit** -- release changelogs need the latest default-branch commit ID
3. **No commits ahead of origin/default-branch** -- output of `git rev-list --count origin/<default>..HEAD` must be 0
4. **Repository is not a shallow clone** -- git-cliff needs full history for accurate changelogs

The release script handles shallow/latest-commit checkouts by fetching full history and tags before comparing against the remote default branch.

Check manually with:

```bash
git status --short
git rev-parse --abbrev-ref HEAD
git fetch origin
git rev-list --count origin/master..HEAD
git tag --sort=-creatordate | head -3
git log --oneline v<latest_tag>..HEAD
```

## Version Decision Guide

Use Semantic Versioning (MAJOR.MINOR.PATCH). Determine the bump type by analyzing commits since the last release.

### Major Version (X.0.0)

Bump MAJOR when:
- Breaking changes to public APIs
- Breaking changes to CTAP behavior
- Breaking changes to crate features or default behavior
- Commit message contains `BREAKING CHANGE:` or `!` (for example, `feat!: ...`)

### Minor Version (0.X.0)

Bump MINOR when:
- New features are added (`feat:` commits)
- New public APIs are added
- New CTAP capabilities are added
- Backward-compatible enhancements are added

### Patch Version (0.0.X)

Bump PATCH when:
- Bug fixes are added (`fix:` commits)
- Documentation updates are added (`docs:` commits)
- Internal refactoring is added (`refactor:` commits)
- Dependency updates are added (`build(deps):` or `chore(deps):` commits)

### Decision Process

1. Run `git log v<CURRENT_VERSION>..HEAD --oneline`.
2. Check commit messages for `!` or `BREAKING CHANGE:` -> MAJOR.
3. Check for `feat:` -> MINOR.
4. Otherwise use PATCH for fixes, docs, refactors, and dependency updates.
5. If multiple types are present, use the highest precedence: MAJOR > MINOR > PATCH.

## Release Process

### Step 1: Verify Clean State

Run the release script from a clean checkout. It fetches full history/tags when needed, including when the local checkout was fetched with only the latest commit.

```bash
.ci/release.sh
```

If checking manually:

```bash
git status --short
git rev-parse --is-shallow-repository
git fetch --unshallow origin  # only if shallow
git fetch --tags origin
git rev-list --count origin/master..HEAD
```

### Step 2: Determine Version

1. Get current version:
   ```bash
   grep '^version =' Cargo.toml | head -1
   ```
2. Review commits since last release:
   ```bash
   git log v<CURRENT_VERSION>..HEAD --oneline
   ```
3. Decide on MAJOR, MINOR, or PATCH based on the version guide.

### Step 3: Create Release Branch

```bash
git checkout -b release/v<NEW_VERSION>
```

### Step 4: Update Version

Edit the root `Cargo.toml` and update the version in the `[workspace.package]` section:

```toml
version = "<NEW_VERSION>"
```

### Step 5: Update Dependencies

```bash
make update-version
```

This updates soft-fido2 workspace dependency versions and runs `cargo update --workspace`.

### Step 6: Update Changelog

```bash
make update-changelog
```

This runs `git cliff -t v<VERSION> -u -p CHANGELOG.md`.

### Step 7: Commit Changes

```bash
git add .
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
git commit -m "release: Version $VERSION"
```

### Step 8: Push Branch and Create PR

```bash
git push -u origin release/v<NEW_VERSION>
```

Create a pull request to merge into master.

### Step 9: After Merge

After the PR is merged to master, tagging and releasing is done automatically by CI:

1. `auto-tag.yaml` reads the new version from `CHANGELOG.md`.
2. It creates a signed GPG tag `v<VERSION>`.
3. The tag triggers `rust.yml` to build, test, publish crates to crates.io, and create a GitHub Release.

Monitor with:

```bash
gh run list --limit 5
```

Do not manually create tags. CI handles this automatically.

## What Not To Do

| Mistake | Why it's wrong | Fix |
|---------|---------------|-----|
| Manually editing CHANGELOG.md | git-cliff generates it from conventional commits | Use `make update-changelog` |
| Creating git tags manually | `auto-tag.yaml` creates signed tags automatically | Just push to master |
| Releasing with dirty working tree | Script will fail or produce incomplete release | Commit or stash changes first |
| Skipping the unshallow check | Shallow clones produce incomplete changelogs | Let `.ci/release.sh` fetch full history/tags |
| Forgetting `make update-version` after Cargo.toml edit | Version won't propagate to workspace members | Always run `make update-version` |

## Key Files

| File | Role |
|------|------|
| `Cargo.toml` | Workspace version (single source of truth) |
| `cliff.toml` | git-cliff configuration for changelog generation |
| `CHANGELOG.md` | Generated changelog (auto-tag reads version from here) |
| `.github/workflows/auto-tag.yaml` | Creates signed GPG tag on push to master |
| `.github/workflows/rust.yml` | Builds, tests, publishes to crates.io and GitHub on tag |
| `Makefile` | `update-version`, `update-changelog`, and `publish` targets |
| `.ci/release.sh` | Full release script |

## Checklist

- [ ] Clean working tree
- [ ] Checkout points at latest origin/master commit
- [ ] Repository has full history and tags, or `.ci/release.sh` fetched them
- [ ] Determined version bump type
- [ ] Created release branch `release/v<VERSION>`
- [ ] Updated version in `Cargo.toml`
- [ ] Ran `make update-version`
- [ ] Ran `make update-changelog`
- [ ] Committed with message `release: Version <VERSION>`
- [ ] Pushed and created PR
- [ ] After merge: CI automatically creates tag and release

## Quick Reference

| Step | Command |
|------|---------|
| Run release script | `.ci/release.sh` |
| Check current version | `grep '^version =' Cargo.toml \| head -1` |
| View recent commits | `git log v<CUR>..HEAD --oneline` |
| Check commits ahead | `git rev-list --count origin/master..HEAD` |
| Check shallow clone | `git rev-parse --is-shallow-repository` |
| Unshallow repo | `git fetch --unshallow origin && git fetch --tags origin` |
| Update version refs | `make update-version` |
| Update changelog | `make update-changelog` |
| Commit | `git commit -m "release: Version <VER>"` |
| Monitor CI | `gh run list --limit 5` |
