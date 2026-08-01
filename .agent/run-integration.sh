#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
git config user.name github-actions[bot]
git config user.email 41898282+github-actions[bot]@users.noreply.github.com

rm -rf ../pin-lifecycle
git worktree add ../pin-lifecycle origin/agent/fix-pin-token-lifecycle
cd ../pin-lifecycle
python3 - <<'PY'
from pathlib import Path

path = Path("soft-fido2-ctap/src/authenticator.rs")
text = path.read_text()
old = '''    #[test]
    fn test_pin_retry_exhaustion() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        // Exhaust retries
        for _ in 0..MAX_PIN_RETRIES {
            let _ = auth.verify_pin("wrong");
        }

        assert!(auth.is_pin_blocked());
        let result = auth.verify_pin("1234");
        assert_eq!(result, Err(StatusCode::PinBlocked));
    }
'''
new = '''    #[test]
    fn test_pin_auth_blocked_after_three_consecutive_failures() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        assert_eq!(auth.verify_pin("wrong"), Err(StatusCode::PinInvalid));
        assert_eq!(auth.verify_pin("wrong"), Err(StatusCode::PinInvalid));
        assert_eq!(auth.verify_pin("wrong"), Err(StatusCode::PinAuthBlocked));
        assert!(auth.is_pin_auth_blocked());
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES - 3);

        assert_eq!(auth.verify_pin("1234"), Err(StatusCode::PinAuthBlocked));
        assert_eq!(auth.pin_retries(), MAX_PIN_RETRIES - 3);
    }

    #[test]
    fn test_pin_retry_exhaustion_across_power_cycles() {
        let mut auth = create_test_authenticator();
        auth.set_pin("1234").unwrap();

        while auth.pin_retries() > 0 {
            let attempts_this_session = core::cmp::min(3, auth.pin_retries());
            for _ in 0..attempts_this_session {
                let _ = auth.verify_pin("wrong");
            }

            if auth.pin_retries() > 0 {
                assert!(auth.is_pin_auth_blocked());
                auth.pin_consecutive_failures = 0;
            }
        }

        assert!(auth.is_pin_blocked());
        assert_eq!(auth.verify_pin("1234"), Err(StatusCode::PinBlocked));
    }
'''
if old in text:
    path.write_text(text.replace(old, new, 1))
elif "fn test_pin_auth_blocked_after_three_consecutive_failures()" not in text:
    raise SystemExit("PIN retry tests are in an unexpected state")
PY
rm -f .github/workflows/agent-fix-pin-tests.yml .agent/pin-test-trigger
cargo fmt --all
git add -A
if ! git diff --cached --quiet; then
  git commit -m "test PIN auth blocking across device sessions"
  git push origin HEAD:agent/fix-pin-token-lifecycle
fi
PIN_SHA="$(git rev-parse HEAD)"

cd "$ROOT"
git merge --no-edit origin/master
git merge --no-edit "$PIN_SHA"
git merge --no-edit 079e695c1841945756f2583ce768efc8a594c11b
git merge --no-edit 6e10a3534441d003e28f055a0c97d5d3f4962ced
git merge --no-edit ee8f066eb64d532b11d47137539b592b942bf8bd
git merge --no-edit 317977c018276800e2f3ed48d6ae535bc1c5282f

rm -f \
  .github/workflows/agent-integrate-critical-fixes.yml \
  .github/workflows/agent-integration-runner.yml \
  .agent/integrate-trigger \
  .agent/run-integration.sh

git add -A
git commit -m "test integrated critical CTAP fixes"

sudo apt-get update
sudo apt-get install -y libudev-dev

cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings

git push origin HEAD:agent/all-critical-fixes
