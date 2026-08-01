from pathlib import Path

get_info = Path("soft-fido2-ctap/src/commands/get_info.rs")
text = get_info.read_text()

handle_anchor = """/// Handle authenticatorGetInfo command
///
/// This command requires no input and returns the authenticator's capabilities.
"""
version_gate = """const FIDO_2_0: &str = \"FIDO_2_0\";

/// Return only version identifiers whose mandatory feature set is complete.
///
/// FIDO_2_1 and FIDO_2_3 both require a complete hmac-secret implementation.
/// Until dual credential secrets are persisted for discoverable and wrapped
/// credentials, advertising either version would be a false conformance claim.
fn advertised_versions() -> Vec<String> {
    vec![FIDO_2_0.to_string()]
}

""" + handle_anchor
assert text.count(handle_anchor) == 1
text = text.replace(handle_anchor, version_gate, 1)

old_versions = """    // Versions (0x01) - required. There is no FIDO_2_2 version identifier.
    let versions = vec![\"FIDO_2_0\".to_string(), \"FIDO_2_1\".to_string()];
"""
new_versions = """    // Versions (0x01) - required. Version advertisement is a
    // conformance claim, so it is gated on mandatory feature completeness.
    let versions = advertised_versions();
"""
assert text.count(old_versions) == 1
text = text.replace(old_versions, new_versions, 1)

old_test = """        assert!(versions.contains(&\"FIDO_2_0\".to_string()));
        assert!(versions.contains(&\"FIDO_2_1\".to_string()));
        assert!(!versions.contains(&\"FIDO_2_2\".to_string()));
"""
new_test = """        assert_eq!(versions, vec![\"FIDO_2_0\".to_string()]);
        assert!(!versions.contains(&\"FIDO_2_1\".to_string()));
        assert!(!versions.contains(&\"FIDO_2_2\".to_string()));
        assert!(!versions.contains(&\"FIDO_2_3\".to_string()));
"""
assert text.count(old_test) == 1
text = text.replace(old_test, new_test, 1)

new_tests = r'''

    #[test]
    fn version_gate_is_fail_closed_until_mandatory_features_are_complete() {
        assert_eq!(advertised_versions(), vec!["FIDO_2_0".to_string()]);
    }
'''
last = text.rfind("\n}")
assert last != -1
text = text[:last] + new_tests + text[last:]
get_info.write_text(text)

readme = Path("README.md")
readme_text = readme.read_text()
readme_replacements = {
    "A pure Rust implementation of FIDO2/WebAuthn CTAP 2.0/2.1/2.2 protocol.":
        "A pure Rust implementation of a FIDO2/WebAuthn CTAP 2.0 authenticator core with selected CTAP 2.1 features.",
    "- **Full CTAP 2.0/2.1/2.2 Protocol** - Complete implementation of FIDO2 Authenticator Protocol":
        "- **CTAP 2.0 Core** - Registration, assertion, ClientPIN, credential management, and USB/UHID transport, with selected newer features",
    "- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/)":
        "- [FIDO2 CTAP 2.3 Specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/)",
}
for old, new in readme_replacements.items():
    assert old in readme_text, old
    readme_text = readme_text.replace(old, new, 1)
readme.write_text(readme_text)

commands = Path("soft-fido2-ctap/src/commands/mod.rs")
commands_text = commands.read_text()
old = "//! This module contains the implementations of all CTAP 2.0/2.1/2.2 commands."
new = "//! This module contains the implemented CTAP command handlers."
assert old in commands_text
commands.write_text(commands_text.replace(old, new, 1))
