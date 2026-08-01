from pathlib import Path

status_path = Path("soft-fido2-ctap/src/status.rs")
text = status_path.read_text()

replacements = {
    """    /// PIN required for this operation
    PinRequired = 0x36,
""": """    /// PIN/UV auth token required
    PuatRequired = 0x36,
""",
    """    /// PIN token expired
    PinTokenExpired = 0x38,

""": "",
    """    /// PIN/UV auth token required
    PuatRequired = 0x41,

""": "",
    """            Self::PinRequired => \"PIN required\",
""": """            Self::PuatRequired => \"PIN/UV auth token required\",
""",
    """            Self::PinTokenExpired => \"PIN token expired\",
""": "",
    """            Self::PuatRequired => \"PIN/UV auth token required\",
""": "",
    """            0x36 => Self::PinRequired,
""": """            0x36 => Self::PuatRequired,
""",
    """            0x38 => Self::PinTokenExpired,
""": "",
    """            0x41 => Self::PuatRequired,
""": "",
    """            \"PinRequired\" => Ok(Self::PinRequired),
""": """            \"PinRequired\" => Ok(Self::PuatRequired),
""",
    """            \"PinTokenExpired\" => Ok(Self::PinTokenExpired),
""": """            \"PinTokenExpired\" => Ok(Self::PinAuthInvalid),
""",
}

for old, new in replacements.items():
    assert text.count(old) == 1, repr(old)
    text = text.replace(old, new, 1)

impl_anchor = """impl StatusCode {
    /// Convert status code to byte value
"""
impl_replacement = """impl StatusCode {
    /// Deprecated CTAP 2.0 source-level alias. Serializes as
    /// CTAP2_ERR_PUAT_REQUIRED (0x36) under the modern registry.
    #[allow(non_upper_case_globals)]
    #[deprecated(note = \"use StatusCode::PuatRequired\")]
    pub const PinRequired: Self = Self::PuatRequired;

    /// Deprecated CTAP 2.0 source-level alias. The 0x38 wire value is
    /// reserved in modern CTAP, so expired tokens map to PIN_AUTH_INVALID.
    #[allow(non_upper_case_globals)]
    #[deprecated(note = \"use StatusCode::PinAuthInvalid\")]
    pub const PinTokenExpired: Self = Self::PinAuthInvalid;

    /// Convert status code to byte value
"""
assert text.count(impl_anchor) == 1
text = text.replace(impl_anchor, impl_replacement, 1)

new_tests = r'''

    #[test]
    fn ctap_2_3_pin_uv_status_values_are_wire_correct() {
        assert_eq!(StatusCode::PuatRequired.to_u8(), 0x36);
        assert_eq!(StatusCode::UnauthorizedPermission.to_u8(), 0x40);
        assert_eq!(StatusCode::from_u8(0x36), StatusCode::PuatRequired);
    }

    #[test]
    fn reserved_and_non_standard_pin_uv_values_are_not_accepted() {
        assert_eq!(StatusCode::from_u8(0x38), StatusCode::Other);
        assert_eq!(StatusCode::from_u8(0x41), StatusCode::Other);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_source_aliases_use_modern_wire_values() {
        assert_eq!(StatusCode::PinRequired.to_u8(), 0x36);
        assert_eq!(StatusCode::PinTokenExpired.to_u8(), 0x33);
    }
'''
last = text.rfind("\n}")
assert last != -1
text = text[:last] + new_tests + text[last:]
status_path.write_text(text)

for path in Path(".").rglob("*.rs"):
    if path == status_path:
        continue
    source = path.read_text()
    updated = source.replace("StatusCode::PinRequired", "StatusCode::PuatRequired")
    updated = updated.replace("StatusCode::PinTokenExpired", "StatusCode::PinAuthInvalid")
    if updated != source:
        path.write_text(updated)
