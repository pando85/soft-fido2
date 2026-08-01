from pathlib import Path
import re

R=Path('.')
def edit(p,*repls):
 s=(R/p).read_text()
 for old,new in repls:
  n=s.count(old)
  if n!=1: raise SystemExit(f'{p}: expected 1 match, got {n}: {old[:80]!r}')
  s=s.replace(old,new,1)
 (R/p).write_text(s)

# CTAP types and persisted credential metadata.
p='soft-fido2-ctap/src/types.rs'
enum='''/// Backup eligibility and state for a credential.\n///\n/// Models the three valid WebAuthn combinations, making `BE=0, BS=1`\n/// unrepresentable.\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]\n#[serde(rename_all = "camelCase")]\npub enum CredentialBackupState {\n    /// Single-device credential (`BE=0, BS=0`).\n    #[default]\n    NotEligible,\n    /// Multi-device credential that is not currently backed up (`BE=1, BS=0`).\n    Eligible,\n    /// Multi-device credential that is currently backed up (`BE=1, BS=1`).\n    BackedUp,\n}\n\nimpl CredentialBackupState {\n    /// Authenticator-data flag bits for this state.\n    pub const fn flags(self) -> u8 {\n        match self {\n            Self::NotEligible => 0,\n            Self::Eligible => auth_data_flags::BE,\n            Self::BackedUp => auth_data_flags::BE | auth_data_flags::BS,\n        }\n    }\n\n    pub const fn is_eligible(self) -> bool {\n        !matches!(self, Self::NotEligible)\n    }\n\n    pub const fn is_backed_up(self) -> bool {\n        matches!(self, Self::BackedUp)\n    }\n}\n\n'''
edit(p,
('    /// User Verified (UV) - bit 2\n    pub const UV: u8 = 0x04;\n','    /// User Verified (UV) - bit 2\n    pub const UV: u8 = 0x04;\n    /// Backup Eligible (BE) - bit 3\n    pub const BE: u8 = 0x08;\n    /// Backup State (BS) - bit 4\n    pub const BS: u8 = 0x10;\n'),
('/// Credential protection policy\n',enum+'/// Credential protection policy\n'),
('    /// Whether this is a discoverable credential\n    pub discoverable: bool,\n\n    /// User display name\n','    /// Whether this is a discoverable credential\n    pub discoverable: bool,\n\n    /// Backup eligibility and current backup state.\n    pub backup_state: CredentialBackupState,\n\n    /// User display name\n'),
('        map.serialize_entry("discoverable", &self.discoverable)?;\n        map.serialize_entry("user_display_name", &self.user_display_name)?;\n','        map.serialize_entry("discoverable", &self.discoverable)?;\n        map.serialize_entry("backup_state", &self.backup_state)?;\n        map.serialize_entry("user_display_name", &self.user_display_name)?;\n'),
('        let mut discoverable: Option<bool> = None;\n        let mut user_display_name: Option<Option<String>> = None;\n','        let mut discoverable: Option<bool> = None;\n        let mut backup_state: Option<CredentialBackupState> = None;\n        let mut user_display_name: Option<Option<String>> = None;\n'),
('                "user_display_name" => match v {\n','                "backup_state" => {\n                    backup_state = Some(crate::cbor::from_value(&v).map_err(serde::de::Error::custom)?);\n                }\n                "user_display_name" => match v {\n'),
('            user_display_name: user_display_name.unwrap_or(None),\n            cred_random: cred_random.unwrap_or(None),\n','            backup_state: backup_state.unwrap_or_default(),\n            user_display_name: user_display_name.unwrap_or(None),\n            cred_random: cred_random.unwrap_or(None),\n'),
('            discoverable,\n            user_display_name,\n            cred_random,\n','            discoverable,\n            backup_state: CredentialBackupState::NotEligible,\n            user_display_name,\n            cred_random,\n'),
('    #[test]\n    fn test_cose_algorithm() {','    #[test]\n    fn test_credential_backup_state_flags() {\n        assert_eq!(CredentialBackupState::NotEligible.flags(), 0);\n        assert_eq!(CredentialBackupState::Eligible.flags(), auth_data_flags::BE);\n        assert_eq!(CredentialBackupState::BackedUp.flags(), auth_data_flags::BE | auth_data_flags::BS);\n    }\n\n    #[test]\n    fn test_cose_algorithm() {'))

# CTAP authenticator configuration.
p='soft-fido2-ctap/src/authenticator.rs'
edit(p,
('    types::PinState,\n','    types::{CredentialBackupState, PinState},\n'),
('    /// Use constant signature counter (for privacy)\n','    /// Backup state assigned to newly created stored credentials.\n    pub default_credential_backup_state: CredentialBackupState,\n\n    /// Use constant signature counter (for privacy)\n'),
('            force_resident_keys: true,\n            constant_sign_count: false,\n','            force_resident_keys: true,\n            default_credential_backup_state: CredentialBackupState::NotEligible,\n            constant_sign_count: false,\n'),
('    /// Use constant signature counter (for privacy)\n    ///\n    /// When enabled, the signature counter will not increment and remain at 0.\n','    /// Set the backup state assigned to newly created stored credentials.\n    pub fn with_default_credential_backup_state(mut self, state: CredentialBackupState) -> Self {\n        self.default_credential_backup_state = state;\n        self\n    }\n\n    /// Use constant signature counter (for privacy)\n    ///\n    /// When enabled, the signature counter will not increment and remain at 0.\n'))

# MakeCredential: resolve once, persist for stored credentials, emit same flags.
p='soft-fido2-ctap/src/commands/make_credential.rs'
edit(p,
('        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,\n        auth_data_flags,\n','        CredentialBackupState, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,\n        RelyingParty, User, auth_data_flags,\n'),
('    // Step 17: Create credential (resident or non-resident)\n    let credential_id = create_credential(\n','    // Step 17: Resolve backup properties and create the credential. Wrapped\n    // non-resident credentials use the legacy format and remain single-device.\n    let backup_state = if options.rk || auth.config().force_resident_keys {\n        auth.config().default_credential_backup_state\n    } else {\n        CredentialBackupState::NotEligible\n    };\n    let credential_id = create_credential(\n'),
('        &user,\n        alg,\n    )?;\n\n    // Step 18: Generate attestation\n','        &user,\n        alg,\n        backup_state,\n    )?;\n\n    // Step 18: Generate attestation\n'),
('        response_state.uv,\n        auth.config().aaguid,\n','        response_state.uv,\n        backup_state,\n        auth.config().aaguid,\n'),
('    user: &User,\n    algorithm: i32,\n) -> Result<Vec<u8>> {\n','    user: &User,\n    algorithm: i32,\n    backup_state: CredentialBackupState,\n) -> Result<Vec<u8>> {\n'),
('            discoverable: true,\n            cred_protect: cred_protect_value,\n','            discoverable: true,\n            backup_state,\n            cred_protect: cred_protect_value,\n'),
('    uv: bool,\n    aaguid: [u8; 16],\n','    uv: bool,\n    backup_state: CredentialBackupState,\n    aaguid: [u8; 16],\n'),
('    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    flags |= auth_data_flags::AT;\n','    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    flags |= backup_state.flags();\n    flags |= auth_data_flags::AT;\n'))

# GetAssertion: legacy wrapped credentials are NotEligible; stored credentials retain state.
p='soft-fido2-ctap/src/commands/get_assertion.rs'
edit(p,
('    types::{PublicKeyCredentialDescriptor, auth_data_flags},\n','    types::{CredentialBackupState, PublicKeyCredentialDescriptor, auth_data_flags},\n'),
('                    discoverable: false,\n                    cred_protect: 0,\n','                    discoverable: false,\n                    backup_state: CredentialBackupState::NotEligible,\n                    cred_protect: 0,\n'),
('        response_state.uv,\n        new_sign_count,\n','        response_state.uv,\n        selected_cred.backup_state,\n        new_sign_count,\n'),
('    uv: bool,\n    sign_count: u32,\n','    uv: bool,\n    backup_state: CredentialBackupState,\n    sign_count: u32,\n'),
('    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    if extensions.is_some() {\n','    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    flags |= backup_state.flags();\n    if extensions.is_some() {\n'),
('        let auth_data = build_authenticator_data("example.com", true, false, 42, None).unwrap();\n','        let auth_data = build_authenticator_data(\n            "example.com", true, false, CredentialBackupState::NotEligible, 42, None,\n        ).unwrap();\n'),
('        let auth_data = build_authenticator_data("example.com", true, true, 1, None).unwrap();\n','        let auth_data = build_authenticator_data(\n            "example.com", true, true, CredentialBackupState::NotEligible, 1, None,\n        ).unwrap();\n'),
('    }\n}\n','    }\n\n    #[test]\n    fn test_build_authenticator_data_with_backup_flags() {\n        let eligible = build_authenticator_data(\n            "example.com", true, false, CredentialBackupState::Eligible, 0, None,\n        ).unwrap();\n        assert_eq!(eligible[32], auth_data_flags::UP | auth_data_flags::BE);\n        let backed_up = build_authenticator_data(\n            "example.com", true, false, CredentialBackupState::BackedUp, 0, None,\n        ).unwrap();\n        assert_eq!(backed_up[32], auth_data_flags::UP | auth_data_flags::BE | auth_data_flags::BS);\n    }\n}\n'))

# GetNextAssertion must use each selected credential's properties.
p='soft-fido2-ctap/src/commands/get_next_assertion.rs'
edit(p,
('    types::{PublicKeyCredentialDescriptor, auth_data_flags},\n','    types::{CredentialBackupState, PublicKeyCredentialDescriptor, auth_data_flags},\n'),
('    let auth_data =\n        build_authenticator_data(&context.rp_id, context.up, context.uv, new_sign_count);\n','    let auth_data = build_authenticator_data(\n        &context.rp_id, context.up, context.uv, credential.backup_state, new_sign_count,\n    );\n'),
('fn build_authenticator_data(rp_id: &str, up: bool, uv: bool, sign_count: u32) -> Vec<u8> {\n','fn build_authenticator_data(\n    rp_id: &str, up: bool, uv: bool, backup_state: CredentialBackupState, sign_count: u32,\n) -> Vec<u8> {\n'),
('    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    auth_data.push(flags);\n','    if uv {\n        flags |= auth_data_flags::UV;\n    }\n    flags |= backup_state.flags();\n    auth_data.push(flags);\n'),
('    }\n}\n','    }\n\n    #[test]\n    fn test_get_next_assertion_backup_flags() {\n        let data = build_authenticator_data(\n            "example.com", true, false, CredentialBackupState::BackedUp, 0,\n        );\n        assert_eq!(data[32], auth_data_flags::UP | auth_data_flags::BE | auth_data_flags::BS);\n    }\n}\n'))

# CTAP export.
p='soft-fido2-ctap/src/lib.rs'
edit(p,('    CoseAlgorithm, CredProtect, Credential, PinState, PublicKeyCredentialDescriptor,\n','    CoseAlgorithm, CredProtect, Credential, CredentialBackupState, PinState,\n    PublicKeyCredentialDescriptor,\n'))

# High-level credential conversion. Keep backup state in Extensions to avoid a second
# top-level credential representation while still preserving it through callbacks.
p='soft-fido2/src/types.rs'
edit(p,
('pub use soft_fido2_ctap::types::{RelyingParty, User};\n','pub use soft_fido2_ctap::types::{CredentialBackupState, RelyingParty, User};\n'),
('    /// HMAC secret credential random (32 bytes)\n','    /// Backup eligibility and current backup state.\n    #[serde(default)]\n    pub backup_state: CredentialBackupState,\n    /// HMAC secret credential random (32 bytes)\n'),
('    /// Credential random for hmac-secret extension (32 bytes)\n    pub cred_random: Option<&\'a SecBytes>,\n','    /// Backup eligibility and current backup state.\n    pub backup_state: &\'a CredentialBackupState,\n    /// Credential random for hmac-secret extension (32 bytes)\n    pub cred_random: Option<&\'a SecBytes>,\n'),
('                hmac_secret: None,\n                cred_random: self.cred_random.cloned(),\n','                hmac_secret: None,\n                backup_state: *self.backup_state,\n                cred_random: self.cred_random.cloned(),\n'),
('                hmac_secret: cred.cred_random.is_some().then_some(true),\n                cred_random: cred.cred_random,\n','                hmac_secret: cred.cred_random.is_some().then_some(true),\n                backup_state: cred.backup_state,\n                cred_random: cred.cred_random,\n'),
('            cred_protect: cred.extensions.cred_protect.unwrap_or(1),\n            cred_random: cred.extensions.cred_random,\n','            cred_protect: cred.extensions.cred_protect.unwrap_or(1),\n            backup_state: cred.extensions.backup_state,\n            cred_random: cred.extensions.cred_random,\n'))

# High-level config and callback adapter.
p='soft-fido2/src/authenticator.rs'
edit(p,
('use crate::types::{Credential, CredentialRef};\n','use crate::types::{Credential, CredentialBackupState, CredentialRef};\n'),
('            cred_protect: Some(&credential.cred_protect),\n            cred_random: credential.cred_random.as_ref(),\n','            cred_protect: Some(&credential.cred_protect),\n            backup_state: &credential.backup_state,\n            cred_random: credential.cred_random.as_ref(),\n'),
('    pub constant_sign_count: bool,\n    pub max_msg_size: usize,\n','    pub constant_sign_count: bool,\n    /// Backup state assigned to newly created stored credentials.\n    pub default_credential_backup_state: CredentialBackupState,\n    pub max_msg_size: usize,\n'),
('            constant_sign_count: false,\n            max_msg_size: MAX_CTAP_MESSAGE_SIZE,\n','            constant_sign_count: false,\n            default_credential_backup_state: CredentialBackupState::NotEligible,\n            max_msg_size: MAX_CTAP_MESSAGE_SIZE,\n'),
('    constant_sign_count: bool,\n    max_msg_size: usize,\n','    constant_sign_count: bool,\n    default_credential_backup_state: CredentialBackupState,\n    max_msg_size: usize,\n'),
('            constant_sign_count: false,\n            max_msg_size: MAX_CTAP_MESSAGE_SIZE,\n','            constant_sign_count: false,\n            default_credential_backup_state: CredentialBackupState::NotEligible,\n            max_msg_size: MAX_CTAP_MESSAGE_SIZE,\n'),
('    pub fn max_msg_size(mut self, size: usize) -> Self {\n','    /// Set the backup state assigned to newly created stored credentials.\n    pub fn default_credential_backup_state(mut self, state: CredentialBackupState) -> Self {\n        self.default_credential_backup_state = state;\n        self\n    }\n\n    pub fn max_msg_size(mut self, size: usize) -> Self {\n'),
('            constant_sign_count: self.constant_sign_count,\n            max_msg_size: self.max_msg_size,\n','            constant_sign_count: self.constant_sign_count,\n            default_credential_backup_state: self.default_credential_backup_state,\n            max_msg_size: self.max_msg_size,\n'),
('            .with_constant_sign_count(config.constant_sign_count)\n            .with_max_msg_size(config.max_msg_size)\n','            .with_constant_sign_count(config.constant_sign_count)\n            .with_default_credential_backup_state(config.default_credential_backup_state)\n            .with_max_msg_size(config.max_msg_size)\n'))

p='soft-fido2/src/lib.rs'
edit(p,('pub use types::{Credential, CredentialRef, Extensions, RelyingParty, User};\n','pub use types::{\n    Credential, CredentialBackupState, CredentialRef, Extensions, RelyingParty, User,\n};\n'))

# Add the new field to any remaining CTAP Credential literal, using the safe legacy default.
for p in (R/'soft-fido2-ctap').rglob('*.rs'):
 s=p.read_text(); out=[]; pos=0; changed=False
 while (m:=re.search(r'(?<!struct )Credential\s*\{',s[pos:])):
  a=pos+m.start(); b=pos+m.end()-1; depth=0; end=None
  for i in range(b,len(s)):
   depth += (s[i]=='{')-(s[i]=='}')
   if depth==0: end=i+1; break
  if end is None: raise SystemExit(f'unclosed Credential literal in {p}')
  block=s[a:end]; out.append(s[pos:a])
  if 'backup_state:' not in block and 'cred_random:' in block:
   block,n=re.subn(r'(?m)^(\s*)cred_random:',r'\1backup_state: crate::types::CredentialBackupState::NotEligible,\n\1cred_random:',block,count=1)
   if n!=1: raise SystemExit(f'cannot patch Credential literal in {p}')
   changed=True
  out.append(block); pos=end
 out.append(s[pos:])
 if changed: p.write_text(''.join(out))

print('applied BE/BS support')
