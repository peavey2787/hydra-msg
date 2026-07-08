use std::collections::BTreeMap;

use hydra_core::{types::IdentityFingerprint, ML_DSA_65_SIG_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::identity_store::derive_device_fingerprint;
use crate::{AppError, AppResult, DeviceFingerprint, DeviceId, IdentityStore, PublicIdentity};

const DEVICE_LINK_VERSION: u8 = 1;
const DEFAULT_GROUP_REKEY_REQUIRED: bool = true;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinkedDeviceRecord {
    pub device_id: DeviceId,
    pub device_fingerprint: DeviceFingerprint,
    pub identity_fingerprint: IdentityFingerprint,
    pub public_identity: PublicIdentity,
    pub identity_generation: u64,
    pub linked_at_ms: u64,
    pub status: DeviceStatus,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceLinkPolicy {
    /// Allow linking a new device that uses the same ML-DSA identity fingerprint
    /// as an already-active device. This is false by default so recovery/import
    /// cannot silently clone an active device identity.
    pub allow_existing_identity_clone: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceLinkRequest {
    account_identity_fingerprint: IdentityFingerprint,
    requester_device_id: DeviceId,
    requester_device_fingerprint: DeviceFingerprint,
    requester_identity_generation: u64,
    requester_public_identity: PublicIdentity,
    created_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 32],
    request_signature: [u8; ML_DSA_65_SIG_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkApproval {
    request_digest: [u8; 64],
    approved_device_id: DeviceId,
    approved_device_fingerprint: DeviceFingerprint,
    approved_identity_fingerprint: IdentityFingerprint,
    approved_identity_generation: u64,
    approver_device_id: DeviceId,
    approver_device_fingerprint: DeviceFingerprint,
    approved_at_ms: u64,
    expires_at_ms: u64,
    allow_existing_identity_clone: bool,
    group_rekey_required_on_future_revocation: bool,
    approval_signature: [u8; ML_DSA_65_SIG_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevocation {
    pub target_device_id: DeviceId,
    pub target_device_fingerprint: DeviceFingerprint,
    pub target_identity_fingerprint: IdentityFingerprint,
    pub revoked_by_device_id: DeviceId,
    pub revoked_at_ms: u64,
    pub group_rekey_required: bool,
}

/// Per-account app device registry.
///
/// The registry is intentionally explicit: a new device must produce a signed
/// request, an already-active device must sign an approval, and revocation
/// returns a group-rekey-required signal for any groups that used the removed
/// device/subidentity.
pub struct DeviceRegistry {
    account_identity_fingerprint: IdentityFingerprint,
    devices: BTreeMap<DeviceId, LinkedDeviceRecord>,
}

impl DeviceRegistry {
    pub fn new(primary: &IdentityStore, linked_at_ms: u64) -> AppResult<Self> {
        primary.identity()?;
        let public_identity = primary.public_identity();
        let record = LinkedDeviceRecord {
            device_id: primary.device_id(),
            device_fingerprint: primary.device_fingerprint(),
            identity_fingerprint: public_identity.fingerprint(),
            public_identity: public_identity.clone(),
            identity_generation: primary.generation(),
            linked_at_ms,
            status: DeviceStatus::Active,
            revoked_at_ms: None,
        };
        let mut devices = BTreeMap::new();
        devices.insert(record.device_id, record);
        Ok(Self {
            account_identity_fingerprint: public_identity.fingerprint(),
            devices,
        })
    }

    pub fn approve_link_request(
        &self,
        approver: &IdentityStore,
        request: &DeviceLinkRequest,
        now_ms: u64,
        policy: DeviceLinkPolicy,
    ) -> AppResult<DeviceLinkApproval> {
        let approver_identity = approver.identity()?;
        let approver_record =
            self.require_active_device_generation(approver.device_id(), approver.generation())?;
        if approver_record.device_fingerprint != approver.device_fingerprint() {
            return Err(AppError::InvalidState(
                "approver device fingerprint is stale",
            ));
        }
        request.verify_for_account(self.account_identity_fingerprint, now_ms)?;
        if self.devices.contains_key(&request.requester_device_id) {
            return Err(AppError::InvalidState("device is already linked"));
        }
        if self.identity_clone_exists(request.requester_identity_fingerprint())
            && !policy.allow_existing_identity_clone
        {
            return Err(AppError::InvalidState(
                "link request would clone an active device identity without explicit permission",
            ));
        }
        let request_digest = request.digest();
        let approval_core = ApprovalCore {
            request_digest,
            approved_device_id: request.requester_device_id,
            approved_device_fingerprint: request.requester_device_fingerprint,
            approved_identity_fingerprint: request.requester_identity_fingerprint(),
            approved_identity_generation: request.requester_identity_generation,
            approver_device_id: approver.device_id(),
            approver_device_fingerprint: approver.device_fingerprint(),
            approved_at_ms: now_ms,
            expires_at_ms: request.expires_at_ms,
            allow_existing_identity_clone: policy.allow_existing_identity_clone,
            group_rekey_required_on_future_revocation: DEFAULT_GROUP_REKEY_REQUIRED,
        };
        let digest = approval_core.digest();
        let approval_signature =
            RustCryptoBackend::mldsa65_sign(approver_identity.signing_key(), &digest)?;
        Ok(approval_core.into_approval(approval_signature))
    }

    pub fn install_approved_device(
        &mut self,
        request: &DeviceLinkRequest,
        approval: &DeviceLinkApproval,
        now_ms: u64,
    ) -> AppResult<LinkedDeviceRecord> {
        request.verify_for_account(self.account_identity_fingerprint, now_ms)?;
        approval.verify_for_request(request, self, now_ms)?;
        if self.devices.contains_key(&request.requester_device_id) {
            return Err(AppError::InvalidState("device is already linked"));
        }
        if self.identity_clone_exists(request.requester_identity_fingerprint())
            && !approval.allow_existing_identity_clone
        {
            return Err(AppError::InvalidState(
                "approval does not permit active identity cloning",
            ));
        }
        let record = LinkedDeviceRecord {
            device_id: request.requester_device_id,
            device_fingerprint: request.requester_device_fingerprint,
            identity_fingerprint: request.requester_identity_fingerprint(),
            public_identity: request.requester_public_identity.clone(),
            identity_generation: request.requester_identity_generation,
            linked_at_ms: approval.approved_at_ms,
            status: DeviceStatus::Active,
            revoked_at_ms: None,
        };
        self.devices.insert(record.device_id, record.clone());
        Ok(record)
    }

    pub fn revoke_device(
        &mut self,
        approver: &IdentityStore,
        target_device_id: DeviceId,
        revoked_at_ms: u64,
    ) -> AppResult<DeviceRevocation> {
        approver.identity()?;
        self.require_active_device_generation(approver.device_id(), approver.generation())?;
        if approver.device_id() == target_device_id {
            return Err(AppError::InvalidInput(
                "use a different active device to revoke this device",
            ));
        }
        let active_count = self
            .devices
            .values()
            .filter(|record| record.status == DeviceStatus::Active)
            .count();
        if active_count <= 1 {
            return Err(AppError::InvalidState(
                "cannot revoke the last active device",
            ));
        }
        let target = self
            .devices
            .get_mut(&target_device_id)
            .ok_or(AppError::InvalidInput("target device is not linked"))?;
        if target.status == DeviceStatus::Revoked {
            return Err(AppError::InvalidState("target device is already revoked"));
        }
        target.status = DeviceStatus::Revoked;
        target.revoked_at_ms = Some(revoked_at_ms);
        Ok(DeviceRevocation {
            target_device_id,
            target_device_fingerprint: target.device_fingerprint,
            target_identity_fingerprint: target.identity_fingerprint,
            revoked_by_device_id: approver.device_id(),
            revoked_at_ms,
            group_rekey_required: DEFAULT_GROUP_REKEY_REQUIRED,
        })
    }

    pub fn require_active_device(&self, device_id: DeviceId) -> AppResult<&LinkedDeviceRecord> {
        let record = self
            .devices
            .get(&device_id)
            .ok_or(AppError::InvalidInput("device is not linked"))?;
        if record.status == DeviceStatus::Active {
            Ok(record)
        } else {
            Err(AppError::InvalidState("device is revoked"))
        }
    }

    pub fn require_active_device_generation(
        &self,
        device_id: DeviceId,
        identity_generation: u64,
    ) -> AppResult<&LinkedDeviceRecord> {
        let record = self.require_active_device(device_id)?;
        if record.identity_generation == identity_generation {
            Ok(record)
        } else {
            Err(AppError::InvalidState("device generation is stale"))
        }
    }

    #[must_use]
    pub const fn account_identity_fingerprint(&self) -> IdentityFingerprint {
        self.account_identity_fingerprint
    }

    #[must_use]
    pub fn devices(&self) -> Vec<&LinkedDeviceRecord> {
        self.devices.values().collect()
    }

    #[must_use]
    pub fn active_devices(&self) -> Vec<&LinkedDeviceRecord> {
        self.devices
            .values()
            .filter(|record| record.status == DeviceStatus::Active)
            .collect()
    }

    #[must_use]
    pub fn device(&self, device_id: DeviceId) -> Option<&LinkedDeviceRecord> {
        self.devices.get(&device_id)
    }

    fn identity_clone_exists(&self, identity_fingerprint: IdentityFingerprint) -> bool {
        self.devices.values().any(|record| {
            record.status == DeviceStatus::Active
                && record.identity_fingerprint == identity_fingerprint
        })
    }
}

impl DeviceLinkRequest {
    pub fn create(
        requester: &IdentityStore,
        account_identity_fingerprint: IdentityFingerprint,
        created_at_ms: u64,
        ttl_ms: u64,
    ) -> AppResult<Self> {
        if ttl_ms == 0 {
            return Err(AppError::InvalidInput("device link TTL must be nonzero"));
        }
        let expires_at_ms = created_at_ms
            .checked_add(ttl_ms)
            .ok_or(AppError::InvalidInput("device link expiration overflow"))?;
        let nonce = crate::random::random_array()?;
        let public_identity = requester.public_identity();
        let core = RequestCore {
            account_identity_fingerprint,
            requester_device_id: requester.device_id(),
            requester_device_fingerprint: requester.device_fingerprint(),
            requester_identity_generation: requester.generation(),
            requester_identity_fingerprint: public_identity.fingerprint(),
            requester_public_key: public_identity.public_key().0,
            created_at_ms,
            expires_at_ms,
            nonce,
        };
        let digest = core.digest();
        let signature =
            RustCryptoBackend::mldsa65_sign(requester.identity()?.signing_key(), &digest)?;
        Ok(Self {
            account_identity_fingerprint,
            requester_device_id: requester.device_id(),
            requester_device_fingerprint: requester.device_fingerprint(),
            requester_identity_generation: requester.generation(),
            requester_public_identity: public_identity,
            created_at_ms,
            expires_at_ms,
            nonce,
            request_signature: signature,
        })
    }

    #[must_use]
    pub const fn account_identity_fingerprint(&self) -> IdentityFingerprint {
        self.account_identity_fingerprint
    }

    #[must_use]
    pub const fn requester_device_id(&self) -> DeviceId {
        self.requester_device_id
    }

    #[must_use]
    pub const fn requester_device_fingerprint(&self) -> DeviceFingerprint {
        self.requester_device_fingerprint
    }

    #[must_use]
    pub const fn requester_identity_generation(&self) -> u64 {
        self.requester_identity_generation
    }

    #[must_use]
    pub fn requester_public_identity(&self) -> &PublicIdentity {
        &self.requester_public_identity
    }

    #[must_use]
    pub fn requester_identity_fingerprint(&self) -> IdentityFingerprint {
        self.requester_public_identity.fingerprint()
    }

    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub fn request_signature(&self) -> &[u8; ML_DSA_65_SIG_SIZE] {
        &self.request_signature
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 64] {
        self.core().digest()
    }

    fn verify_for_account(
        &self,
        account_identity_fingerprint: IdentityFingerprint,
        now_ms: u64,
    ) -> AppResult<()> {
        if self.account_identity_fingerprint != account_identity_fingerprint {
            return Err(AppError::InvalidInput(
                "device link request targets a different account",
            ));
        }
        if self.created_at_ms >= self.expires_at_ms || now_ms > self.expires_at_ms {
            return Err(AppError::InvalidState("device link request is stale"));
        }
        if derive_device_fingerprint(
            self.requester_device_id,
            self.requester_identity_fingerprint(),
        ) != self.requester_device_fingerprint
        {
            return Err(AppError::InvalidInput(
                "device link request has invalid device fingerprint",
            ));
        }
        RustCryptoBackend::mldsa65_verify(
            &self.requester_public_identity.verification_key_for_group(),
            &self.digest(),
            &self.request_signature,
        )?;
        Ok(())
    }

    fn core(&self) -> RequestCore {
        RequestCore {
            account_identity_fingerprint: self.account_identity_fingerprint,
            requester_device_id: self.requester_device_id,
            requester_device_fingerprint: self.requester_device_fingerprint,
            requester_identity_generation: self.requester_identity_generation,
            requester_identity_fingerprint: self.requester_identity_fingerprint(),
            requester_public_key: self.requester_public_identity.public_key().0,
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
            nonce: self.nonce,
        }
    }
}

impl DeviceLinkApproval {
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 64] {
        self.request_digest
    }

    #[must_use]
    pub const fn approved_device_id(&self) -> DeviceId {
        self.approved_device_id
    }

    #[must_use]
    pub const fn approver_device_id(&self) -> DeviceId {
        self.approver_device_id
    }

    #[must_use]
    pub const fn approved_at_ms(&self) -> u64 {
        self.approved_at_ms
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn allows_existing_identity_clone(&self) -> bool {
        self.allow_existing_identity_clone
    }

    #[must_use]
    pub const fn group_rekey_required_on_future_revocation(&self) -> bool {
        self.group_rekey_required_on_future_revocation
    }

    fn verify_for_request(
        &self,
        request: &DeviceLinkRequest,
        registry: &DeviceRegistry,
        now_ms: u64,
    ) -> AppResult<()> {
        if now_ms > self.expires_at_ms || self.request_digest != request.digest() {
            return Err(AppError::InvalidState(
                "device link approval is stale or mismatched",
            ));
        }
        if self.approved_device_id != request.requester_device_id
            || self.approved_device_fingerprint != request.requester_device_fingerprint
            || self.approved_identity_fingerprint != request.requester_identity_fingerprint()
            || self.approved_identity_generation != request.requester_identity_generation
        {
            return Err(AppError::InvalidInput(
                "device link approval does not match request",
            ));
        }
        let approver = registry.require_active_device(self.approver_device_id)?;
        if approver.device_fingerprint != self.approver_device_fingerprint {
            return Err(AppError::InvalidState(
                "approver device fingerprint is stale",
            ));
        }
        RustCryptoBackend::mldsa65_verify(
            &approver.public_identity.verification_key_for_group(),
            &self.core().digest(),
            &self.approval_signature,
        )?;
        Ok(())
    }

    fn core(&self) -> ApprovalCore {
        ApprovalCore {
            request_digest: self.request_digest,
            approved_device_id: self.approved_device_id,
            approved_device_fingerprint: self.approved_device_fingerprint,
            approved_identity_fingerprint: self.approved_identity_fingerprint,
            approved_identity_generation: self.approved_identity_generation,
            approver_device_id: self.approver_device_id,
            approver_device_fingerprint: self.approver_device_fingerprint,
            approved_at_ms: self.approved_at_ms,
            expires_at_ms: self.expires_at_ms,
            allow_existing_identity_clone: self.allow_existing_identity_clone,
            group_rekey_required_on_future_revocation: self
                .group_rekey_required_on_future_revocation,
        }
    }
}

struct RequestCore {
    account_identity_fingerprint: IdentityFingerprint,
    requester_device_id: DeviceId,
    requester_device_fingerprint: DeviceFingerprint,
    requester_identity_generation: u64,
    requester_identity_fingerprint: IdentityFingerprint,
    requester_public_key: [u8; hydra_core::ML_DSA_65_VK_SIZE],
    created_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; 32],
}

impl RequestCore {
    fn digest(&self) -> [u8; 64] {
        let mut input = Vec::with_capacity(256 + self.requester_public_key.len());
        input.extend_from_slice(b"HYDRA-MSG/app/device-link/request/v1");
        input.push(DEVICE_LINK_VERSION);
        input.extend_from_slice(&self.account_identity_fingerprint.0);
        input.extend_from_slice(&self.requester_device_id.0);
        input.extend_from_slice(&self.requester_device_fingerprint.0);
        input.extend_from_slice(&self.requester_identity_generation.to_be_bytes());
        input.extend_from_slice(&self.requester_identity_fingerprint.0);
        input.extend_from_slice(&self.requester_public_key);
        input.extend_from_slice(&self.created_at_ms.to_be_bytes());
        input.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        input.extend_from_slice(&self.nonce);
        RustCryptoBackend::sha3_512(&input)
    }
}

struct ApprovalCore {
    request_digest: [u8; 64],
    approved_device_id: DeviceId,
    approved_device_fingerprint: DeviceFingerprint,
    approved_identity_fingerprint: IdentityFingerprint,
    approved_identity_generation: u64,
    approver_device_id: DeviceId,
    approver_device_fingerprint: DeviceFingerprint,
    approved_at_ms: u64,
    expires_at_ms: u64,
    allow_existing_identity_clone: bool,
    group_rekey_required_on_future_revocation: bool,
}

impl ApprovalCore {
    fn digest(&self) -> [u8; 64] {
        let mut input = Vec::with_capacity(320);
        input.extend_from_slice(b"HYDRA-MSG/app/device-link/approval/v1");
        input.push(DEVICE_LINK_VERSION);
        input.extend_from_slice(&self.request_digest);
        input.extend_from_slice(&self.approved_device_id.0);
        input.extend_from_slice(&self.approved_device_fingerprint.0);
        input.extend_from_slice(&self.approved_identity_fingerprint.0);
        input.extend_from_slice(&self.approved_identity_generation.to_be_bytes());
        input.extend_from_slice(&self.approver_device_id.0);
        input.extend_from_slice(&self.approver_device_fingerprint.0);
        input.extend_from_slice(&self.approved_at_ms.to_be_bytes());
        input.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        input.push(u8::from(self.allow_existing_identity_clone));
        input.push(u8::from(self.group_rekey_required_on_future_revocation));
        RustCryptoBackend::sha3_512(&input)
    }

    fn into_approval(self, approval_signature: [u8; ML_DSA_65_SIG_SIZE]) -> DeviceLinkApproval {
        DeviceLinkApproval {
            request_digest: self.request_digest,
            approved_device_id: self.approved_device_id,
            approved_device_fingerprint: self.approved_device_fingerprint,
            approved_identity_fingerprint: self.approved_identity_fingerprint,
            approved_identity_generation: self.approved_identity_generation,
            approver_device_id: self.approver_device_id,
            approver_device_fingerprint: self.approver_device_fingerprint,
            approved_at_ms: self.approved_at_ms,
            expires_at_ms: self.expires_at_ms,
            allow_existing_identity_clone: self.allow_existing_identity_clone,
            group_rekey_required_on_future_revocation: self
                .group_rekey_required_on_future_revocation,
            approval_signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::AppErrorClass;

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-msg-{name}-{nonce}.hydraid"))
    }

    #[test]
    fn approved_device_link_installs_new_active_device() {
        let primary_path = temp_path("primary-link");
        let new_path = temp_path("new-link");
        let primary = IdentityStore::create(&primary_path, b"primary password").unwrap();
        let new_device = IdentityStore::create(&new_path, b"new password").unwrap();
        let mut registry = DeviceRegistry::new(&primary, 1_000).unwrap();
        let request = DeviceLinkRequest::create(
            &new_device,
            registry.account_identity_fingerprint(),
            1_010,
            60_000,
        )
        .unwrap();
        let approval = registry
            .approve_link_request(&primary, &request, 1_020, DeviceLinkPolicy::default())
            .unwrap();
        let installed = registry
            .install_approved_device(&request, &approval, 1_030)
            .unwrap();
        assert_eq!(installed.device_id, new_device.device_id());
        assert_eq!(registry.active_devices().len(), 2);
        registry
            .require_active_device_generation(new_device.device_id(), new_device.generation())
            .unwrap();
        fs::remove_file(primary_path).ok();
        fs::remove_file(new_path).ok();
    }

    #[test]
    fn stale_request_rejects_before_approval() {
        let primary_path = temp_path("primary-stale");
        let new_path = temp_path("new-stale");
        let primary = IdentityStore::create(&primary_path, b"primary password").unwrap();
        let new_device = IdentityStore::create(&new_path, b"new password").unwrap();
        let registry = DeviceRegistry::new(&primary, 1_000).unwrap();
        let request = DeviceLinkRequest::create(
            &new_device,
            registry.account_identity_fingerprint(),
            1_010,
            5,
        )
        .unwrap();
        let error = registry
            .approve_link_request(&primary, &request, 1_016, DeviceLinkPolicy::default())
            .unwrap_err();
        assert_eq!(error.class(), AppErrorClass::InvalidState);
        fs::remove_file(primary_path).ok();
        fs::remove_file(new_path).ok();
    }

    #[test]
    fn active_identity_clone_requires_explicit_policy() {
        let primary_path = temp_path("primary-clone");
        let clone_path = temp_path("clone-device");
        let primary = IdentityStore::create(&primary_path, b"primary password").unwrap();
        let clone = IdentityStore::import_backup_record(
            &clone_path,
            b"clone password",
            primary.export_backup_record(),
            false,
        )
        .unwrap();
        let mut registry = DeviceRegistry::new(&primary, 1_000).unwrap();
        let request = DeviceLinkRequest::create(
            &clone,
            registry.account_identity_fingerprint(),
            1_010,
            60_000,
        )
        .unwrap();
        let blocked = registry
            .approve_link_request(&primary, &request, 1_020, DeviceLinkPolicy::default())
            .unwrap_err();
        assert_eq!(blocked.class(), AppErrorClass::InvalidState);
        let approval = registry
            .approve_link_request(
                &primary,
                &request,
                1_020,
                DeviceLinkPolicy {
                    allow_existing_identity_clone: true,
                },
            )
            .unwrap();
        registry
            .install_approved_device(&request, &approval, 1_030)
            .unwrap();
        assert_eq!(registry.active_devices().len(), 2);
        fs::remove_file(primary_path).ok();
        fs::remove_file(clone_path).ok();
    }

    #[test]
    fn revoked_and_stale_generation_devices_reject() {
        let primary_path = temp_path("primary-revoke");
        let new_path = temp_path("new-revoke");
        let primary = IdentityStore::create(&primary_path, b"primary password").unwrap();
        let new_device = IdentityStore::create(&new_path, b"new password").unwrap();
        let mut registry = DeviceRegistry::new(&primary, 1_000).unwrap();
        assert_eq!(
            registry
                .require_active_device_generation(primary.device_id(), primary.generation() + 1)
                .unwrap_err()
                .class(),
            AppErrorClass::InvalidState
        );
        let request = DeviceLinkRequest::create(
            &new_device,
            registry.account_identity_fingerprint(),
            1_010,
            60_000,
        )
        .unwrap();
        let approval = registry
            .approve_link_request(&primary, &request, 1_020, DeviceLinkPolicy::default())
            .unwrap();
        registry
            .install_approved_device(&request, &approval, 1_030)
            .unwrap();
        let revocation = registry
            .revoke_device(&primary, new_device.device_id(), 1_100)
            .unwrap();
        assert!(revocation.group_rekey_required);
        assert_eq!(
            registry
                .require_active_device(new_device.device_id())
                .unwrap_err()
                .class(),
            AppErrorClass::InvalidState
        );
        fs::remove_file(primary_path).ok();
        fs::remove_file(new_path).ok();
    }
}
