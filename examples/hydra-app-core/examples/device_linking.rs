use hydra_app_core::{
    AppGroup, DeviceLinkPolicy, DeviceLinkRequest, DeviceRegistry, IdentityStore,
};
use hydra_group::GroupRole;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join("hydra-msg-device-linking-example");
    std::fs::create_dir_all(&base)?;
    let primary_path = base.join("primary.hydraid");
    let phone_path = base.join("phone.hydraid");
    let primary_password = b"primary device password";
    let phone_password = b"phone device password";
    let primary = IdentityStore::create(&primary_path, primary_password)?;
    let phone = IdentityStore::create(&phone_path, phone_password)?;

    let mut registry = DeviceRegistry::new(&primary, 1_000)?;
    let request = DeviceLinkRequest::create(
        &phone,
        registry.account_identity_fingerprint(),
        1_010,
        60_000,
    )?;
    let approval =
        registry.approve_link_request(&primary, &request, 1_020, DeviceLinkPolicy::default())?;
    let linked = registry.install_approved_device(&request, &approval, 1_030)?;
    println!("linked device: {:?}", linked.device_id);

    let mut group = AppGroup::create_lite(primary.identity()?, GroupRole::Member)?;
    let welcome = group.add_lite_member(
        primary.identity()?,
        phone.public_identity(),
        GroupRole::Member,
    )?;
    let phone_group = AppGroup::install_lite_welcome(phone.identity()?, welcome)?;
    let revocation = registry.revoke_device(&primary, phone.device_id(), 1_100)?;
    if revocation.group_rekey_required {
        let notice = group.remove_lite_member_and_rekey(
            primary.identity()?,
            phone_group.local_member_id(),
            1,
        )?;
        println!("rekeyed group to epoch {:?}", notice.new_epoch());
    }

    std::fs::remove_file(primary_path).ok();
    std::fs::remove_file(phone_path).ok();
    Ok(())
}
