use super::primitives::{checked_u16_be, u32_be, u64_be};
use crate::{GroupError, GroupMode, GroupResult, MemberStatus, RosterEntry};

pub const ROSTER_ENTRY_SIZE: usize = 86;

pub fn encode_roster_entry(entry: &RosterEntry) -> [u8; ROSTER_ENTRY_SIZE] {
    let mut encoded = [0_u8; ROSTER_ENTRY_SIZE];
    encoded[0..32].copy_from_slice(&entry.member_id.0);
    encoded[32..64].copy_from_slice(&entry.device_identity_fingerprint.0);
    encoded[64] = entry.role as u8;
    encoded[65] = entry.status as u8;
    encoded[66..70].copy_from_slice(&u32_be(entry.tree_leaf_slot));
    encoded[70..78].copy_from_slice(&u64_be(entry.joined_epoch.0));
    encoded[78..86].copy_from_slice(&u64_be(entry.removed_epoch.0));
    encoded
}

pub fn encode_roster(mode: GroupMode, roster: &[RosterEntry]) -> GroupResult<Vec<u8>> {
    validate_roster_for_canonical_encoding(mode, roster)?;
    let mut ordered = roster.to_vec();
    ordered.sort_by_key(|entry| entry.member_id.0);

    let mut encoded = Vec::with_capacity(2 + ordered.len() * ROSTER_ENTRY_SIZE);
    encoded.extend_from_slice(&checked_u16_be(ordered.len())?);
    for entry in &ordered {
        encoded.extend_from_slice(&encode_roster_entry(entry));
    }
    Ok(encoded)
}

pub fn validate_roster_for_canonical_encoding(
    mode: GroupMode,
    roster: &[RosterEntry],
) -> GroupResult<()> {
    if roster.is_empty() || roster.len() > mode.max_roster_entries() {
        return Err(GroupError::InvalidRoster);
    }

    let mut member_ids = roster
        .iter()
        .map(|entry| entry.member_id.0)
        .collect::<Vec<_>>();
    member_ids.sort_unstable();
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GroupError::InvalidRoster);
    }

    let mut active_fingerprints = roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
        .map(|entry| entry.device_identity_fingerprint.0)
        .collect::<Vec<_>>();
    active_fingerprints.sort_unstable();
    if active_fingerprints
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(GroupError::InvalidRoster);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::test_support::entry, GroupError, GroupMode, GroupRole, MemberStatus};

    #[test]
    fn roster_entry_encoding_is_exactly_86_bytes() {
        let encoded = encode_roster_entry(&entry(1, 2));
        assert_eq!(encoded.len(), ROSTER_ENTRY_SIZE);
        assert_eq!(&encoded[0..32], &[1; 32]);
        assert_eq!(&encoded[32..64], &[2; 32]);
        assert_eq!(encoded[64], GroupRole::Member as u8);
        assert_eq!(encoded[65], MemberStatus::Active as u8);
        assert_eq!(&encoded[66..70], &1_u32.to_be_bytes());
        assert_eq!(&encoded[70..78], &1_u64.to_be_bytes());
        assert_eq!(&encoded[78..86], &0_u64.to_be_bytes());
    }

    #[test]
    fn canonical_roster_orders_by_member_id_and_rejects_duplicates() {
        let encoded = encode_roster(GroupMode::Interactive, &[entry(3, 3), entry(1, 1)]).unwrap();
        assert_eq!(&encoded[0..2], &2_u16.to_be_bytes());
        assert_eq!(&encoded[2..34], &[1; 32]);
        assert_eq!(
            &encoded[2 + ROSTER_ENTRY_SIZE..34 + ROSTER_ENTRY_SIZE],
            &[3; 32]
        );

        assert_eq!(
            encode_roster(GroupMode::Interactive, &[entry(1, 1), entry(1, 2)]),
            Err(GroupError::InvalidRoster)
        );
        assert_eq!(
            encode_roster(GroupMode::Interactive, &[entry(1, 7), entry(2, 7)]),
            Err(GroupError::InvalidRoster)
        );
    }

    #[test]
    fn roster_count_boundaries_are_explicit() {
        assert_eq!(
            encode_roster(GroupMode::Lite, &[]),
            Err(GroupError::InvalidRoster)
        );

        let one = vec![entry(1, 1)];
        assert!(encode_roster(GroupMode::Lite, &one).is_ok());

        let at_max = (0..hydra_core::MAX_LITE_MEMBERS)
            .map(|index| entry(index as u8 + 1, index as u8 + 1))
            .collect::<Vec<_>>();
        assert!(encode_roster(GroupMode::Lite, &at_max).is_ok());

        let too_many = (0..=hydra_core::MAX_LITE_MEMBERS)
            .map(|index| entry(index as u8 + 1, index as u8 + 1))
            .collect::<Vec<_>>();
        assert_eq!(
            encode_roster(GroupMode::Lite, &too_many),
            Err(GroupError::InvalidRoster)
        );
    }
}
