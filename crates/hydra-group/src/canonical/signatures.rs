use super::primitives::is_strictly_ordered_member_ids;
use crate::{GroupError, GroupResult, MemberId};
use hydra_core::{MAX_COMMIT_SIGNATURES, ML_DSA_65_SIG_SIZE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitSignature {
    pub signer: MemberId,
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
}

pub fn encode_signature_set(signatures: &[CommitSignature]) -> GroupResult<Vec<u8>> {
    validate_signature_set(signatures)?;
    let mut encoded = Vec::with_capacity(1 + signatures.len() * (32 + ML_DSA_65_SIG_SIZE));
    encoded.push(u8::try_from(signatures.len()).map_err(|_| GroupError::InvalidSignatureSet)?);
    for signature in signatures {
        encoded.extend_from_slice(&signature.signer.0);
        encoded.extend_from_slice(&signature.signature);
    }
    Ok(encoded)
}

pub fn validate_signature_set(signatures: &[CommitSignature]) -> GroupResult<()> {
    if signatures.is_empty() || signatures.len() > MAX_COMMIT_SIGNATURES {
        return Err(GroupError::InvalidSignatureSet);
    }
    let signers = signatures
        .iter()
        .map(|signature| signature.signer)
        .collect::<Vec<_>>();
    if !is_strictly_ordered_member_ids(&signers) {
        return Err(GroupError::InvalidSignatureSet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::test_support::member, GroupError};

    #[test]
    fn signature_set_count_and_order_boundaries_are_enforced() {
        assert_eq!(
            encode_signature_set(&[]),
            Err(GroupError::InvalidSignatureSet)
        );
        let one = vec![CommitSignature {
            signer: member(1),
            signature: [0x11; ML_DSA_65_SIG_SIZE],
        }];
        assert!(encode_signature_set(&one).is_ok());

        let seventeen = (1..=MAX_COMMIT_SIGNATURES)
            .map(|index| CommitSignature {
                signer: member(index as u8),
                signature: [index as u8; ML_DSA_65_SIG_SIZE],
            })
            .collect::<Vec<_>>();
        assert!(encode_signature_set(&seventeen).is_ok());

        let eighteen = (1..=MAX_COMMIT_SIGNATURES + 1)
            .map(|index| CommitSignature {
                signer: member(index as u8),
                signature: [index as u8; ML_DSA_65_SIG_SIZE],
            })
            .collect::<Vec<_>>();
        assert_eq!(
            encode_signature_set(&eighteen),
            Err(GroupError::InvalidSignatureSet)
        );

        let unsorted = vec![
            CommitSignature {
                signer: member(2),
                signature: [2; ML_DSA_65_SIG_SIZE],
            },
            CommitSignature {
                signer: member(1),
                signature: [1; ML_DSA_65_SIG_SIZE],
            },
        ];
        assert_eq!(
            encode_signature_set(&unsorted),
            Err(GroupError::InvalidSignatureSet)
        );
    }
}
