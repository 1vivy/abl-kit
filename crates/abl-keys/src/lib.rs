//! Qualcomm ABL AVB public keys and the first-key trust anchor.
//!
//! The stock ABL's `AvbValidateVbmetaPublicKey` byte-compares the root
//! `vbmeta` public key against its compiled-in `OEMPublicKey` array
//! (`QcomModulePkg/Library/avb/libavb/avb_ops.c`). That array is the first
//! structurally complete AVB public-key blob embedded in the LinuxLoader PE.
//! [`AblKeys::anchor`] is therefore the first key in file order.
//!
//! The scan reports every distinct self-consistent blob, with its first offset.
//! A repeated blob does not push the first key out of first place. A later key
//! is reported but is not an anchor.
//!
//! The raw scan finds the separate Qualcomm trust path: a bare RSA-2048 modulus
//! followed by exponent 65537. Such a record is not an AVB key blob and does not
//! anchor AVB metadata.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
pub use avb_chain::{
    CmdlineDigest, Defect, HashAlg, Kind, Need, VBMETA_FLAG_VERIFICATION_DISABLED, VbmetaDigest,
    VbmetaInfo, Verdict, extract_vbmd, inspect,
};
pub use avb_format::{RSA_KEY_HEADER_SIZE, key_blob_len, key_num_bits};
use avb_format::{key_is_valid, validate_key_blob};
pub use avb_verify::{sha256, sha512, sha512_concat};

pub mod plan;
pub mod vbh;

pub use plan::{AblAccepted, AblPlan, AblRejected, AblVerdict, Properties, identity_ok};
pub use vbh::{VbmetaReader, derive_set_vbh};

/// The `com.android.build.boot.*` property the observed canoe ABL prefers over
/// the boot header (`evidence/emu-report.md` section 5).
pub const OS_VERSION_KEY: &str = "com.android.build.boot.os_version";
/// Companion security-patch property.
pub const SECURITY_PATCH_KEY: &str = "com.android.build.boot.security_patch";

/// Bytes of a bare RSA-2048 modulus.
pub const RSA2048_MODULUS: usize = 256;
/// The only exponent accepted with [`RSA2048_MODULUS`].
pub const RSA2048_EXPONENT: [u8; 3] = [1, 0, 1];

/// An AVB RSA public key found inside a PE image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblKey {
    /// File offset of the key blob in the scanned image.
    pub file_offset: usize,
    /// `key_num_bits` of the blob.
    pub num_bits: u32,
    /// SHA-256 of the whole blob, which is what the ABL's cmdline reports.
    pub sha256: [u8; 32],
    /// The blob itself, byte-for-byte as the ABL would compare it.
    pub blob: Vec<u8>,
}

impl AblKey {
    /// Validate a blob and place it at `file_offset`.
    pub fn from_blob(file_offset: usize, blob: Vec<u8>) -> Option<Self> {
        let num_bits = validate_key_blob(&blob)?;
        Some(Self {
            file_offset,
            num_bits,
            sha256: sha256(&blob),
            blob,
        })
    }

    /// Signature size in bytes for this key.
    pub fn signature_len(&self) -> usize {
        self.num_bits as usize / 8
    }
}

/// Every structurally self-consistent AVB key found in one image, in file
/// order, and the trust anchor derived from them.
///
/// The first key is the anchor. A later key is reported but is not trusted
/// unless a caller names it explicitly.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AblKeys {
    keys: Vec<AblKey>,
}

impl AblKeys {
    /// Scan `image` for AVB keys, in file order.
    pub fn scan(image: &[u8]) -> Self {
        Self {
            keys: scan_abl_keys(image),
        }
    }

    /// A set built by the caller, order preserved as given.
    ///
    /// The first entry is the anchor, exactly as a scan's first entry is.
    pub fn from_keys(keys: Vec<AblKey>) -> Self {
        Self { keys }
    }

    /// The trust anchor: the first key in file order.
    ///
    /// `None` only when no key was found, which is a refusal to anchor rather
    /// than an unanchored success.
    pub fn anchor(&self) -> Option<&AblKey> {
        self.keys.first()
    }

    /// Every distinct key found, in file order.
    pub fn keys(&self) -> &[AblKey] {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys themselves, consumed.
    pub fn into_keys(self) -> Vec<AblKey> {
        self.keys
    }

    /// The keys in trust order: the anchor first, then every later key in file
    /// order. A caller that trusts an extra key adds it explicitly.
    pub fn trusted_order(&self) -> Vec<AblKey> {
        self.keys.clone()
    }
}

/// Every structurally self-consistent AVB RSA public key in `image`, in file
/// order.
///
/// The scan visits every byte offset, because an embedded key need not be
/// aligned. A candidate is accepted only when [`avb_format::key_is_valid`]
/// confirms the length, the full-width odd modulus, `n0inv`, and `rr`.
///
/// An exact duplicate blob is reported once, at its first offset. File order is
/// preserved and the first key stays the anchor.
pub fn abl_keys(image: &[u8]) -> AblKeys {
    AblKeys::scan(image)
}

fn scan_abl_keys(image: &[u8]) -> Vec<AblKey> {
    let mut found = Vec::new();
    let Some(last) = image.len().checked_sub(RSA_KEY_HEADER_SIZE) else {
        return found;
    };
    for offset in 0..=last {
        let Some(head) = image.get(offset..offset + 4) else {
            continue;
        };
        let Ok(head) = <[u8; 4]>::try_from(head) else {
            continue;
        };
        let bits = u32::from_be_bytes(head);
        let Some(len) = key_blob_len(bits) else {
            continue;
        };
        let Some(end) = offset.checked_add(len) else {
            continue;
        };
        let Some(blob) = image.get(offset..end) else {
            continue;
        };
        if !key_is_valid(blob) {
            continue;
        }
        if found.iter().any(|key: &AblKey| key.blob.as_slice() == blob) {
            continue;
        }
        found.push(AblKey {
            file_offset: offset,
            num_bits: bits,
            sha256: sha256(blob),
            blob: blob.to_vec(),
        });
    }
    found
}

/// One bare RSA-2048 modulus followed by exponent 65537.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRsa2048Key {
    /// File offset of the 256-byte modulus.
    pub file_offset: usize,
    /// The big-endian modulus.
    pub modulus: [u8; RSA2048_MODULUS],
}

/// Every 256-byte big-endian RSA-2048 modulus immediately followed by `01 00 01`
/// (e = 65537), in file order.
///
/// The modulus must have its top bit set and an odd last byte. Repeated moduli
/// are reported once, at their first offset.
pub fn scan_rsa2048_e65537(image: &[u8]) -> Vec<RawRsa2048Key> {
    let mut keys = Vec::new();
    let Some(last) = image.len().checked_sub(RSA2048_MODULUS + 3) else {
        return keys;
    };
    for offset in 0..=last {
        let Some(record) = image.get(offset..offset + RSA2048_MODULUS + 3) else {
            continue;
        };
        if record[RSA2048_MODULUS..] != RSA2048_EXPONENT
            || record[0] & 0x80 == 0
            || record[RSA2048_MODULUS - 1] & 1 == 0
        {
            continue;
        }
        let Ok(modulus) = <[u8; RSA2048_MODULUS]>::try_from(&record[..RSA2048_MODULUS]) else {
            continue;
        };
        if !keys
            .iter()
            .any(|key: &RawRsa2048Key| key.modulus == modulus)
        {
            keys.push(RawRsa2048Key {
                file_offset: offset,
                modulus,
            });
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const TESTKEY: &[u8] = include_bytes!("../tests/fixtures/testkey_rsa4096_pub.bin");

    #[test]
    fn scan_finds_the_avb_test_key_and_anchors_it() {
        let keys = abl_keys(TESTKEY);
        assert_eq!(keys.len(), 1);
        let key = keys.anchor().expect("the fixture is a valid AVB key");
        assert_eq!(key.file_offset, 0);
        assert_eq!(key.num_bits, 4096);
        assert_eq!(key.blob, TESTKEY);
        assert_eq!(key.signature_len(), 512);
        assert_eq!(key.blob.len(), 1032);
    }

    #[test]
    fn scan_reports_the_first_offset_and_removes_exact_duplicates() {
        let mut image = vec![0u8; 5];
        image.extend_from_slice(TESTKEY);
        image.extend_from_slice(&[0u8; 7]);
        image.extend_from_slice(TESTKEY);
        let keys = abl_keys(&image);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.keys()[0].file_offset, 5);
        assert_eq!(keys.anchor().map(|key| key.file_offset), Some(5));
    }

    #[test]
    fn tampered_key_arithmetic_is_not_a_key() {
        let mut tampered = TESTKEY.to_vec();
        tampered[4] ^= 0xff;
        assert!(abl_keys(&tampered).is_empty());

        let mut tampered = TESTKEY.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(abl_keys(&tampered).is_empty());
    }

    #[test]
    fn from_keys_keeps_the_first_key_as_the_anchor() {
        let later = AblKey::from_blob(16, TESTKEY.to_vec()).expect("valid key");
        let anchor = AblKey::from_blob(0, TESTKEY.to_vec()).expect("valid key");
        assert_eq!(anchor.sha256, later.sha256);
        let keys = AblKeys::from_keys(vec![later, anchor]);
        assert_eq!(keys.anchor().map(|key| key.file_offset), Some(16));
        assert_eq!(keys.trusted_order().len(), 2);
    }

    #[test]
    fn scan_finds_nothing_in_random_data() {
        let mut state = 0x1234_5678u32;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        assert!(abl_keys(&noise).is_empty());
        assert!(abl_keys(&[]).is_empty());
        assert!(abl_keys(&[0u8; 8]).is_empty());
        assert!(abl_keys(&[0u8; 7]).is_empty());
    }

    #[test]
    fn scan_rsa2048_matches_only_the_full_encoding() {
        let mut modulus = [0x7f_u8; RSA2048_MODULUS];
        modulus[0] = 0xff;
        modulus[RSA2048_MODULUS - 1] = 0x01;
        let mut record = modulus.to_vec();
        record.extend_from_slice(&RSA2048_EXPONENT);
        assert_eq!(
            scan_rsa2048_e65537(&record),
            vec![RawRsa2048Key {
                file_offset: 0,
                modulus
            }]
        );

        // Equal moduli are reported once, at the first offset.
        let mut repeated = vec![0u8; 9];
        repeated.extend_from_slice(&record);
        repeated.extend_from_slice(&record);
        assert_eq!(
            scan_rsa2048_e65537(&repeated),
            vec![RawRsa2048Key {
                file_offset: 9,
                modulus
            }]
        );

        // An even modulus, a cleared top bit, a wrong exponent and a truncated
        // record are not RSA-2048 moduli with e = 65537.
        let mut even = record.clone();
        even[RSA2048_MODULUS - 1] = 0x02;
        assert!(scan_rsa2048_e65537(&even).is_empty());
        let mut lowered = record.clone();
        lowered[0] = 0x01;
        assert!(scan_rsa2048_e65537(&lowered).is_empty());
        let mut exponent = record.clone();
        exponent[RSA2048_MODULUS + 2] = 3;
        assert!(scan_rsa2048_e65537(&exponent).is_empty());
        assert!(scan_rsa2048_e65537(&record[..record.len() - 1]).is_empty());

        // The AVB test key carries no bare RSA-2048 modulus/exponent pair.
        assert!(scan_rsa2048_e65537(TESTKEY).is_empty());
    }
}
