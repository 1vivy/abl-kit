//! Qualcomm ABL trust and presentation conventions over an AVB chain plan.
//!
//! `avb-chain` owns libavb's walk. This module adds the platform decisions the
//! stock ABL makes on top of it:
//!
//! * the root is anchored only to the **first** embedded key, or to a key the
//!   caller names explicitly;
//! * `boot` metadata properties are preferred over root properties;
//! * a metadata image is identified by the partitions it covers
//!   (`vbmeta_<group>` covers `<group>`);
//! * the ABL/TEE VBH is SHA-256 over the ordered exact metadata extents;
//! * the DICE authority hash is SHA-512 over the embedded public keys in visit
//!   order, with repeats kept.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use avb_chain::{
    Accepted, CmdlineDigest, Defect, HashAlg, Image, KeyBlob, Kind, Need, Plan, Property, Rejected,
    VbmetaDigest, VbmetaInfo, Verdict, WalkNode, inspect, sha256,
};
use avb_verify::sha512_concat;
use core::fmt;

use crate::{AblKey, AblKeys, OS_VERSION_KEY, SECURITY_PATCH_KEY};

/// The build properties the observed ABL reports out of AVB metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Properties {
    pub os_version: Option<String>,
    pub security_patch: Option<String>,
}

impl Properties {
    /// First non-empty source wins; mirrors the ABL's boot-first lookup.
    pub fn or(&self, fallback: &Self) -> Self {
        Self {
            os_version: self
                .os_version
                .clone()
                .or_else(|| fallback.os_version.clone()),
            security_patch: self
                .security_patch
                .clone()
                .or_else(|| fallback.security_patch.clone()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.os_version.is_none() && self.security_patch.is_none()
    }

    fn from_descriptors(properties: &[Property]) -> Self {
        let mut selected = Self::default();
        for property in properties {
            let slot = match property.key.as_str() {
                OS_VERSION_KEY => &mut selected.os_version,
                SECURITY_PATCH_KEY => &mut selected.security_patch,
                _ => continue,
            };
            *slot = Some(property.value.clone());
        }
        selected
    }
}

/// What happened to one supplied image under the ABL's trust convention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AblVerdict {
    /// The authentication block verified. `anchored` is true when the signing
    /// key is the ABL's first embedded key or an explicitly trusted extra.
    Verified {
        key_sha256: [u8; 32],
        anchored: bool,
    },
    /// Signed, but by a different key than the anchor demands.
    KeyMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Signed by a key that is embedded in the ABL but is not trusted.
    UntrustedKey {
        actual: [u8; 32],
    },
    /// The signed coverage does not identify the image as the demanded
    /// partition. AVB does not bind a name to an image, so this is a convention.
    WrongPartition {
        need: String,
        covered: Vec<String>,
    },
    SignatureMismatch,
    HashMismatch,
    Unsigned,
    Malformed(Defect),
}

impl AblVerdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// `Some(anchored)` for a verified image, `None` otherwise.
    pub fn anchored(&self) -> Option<bool> {
        match self {
            Self::Verified { anchored, .. } => Some(*anchored),
            _ => None,
        }
    }
}

impl From<Verdict> for AblVerdict {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Verified {
                key_sha256,
                trusted,
            } => Self::Verified {
                key_sha256,
                anchored: trusted,
            },
            Verdict::KeyMismatch { expected, actual } => Self::KeyMismatch { expected, actual },
            Verdict::UntrustedKey { actual } => Self::UntrustedKey { actual },
            Verdict::SignatureMismatch => Self::SignatureMismatch,
            Verdict::HashMismatch => Self::HashMismatch,
            Verdict::Unsigned => Self::Unsigned,
            Verdict::Malformed(defect) => Self::Malformed(defect),
        }
    }
}

impl fmt::Display for AblVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified {
                key_sha256,
                anchored,
            } => write!(
                f,
                "verified against key {} ({})",
                avb_chain::hex(key_sha256),
                if *anchored { "anchored" } else { "UNANCHORED" }
            ),
            Self::KeyMismatch { expected, actual } => write!(
                f,
                "key mismatch: expected {}, found {}",
                avb_chain::hex(expected),
                avb_chain::hex(actual)
            ),
            Self::UntrustedKey { actual } => {
                write!(f, "signed by untrusted key {}", avb_chain::hex(actual))
            }
            Self::WrongPartition { need, covered } => {
                write!(f, "wrong partition: {need} covers {covered:?}")
            }
            Self::SignatureMismatch => f.write_str("signature mismatch"),
            Self::HashMismatch => f.write_str("hash mismatch"),
            Self::Unsigned => f.write_str("unsigned (algorithm_type NONE)"),
            Self::Malformed(defect) => write!(f, "malformed: {defect}"),
        }
    }
}

/// A supplied image that verified under the ABL convention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblAccepted {
    pub name: String,
    pub kind: Kind,
    pub metadata_len: usize,
    pub metadata_sha256: [u8; 32],
    pub key_sha256: [u8; 32],
    /// True when the image is anchored to the ABL's first key or an explicit
    /// extra.
    pub anchored: bool,
    pub index: usize,
}

/// A supplied image that did not verify under the ABL convention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblRejected {
    pub name: String,
    pub verdict: AblVerdict,
}

impl AblRejected {
    pub fn verdict(&self) -> &AblVerdict {
        &self.verdict
    }
}

impl fmt::Display for AblRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.verdict)
    }
}

/// A chain plan plus the ABL's anchor and presentation decisions.
#[derive(Debug)]
pub struct AblPlan {
    plan: Plan,
    keys: AblKeys,
    /// The trust set: the anchor first, then explicitly trusted extras.
    trusted: Vec<AblKey>,
    anchored: bool,
}

impl AblPlan {
    /// A root that self-verifies but is not anchored to an ABL key.
    pub fn new(root: &[u8]) -> Result<Self, AblVerdict> {
        let plan = Plan::new(root).map_err(AblVerdict::from)?;
        Ok(Self {
            plan,
            keys: AblKeys::default(),
            trusted: Vec::new(),
            anchored: false,
        })
    }

    /// A root anchored to the first key in `anchors`.
    pub fn anchored(root: &[u8], anchors: &AblKeys) -> Result<Self, AblVerdict> {
        Self::anchored_with_extra(root, anchors, &[])
    }

    /// [`AblPlan::anchored`], plus keys the caller explicitly trusts.
    ///
    /// This is the only way a root signed by a later embedded key is accepted as
    /// anchored.
    pub fn anchored_with_extra(
        root: &[u8],
        anchors: &AblKeys,
        extra_trusted: &[AblKey],
    ) -> Result<Self, AblVerdict> {
        let Some(anchor) = anchors.anchor() else {
            return Err(AblVerdict::Malformed(Defect::NoTrustedKey));
        };
        let mut trusted = Vec::with_capacity(1 + extra_trusted.len());
        trusted.push(anchor.clone());
        for key in extra_trusted {
            if !trusted.iter().any(|existing| existing.blob == key.blob) {
                trusted.push(key.clone());
            }
        }

        // Verify the root once against its own key, so a later embedded key can
        // be reported as UNANCHORED instead of being mistaken for a mismatch.
        let self_verified = Plan::new(root).map_err(AblVerdict::from)?;
        let root_key = self_verified.root_info().public_key.clone();
        let root_sha256 = self_verified.root_info().public_key_sha256;

        if !trusted.iter().any(|key| key.blob == root_key) {
            if anchors.keys().iter().any(|key| key.blob == root_key) {
                return Err(AblVerdict::Verified {
                    key_sha256: root_sha256,
                    anchored: false,
                });
            }
            return Err(AblVerdict::KeyMismatch {
                expected: anchor.sha256,
                actual: root_sha256,
            });
        }

        let key_blobs: Vec<KeyBlob> = trusted
            .iter()
            .map(|key| KeyBlob {
                blob: key.blob.clone(),
                num_bits: key.num_bits,
            })
            .collect();
        let plan = Plan::with_trusted_keys(root, &key_blobs).map_err(AblVerdict::from)?;
        Ok(Self {
            plan,
            keys: anchors.clone(),
            trusted,
            anchored: true,
        })
    }

    /// Walk a root structurally, without requiring it to verify.
    pub fn new_unverified(root: &[u8]) -> Result<Self, AblVerdict> {
        let plan = Plan::new_unverified(root).map_err(AblVerdict::Malformed)?;
        Ok(Self {
            plan,
            keys: AblKeys::default(),
            trusted: Vec::new(),
            anchored: false,
        })
    }

    /// Supply one image and apply the ABL identity convention.
    pub fn supply(&mut self, name: &str, bytes: &[u8]) -> Result<AblAccepted, AblRejected> {
        let accepted = self.plan.supply(name, bytes).map_err(AblRejected::from)?;
        self.finish_accepted(name, accepted)
    }

    /// [`AblPlan::supply`] with a caller-supplied backing reader.
    pub fn supply_from<E: fmt::Display>(
        &mut self,
        name: &str,
        image_size: u64,
        read_at: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<AblAccepted, AblRejected> {
        let accepted = self
            .plan
            .supply_from(name, image_size, read_at)
            .map_err(AblRejected::from)?;
        self.finish_accepted(name, accepted)
    }

    fn finish_accepted(&self, name: &str, accepted: Accepted) -> Result<AblAccepted, AblRejected> {
        let covered = self
            .plan
            .image_info(name)
            .map(|info| info.covered.clone())
            .unwrap_or_default();
        if !identity_ok(name, &covered) {
            return Err(AblRejected {
                name: name.to_owned(),
                verdict: AblVerdict::WrongPartition {
                    need: name.to_owned(),
                    covered,
                },
            });
        }
        Ok(AblAccepted {
            name: accepted.name,
            kind: accepted.kind,
            metadata_len: accepted.metadata_len,
            metadata_sha256: accepted.metadata_sha256,
            key_sha256: accepted.key_sha256,
            anchored: accepted.trusted,
            index: accepted.index,
        })
    }

    /// Judge bytes for a demanded name without recording them.
    pub fn judge(&self, name: &str, bytes: &[u8]) -> AblVerdict {
        let verdict = self.plan.judge(name, bytes);
        if verdict.is_verified()
            && let Ok(info) = inspect(bytes)
            && !identity_ok(name, &info.covered)
        {
            return AblVerdict::WrongPartition {
                need: name.to_owned(),
                covered: info.covered,
            };
        }
        AblVerdict::from(verdict)
    }

    pub fn needs(&self) -> Vec<Need> {
        self.plan.needs()
    }

    pub fn missing(&self) -> Vec<String> {
        self.plan.missing()
    }

    pub fn complete(&self) -> bool {
        self.plan.complete()
    }

    pub fn rejected(&self) -> Vec<(String, AblVerdict)> {
        self.plan
            .rejected()
            .into_iter()
            .map(|(name, verdict)| (name, AblVerdict::from(verdict)))
            .collect()
    }

    pub fn ordered_images(&self) -> Vec<Image<'_>> {
        self.plan.ordered_images()
    }

    pub fn walk_order(&self) -> Vec<WalkNode<'_>> {
        self.plan.walk_order()
    }

    pub fn supplied_info(&self) -> Vec<(&str, &VbmetaInfo)> {
        self.plan.supplied_info()
    }

    pub fn payload_hashed(&self) -> Vec<String> {
        self.plan.payload_hashed()
    }

    pub fn covered(&self) -> Vec<(String, Vec<String>)> {
        self.plan.covered()
    }

    pub fn root_metadata(&self) -> &[u8] {
        self.plan.root_metadata()
    }

    pub fn root_info(&self) -> &VbmetaInfo {
        self.plan.root_info()
    }

    pub fn root_algorithm(&self) -> u32 {
        self.plan.root_algorithm()
    }

    /// The root's authentication hash, defaulting to SHA-256 for an unsigned or
    /// ML-DSA root as the source convention did.
    pub fn digest_algorithm(&self) -> HashAlg {
        self.plan.digest_algorithm().unwrap_or(HashAlg::Sha256)
    }

    pub fn root_verdict(&self) -> AblVerdict {
        AblVerdict::from(Verdict::clone(self.plan.root_verdict()))
    }

    pub fn is_anchored(&self) -> bool {
        self.anchored
    }

    /// The anchor first, then explicitly trusted extras.
    pub fn trusted_keys(&self) -> &[AblKey] {
        &self.trusted
    }

    pub fn trust_anchor(&self) -> Option<&AblKey> {
        self.trusted.first()
    }

    pub fn key_set(&self) -> &AblKeys {
        &self.keys
    }

    /// The ABL/TEE `SET_VBH`: SHA-256 over ordered exact metadata extents.
    pub fn vbmeta_digest(&self) -> VbmetaDigest {
        self.plan.vbmeta_digest_with(HashAlg::Sha256)
    }

    pub fn vbmeta_digest_with(&self, algorithm: HashAlg) -> VbmetaDigest {
        self.plan.vbmeta_digest_with(algorithm)
    }

    pub fn libavb_cmdline_digest(&self) -> Option<CmdlineDigest> {
        self.plan.libavb_cmdline_digest()
    }

    /// The DICE authority hash, only when every image is supplied and verified.
    pub fn authority_sha512(&self) -> Option<[u8; 64]> {
        if !self.complete() {
            return None;
        }
        let keys: Vec<&[u8]> = self
            .supplied_info()
            .iter()
            .map(|(_, info)| info.public_key.as_slice())
            .collect();
        Some(sha512_concat(&keys))
    }

    /// The root's own build properties.
    pub fn root_properties(&self) -> Properties {
        Properties::from_descriptors(self.plan.root_properties())
    }

    /// `boot` metadata first, then root properties.
    pub fn properties(&self) -> Properties {
        let boot = self.boot_properties();
        if boot.is_empty() {
            self.root_properties()
        } else {
            boot.or(&self.root_properties())
        }
    }

    pub fn properties_source(&self) -> &'static str {
        if !self.boot_properties().is_empty() {
            "from the boot metadata properties the ABL prefers"
        } else if !self.root_properties().is_empty() {
            "from the root vbmeta properties (no boot metadata supplied)"
        } else {
            "absent: the ABL falls back to the boot header fields"
        }
    }

    fn boot_properties(&self) -> Properties {
        self.plan
            .image_properties("boot")
            .map(Properties::from_descriptors)
            .unwrap_or_default()
    }
}

impl From<Rejected> for AblRejected {
    fn from(rejected: Rejected) -> Self {
        Self {
            name: rejected.name,
            verdict: AblVerdict::from(rejected.verdict),
        }
    }
}

/// Does the signed coverage of an image identify it as the demanded partition?
///
/// AVB does not bind a partition name to a vbmeta image, so this is a convention,
/// not a signature check: `vbmeta_<group>` must declare coverage for `<group>`,
/// and any other name must be covered by itself or a name in its group. An image
/// that names no partition at all cannot be judged this way and is accepted.
pub fn identity_ok(need: &str, covered: &[String]) -> bool {
    if covered.is_empty() {
        return true;
    }
    let group = need.strip_prefix("vbmeta_");
    covered.iter().any(|name| match group {
        Some(group) => {
            name == group
                || name.starts_with(&format!("{group}_"))
                || group.starts_with(&format!("{name}_"))
        }
        None => {
            name == need
                || name.starts_with(&format!("{need}_"))
                || need.starts_with(&format!("{name}_"))
        }
    })
}

/// SHA-256 of a key blob, for callers that hold only bytes.
pub fn key_sha256(blob: &[u8]) -> [u8; 32] {
    sha256(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn identity_accepts_group_coverage_and_rejects_a_foreign_image() {
        let covered = vec!["vendor".to_string()];
        assert!(identity_ok("vbmeta_vendor", &covered));
        assert!(!identity_ok("vbmeta_system", &covered));
        assert!(!identity_ok("boot", &[String::new()]));
        assert!(identity_ok("boot", &["boot".to_string()]));
        assert!(identity_ok("boot", &["boot_a".to_string()]));
        assert!(
            identity_ok("boot", &[]),
            "property-only metadata is accepted"
        );
    }

    #[test]
    fn properties_prefer_last_descriptor_and_boot_over_root() {
        let root = vec![
            Property {
                key: OS_VERSION_KEY.to_string(),
                value: "15".to_string(),
            },
            Property {
                key: OS_VERSION_KEY.to_string(),
                value: "16".to_string(),
            },
        ];
        let boot = vec![Property {
            key: SECURITY_PATCH_KEY.to_string(),
            value: "2026-08-01".to_string(),
        }];
        let root = Properties::from_descriptors(&root);
        let boot = Properties::from_descriptors(&boot);
        assert_eq!(root.os_version.as_deref(), Some("16"));
        assert!(root.security_patch.is_none());
        let selected = boot.or(&root);
        assert_eq!(selected.os_version.as_deref(), Some("16"));
        assert_eq!(selected.security_patch.as_deref(), Some("2026-08-01"));
    }
}
