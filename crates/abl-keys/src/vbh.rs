//! Qualcomm `SET_VBH` reconstruction from source partitions.
//!
//! CLO `Library/avb/VerifiedBoot.c` `ComputeVbMetaDigest` hashes the ordered
//! metadata images with SHA-256. GBL reports the libavb digest and the loaded
//! partitions, but not the vbmeta bytes. This module reads the source
//! partitions in libavb order.
//!
//! The chain walk and the ordered digest are `avb-chain`'s job. This module adds
//! the stock ABL decision: the reconstruction is accepted only when its digest
//! equals the digest the platform already verified. Signature verdicts are
//! recorded and are not required, because the supplied digest is the proof.

use alloc::{format, string::String, vec, vec::Vec};
use avb_chain::{HashAlg, Plan};
use avb_format::{AvbDigest, ExtractError, HEADER_SIZE, VBMETA_MAX_SIZE, vbmd_extent};
use core::fmt::Display;

/// A source of named AVB partitions, without a firmware binding.
///
/// A platform implements this over its partition authority. A test
/// implementation reports the same reads from memory or from captured images.
pub trait VbmetaReader {
    /// The source's read or lookup error.
    type Error: Display;

    /// Returns the partition size, or `None` when the partition is absent.
    ///
    /// # Errors
    ///
    /// Returns the source's lookup error for a partition that is present but
    /// unreadable.
    fn partition_size(&self, partition: &str) -> Result<Option<u64>, Self::Error>;

    /// Reads the complete output slice from `partition` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns the source's read error.
    fn read_partition(
        &self,
        partition: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// Reconstructs the stock ABL SHA-256 hash after an independent digest match.
///
/// The function tries the unsuffixed, `_a`, and `_b` slots. A slot without a
/// `vbmeta` partition uses `boot`, which matches libavb. The chain walk takes
/// the chained images in descriptor order, and a chain descriptor with
/// `DO_NOT_USE_AB` removes the slot suffix.
///
/// A slot cannot match when an image is absent or malformed. A footered image
/// that has no valid footer is read from offset zero, which is the unfootered
/// form. An image that declares an over-large metadata extent is not retried
/// from offset zero.
///
/// Returns `None` when no slot reproduces `digest`.
///
/// # Examples
///
/// ```
/// use abl_keys::vbh::{derive_set_vbh, VbmetaReader};
/// use avb_format::AvbDigest;
///
/// struct Absent;
///
/// impl VbmetaReader for Absent {
///     type Error = &'static str;
///
///     fn partition_size(&self, _: &str) -> Result<Option<u64>, Self::Error> {
///         Ok(None)
///     }
///
///     fn read_partition(&self, _: &str, _: u64, _: &mut [u8]) -> Result<(), Self::Error> {
///         Err("absent")
///     }
/// }
///
/// assert_eq!(derive_set_vbh(&Absent, &AvbDigest::Sha256([0; 32])), None);
/// ```
pub fn derive_set_vbh(reader: &impl VbmetaReader, digest: &AvbDigest) -> Option<[u8; 32]> {
    ["", "_a", "_b"]
        .into_iter()
        .find_map(|suffix| candidate(reader, suffix, digest))
}

/// The main image of one slot, with libavb's `boot` fallback.
fn main_image(reader: &impl VbmetaReader, suffix: &str) -> Option<(String, u64)> {
    for name in [format!("vbmeta{suffix}"), format!("boot{suffix}")] {
        if let Some(size) = reader.partition_size(&name).ok()? {
            return Some((name, size));
        }
    }
    None
}

/// Walks one slot and returns its SHA-256 value after a digest match.
fn candidate(reader: &impl VbmetaReader, suffix: &str, digest: &AvbDigest) -> Option<[u8; 32]> {
    let (name, size) = main_image(reader, suffix)?;
    let root = read_image(reader, &name, size)?;
    let mut plan = Plan::new_unverified(&root).ok()?;
    for need in plan.needs() {
        let physical = need.partition_name(suffix);
        let size = reader.partition_size(&physical).ok()??;
        let walk = |offset: u64, out: &mut [u8]| reader.read_partition(&physical, offset, out);
        let _ = plan.supply_from(&need.name, size, walk);
        if !supplied(&plan, &need.name) {
            let image = read_image(reader, &physical, size)?;
            let _ = plan.supply(&need.name, &image);
        }
        if !supplied(&plan, &need.name) {
            return None;
        }
    }
    let (algorithm, expected) = match digest {
        AvbDigest::Sha256(bytes) => (HashAlg::Sha256, bytes.as_slice()),
        AvbDigest::Sha512(bytes) => (HashAlg::Sha512, bytes.as_slice()),
    };
    if plan.vbmeta_digest_with(algorithm).digest != expected {
        return None;
    }
    plan.vbmeta_digest_with(HashAlg::Sha256)
        .digest
        .try_into()
        .ok()
}

/// Reports whether an image of the walk has its metadata recorded.
fn supplied(plan: &Plan, name: &str) -> bool {
    plan.walk_order()
        .iter()
        .any(|node| node.name == name && node.metadata.is_some())
}

/// Read one image with libavb's footer selection.
fn read_image(reader: &impl VbmetaReader, name: &str, size: u64) -> Option<Vec<u8>> {
    let (offset, length) = if name.starts_with("vbmeta") {
        (0, size.min(VBMETA_MAX_SIZE) as usize)
    } else {
        match vbmd_extent(size, |offset, out| reader.read_partition(name, offset, out)) {
            Ok(extent) => (extent.offset, usize::try_from(extent.size).ok()?),
            Err(ExtractError::Malformed(_)) => (0, size.min(VBMETA_MAX_SIZE) as usize),
            Err(_) => return None,
        }
    };
    if length < HEADER_SIZE || length > VBMETA_MAX_SIZE as usize {
        return None;
    }
    let mut bytes = vec![0; length];
    reader.read_partition(name, offset, &mut bytes).ok()?;
    Some(bytes)
}
