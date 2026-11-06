//! The stock ABL VBH derivation: a digest match over real and synthetic sources.

use std::collections::BTreeMap;
use std::path::Path;

use abl_keys::vbh::{VbmetaReader, derive_set_vbh};
use abl_keys::{extract_vbmd, sha256, sha512};
use avb_format::{
    AvbDigest, CHAIN_PARTITION_FLAG_DO_NOT_USE_AB, DESCRIPTOR_TAG_CHAIN_PARTITION, FOOTER_SIZE,
    Footer, HEADER_SIZE, exact_metadata, replacement_footer,
};

const CAPTURE: &str =
    "/home/vivy/Projects/efisp-projects/gbl_root_canoe/.work/recovery-diagnosis-20260906/device";
const CHAINS: &str = "/home/vivy/Projects/efisp-projects/.work/phone-layout/20261004T013922Z";
const EVIDENCE_VBH: &str = "bc9bbd83c4be79f36d5c9b1724a865f83d8c26c3c76f96abe4c7fd082d7ccc47";
const EVIDENCE_TOTAL: u64 = 19776;

/// A source of partitions over captured files or synthetic bytes.
struct Files(BTreeMap<String, Vec<u8>>);

impl Files {
    fn captured(entries: &[(&str, String)]) -> Option<Self> {
        let mut map = BTreeMap::new();
        for (name, path) in entries {
            let path = Path::new(path);
            if !path.is_file() {
                eprintln!("SKIP: required capture is absent: {}", path.display());
                return None;
            }
            map.insert(
                name.to_string(),
                std::fs::read(path).expect("capture is readable"),
            );
        }
        Some(Self(map))
    }

    fn synthetic(entries: &[(&str, Vec<u8>)]) -> Self {
        Self(
            entries
                .iter()
                .map(|(name, bytes)| (name.to_string(), bytes.clone()))
                .collect(),
        )
    }
}

impl VbmetaReader for Files {
    type Error = &'static str;

    fn partition_size(&self, partition: &str) -> Result<Option<u64>, Self::Error> {
        Ok(self.0.get(partition).map(|bytes| bytes.len() as u64))
    }

    fn read_partition(
        &self,
        partition: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        let bytes = self.0.get(partition).ok_or("absent")?;
        let start = usize::try_from(offset).map_err(|_| "offset")?;
        let end = start.checked_add(out.len()).ok_or("overflow")?;
        out.copy_from_slice(bytes.get(start..end).ok_or("short read")?);
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One vbmeta image with an empty authentication block and the given auxiliary block.
fn image(auxiliary: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; HEADER_SIZE];
    image[..4].copy_from_slice(b"AVB0");
    image[4..8].copy_from_slice(&1u32.to_be_bytes());
    let padded = auxiliary.len().next_multiple_of(64);
    image[20..28].copy_from_slice(&(padded as u64).to_be_bytes());
    image[96..104].copy_from_slice(&0u64.to_be_bytes());
    image[104..112].copy_from_slice(&(auxiliary.len() as u64).to_be_bytes());
    image.extend_from_slice(auxiliary);
    image.resize(HEADER_SIZE + padded, 0);
    image
}

/// One chain-partition descriptor with an AOSP-shaped single-byte key.
fn chain(name: &str, location: u32, flags: u32) -> Vec<u8> {
    let mut payload = [0u8; 76];
    payload[..4].copy_from_slice(&location.to_be_bytes());
    payload[4..8].copy_from_slice(&(name.len() as u32).to_be_bytes());
    payload[8..12].copy_from_slice(&1u32.to_be_bytes());
    payload[12..16].copy_from_slice(&flags.to_be_bytes());
    let mut following = payload.len() + name.len() + 1;
    following += (8 - following % 8) % 8;
    let mut descriptor = vec![0u8; 16 + following];
    descriptor[..8].copy_from_slice(&DESCRIPTOR_TAG_CHAIN_PARTITION.to_be_bytes());
    descriptor[8..16].copy_from_slice(&(following as u64).to_be_bytes());
    descriptor[16..16 + payload.len()].copy_from_slice(&payload);
    descriptor[16 + payload.len()..16 + payload.len() + name.len()]
        .copy_from_slice(name.as_bytes());
    descriptor
}

/// Places an image behind a footer in a 1024-byte partition.
fn partitioned(image: &[u8]) -> Vec<u8> {
    let mut partition = vec![0u8; 1024];
    let offset = 128;
    partition[offset..offset + image.len()].copy_from_slice(image);
    let footer = partition.len() - FOOTER_SIZE;
    partition[footer..].copy_from_slice(&replacement_footer(Footer {
        original_image_size: 0,
        vbmeta_offset: offset as u64,
        vbmeta_size: image.len() as u64,
    }));
    partition
}

#[test]
fn real_capture_reproduces_the_recorded_vbh_from_source_partitions() {
    let Some(files) = Files::captured(&[
        ("vbmeta_a", format!("{CAPTURE}/vbmeta_a.img")),
        ("boot_a", format!("{CAPTURE}/boot_a.img")),
        ("dtbo_a", format!("{CAPTURE}/dtbo_a.img")),
        ("recovery_a", format!("{CAPTURE}/recovery_a.img")),
        ("vbmeta_system_a", format!("{CHAINS}/vbmeta_system_b.img")),
        ("vbmeta_vendor_a", format!("{CHAINS}/vbmeta_vendor_b.img")),
    ]) else {
        return;
    };
    assert_eq!(
        derive_set_vbh(&files, &AvbDigest::Sha512([0; 64])),
        None,
        "a wrong digest must not match"
    );

    // The exact extents in libavb order: the first image and the `vbmeta*`
    // chained images are whole partitions, the others are footered.
    let metadata = [
        exact_metadata(&files.0["vbmeta_a"])
            .expect("root metadata")
            .to_vec(),
        extract_vbmd(files.0["boot_a"].len() as u64, |offset, out: &mut [u8]| {
            let start = offset as usize;
            out.copy_from_slice(&files.0["boot_a"][start..start + out.len()]);
            Ok::<(), ()>(())
        })
        .expect("boot metadata"),
        extract_vbmd(files.0["dtbo_a"].len() as u64, |offset, out: &mut [u8]| {
            let start = offset as usize;
            out.copy_from_slice(&files.0["dtbo_a"][start..start + out.len()]);
            Ok::<(), ()>(())
        })
        .expect("dtbo metadata"),
        extract_vbmd(
            files.0["recovery_a"].len() as u64,
            |offset, out: &mut [u8]| {
                let start = offset as usize;
                out.copy_from_slice(&files.0["recovery_a"][start..start + out.len()]);
                Ok::<(), ()>(())
            },
        )
        .expect("recovery metadata"),
        exact_metadata(&files.0["vbmeta_system_a"])
            .expect("system metadata")
            .to_vec(),
        exact_metadata(&files.0["vbmeta_vendor_a"])
            .expect("vendor metadata")
            .to_vec(),
    ];
    let sequence = metadata.concat();
    assert_eq!(sequence.len() as u64, EVIDENCE_TOTAL);

    let vbh = derive_set_vbh(&files, &AvbDigest::Sha512(sha512(&sequence)))
        .expect("the captured chain reproduces its own digest");
    assert_eq!(hex(&vbh), EVIDENCE_VBH);
    // The recorded value is the SHA-256 over the same ordered extents.
    assert_eq!(hex(&sha256(&sequence)), EVIDENCE_VBH);
}

#[test]
fn do_not_use_ab_removes_the_slot_suffix() {
    let root = image(&chain("dtbo", 3, CHAIN_PARTITION_FLAG_DO_NOT_USE_AB));
    let chained = image(&[]);
    let digest = AvbDigest::Sha512(sha512(&[root.clone(), chained.clone()].concat()));
    let files = Files::synthetic(&[("vbmeta_a", root.clone()), ("dtbo", partitioned(&chained))]);
    assert_eq!(
        derive_set_vbh(&files, &digest),
        Some(sha256(&[root, chained].concat()))
    );

    // The suffixed name is not the image the descriptor names.
    let wrong = Files::synthetic(&[
        (
            "vbmeta_a",
            image(&chain("dtbo", 3, CHAIN_PARTITION_FLAG_DO_NOT_USE_AB)),
        ),
        ("dtbo_a", partitioned(&image(&[]))),
    ]);
    assert_eq!(derive_set_vbh(&wrong, &digest), None);
}

#[test]
fn unfootered_chained_image_is_read_from_offset_zero() {
    let root = image(&chain("boot", 4, 0));
    let chained = image(&[]);
    let mut partition = vec![0u8; 1024];
    partition[..chained.len()].copy_from_slice(&chained);
    let digest = AvbDigest::Sha512(sha512(&[root.clone(), chained.clone()].concat()));
    let files = Files::synthetic(&[("vbmeta", root.clone()), ("boot", partition)]);
    assert_eq!(
        derive_set_vbh(&files, &digest),
        Some(sha256(&[root, chained].concat()))
    );
}

#[test]
fn zero_rollback_location_is_refused_as_invalid_metadata() {
    let root = image(&chain("boot", 0, 0));
    let chained = image(&[]);
    let digest = AvbDigest::Sha512(sha512(&[root.clone(), chained.clone()].concat()));
    let files = Files::synthetic(&[("vbmeta", root), ("boot", partitioned(&chained))]);
    assert_eq!(derive_set_vbh(&files, &digest), None);
}
