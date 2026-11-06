//! Real canoe evidence for the ABL's anchored plan, properties, VBH and
//! authority conventions. Every external capture is a clean skip when absent.

use std::path::Path;

use abl_keys::{
    AblKey, AblKeys, AblPlan, AblVerdict, CmdlineDigest, Defect, HashAlg, Kind,
    VBMETA_FLAG_VERIFICATION_DISABLED, extract_vbmd, inspect, sha256, sha512_concat,
};

const CAPTURE: &str =
    "/home/vivy/Projects/efisp-projects/gbl_root_canoe/.work/recovery-diagnosis-20260906/device";
const CHAINS: &str = "/home/vivy/Projects/efisp-projects/.work/phone-layout/20261004T013922Z";
const CANOE_PE: &str = "/home/vivy/Ghidra/inputs/canoe-abl-parallel-20260902/abl_b.LinuxLoader.efi";
const CANOE_KEY_OFFSET: usize = 452022;
const ROOT_KEY: &str = "8d897f62492ea617f777bad41a5711ab621fcac1efc1865b890328ee8c3853bb";
const SYSTEM_KEY: &str = "1aef65cb06c0146a2071ed14eeb05f09a296bef1e20d0a1e81ef813bed0599c2";
const EVIDENCE_VBH: &str = "bc9bbd83c4be79f36d5c9b1724a865f83d8c26c3c76f96abe4c7fd082d7ccc47";
const EVIDENCE_TOTAL: u64 = 19776;

fn read(path: &str) -> Option<Vec<u8>> {
    let path = Path::new(path);
    if !path.is_file() {
        eprintln!("SKIP: required capture is absent: {}", path.display());
        return None;
    }
    Some(std::fs::read(path).expect("capture is readable"))
}

fn footered_metadata(path: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("partition is readable");
    let size = bytes.len() as u64;
    let mut reader = |at: u64, out: &mut [u8]| -> Result<(), String> {
        let start = usize::try_from(at).map_err(|_| "offset does not fit".to_owned())?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| "range overflow".to_owned())?;
        let part = bytes
            .get(start..end)
            .ok_or_else(|| "short read".to_owned())?;
        out.copy_from_slice(part);
        Ok(())
    };
    extract_vbmd(size, &mut reader).expect("footer metadata")
}

/// A slice-backed `read_at`, the shape a file or a block source presents.
fn reader(image: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), String> + '_ {
    move |at: u64, out: &mut [u8]| {
        let start = usize::try_from(at).map_err(|_| "offset does not fit".to_owned())?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| "range overflow".to_owned())?;
        out.copy_from_slice(
            image
                .get(start..end)
                .ok_or_else(|| "short read".to_owned())?,
        );
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn canon_keys() -> Option<(Vec<u8>, AblKeys)> {
    let pe = read(CANOE_PE)?;
    let keys = abl_keys::abl_keys(&pe);
    Some((pe, keys))
}

#[test]
fn real_capture_walk_verifies_every_image_and_reproduces_the_recorded_digest() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    for name in ["boot", "dtbo", "recovery"] {
        if !Path::new(&format!("{CAPTURE}/{name}_a.img")).is_file() {
            eprintln!("SKIP: required capture is absent: {CAPTURE}/{name}_a.img");
            return;
        }
    }
    let (Some(system), Some(vendor)) = (
        read(&format!("{CHAINS}/vbmeta_system_b.img")),
        read(&format!("{CHAINS}/vbmeta_vendor_b.img")),
    ) else {
        return;
    };
    let Some((_, keys)) = canon_keys() else {
        return;
    };
    let mut plan =
        AblPlan::anchored(&root, &keys).expect("the real root verifies against the ABL key");
    assert!(plan.is_anchored());
    assert_eq!(plan.root_metadata().len(), 8448);
    assert_eq!(hex(&plan.root_info().public_key_sha256), ROOT_KEY);
    assert_eq!(plan.root_algorithm(), 2);
    assert_eq!(plan.digest_algorithm(), HashAlg::Sha256);
    assert_eq!(plan.root_properties().os_version.as_deref(), Some("16"));
    assert_eq!(
        plan.root_properties().security_patch.as_deref(),
        Some("2026-08-01")
    );

    // The walk alone, before any image is supplied, yields the five needs in
    // libavb visit order, with the right kinds and demanded keys.
    let needs = plan.needs();
    let names: Vec<&str> = needs.iter().map(|need| need.name.as_str()).collect();
    assert_eq!(
        names,
        ["boot", "dtbo", "recovery", "vbmeta_system", "vbmeta_vendor"]
    );
    assert_eq!(
        needs.iter().map(|need| need.kind).collect::<Vec<_>>(),
        [
            Kind::Footered,
            Kind::Footered,
            Kind::Footered,
            Kind::Vbmeta,
            Kind::Vbmeta
        ]
    );
    assert_eq!(
        needs
            .iter()
            .map(|need| need.rollback_index_location)
            .collect::<Vec<_>>(),
        [4, 3, 1, 2, 5]
    );
    assert_eq!(hex(&needs[0].expected_key_sha256), ROOT_KEY);
    assert_eq!(hex(&needs[3].expected_key_sha256), SYSTEM_KEY);
    assert_eq!(hex(&needs[4].expected_key_sha256), SYSTEM_KEY);
    assert!(needs.iter().all(|need| need.parent == "vbmeta"));

    for (name, size) in [("boot", 2368usize), ("dtbo", 2240), ("recovery", 2240)] {
        let metadata = footered_metadata(&format!("{CAPTURE}/{name}_a.img"));
        assert_eq!(metadata.len(), size);
        let accepted = plan
            .supply(name, &metadata)
            .unwrap_or_else(|rejected| panic!("{rejected}"));
        assert_eq!(accepted.kind, Kind::Footered);
        assert!(accepted.anchored);
        assert_eq!(accepted.metadata_len, size);
    }
    assert_eq!(
        plan.supply("vbmeta_system", &system).unwrap().metadata_len,
        2624
    );
    assert_eq!(
        plan.supply("vbmeta_vendor", &vendor).unwrap().metadata_len,
        1856
    );
    assert!(plan.complete(), "rejected: {:?}", plan.rejected());
    assert!(plan.missing().is_empty());

    let digest = plan.vbmeta_digest();
    assert_eq!(digest.hex(), EVIDENCE_VBH);
    assert_eq!(digest.total_size, EVIDENCE_TOTAL);
    assert_eq!(digest.algorithm, HashAlg::Sha256);

    assert_eq!(
        plan.libavb_cmdline_digest(),
        Some(CmdlineDigest {
            hash_alg: HashAlg::Sha256,
            digest: digest.digest.clone(),
            size: EVIDENCE_TOTAL,
        })
    );
    let sha512_digest = plan.vbmeta_digest_with(HashAlg::Sha512);
    assert_eq!(sha512_digest.algorithm, HashAlg::Sha512);
    assert_eq!(sha512_digest.digest.len(), 64);
    assert_eq!(sha512_digest.total_size, EVIDENCE_TOTAL);
    assert_ne!(sha512_digest.hex(), EVIDENCE_VBH);
    let keys: Vec<Vec<u8>> = plan
        .supplied_info()
        .iter()
        .map(|(_, info)| info.public_key.clone())
        .collect();
    assert_eq!(
        plan.authority_sha512(),
        Some(sha512_concat(
            &keys.iter().map(Vec::as_slice).collect::<Vec<_>>()
        ))
    );
    assert_ne!(
        plan.authority_sha512().map(|authority| hex(&authority)),
        Some(sha512_digest.hex())
    );
    let deduped: Vec<&[u8]> = {
        let mut unique: Vec<&[u8]> = Vec::new();
        for key in &keys {
            if !unique.contains(&key.as_slice()) {
                unique.push(key.as_slice());
            }
        }
        unique
    };
    assert_ne!(
        sha512_concat(&deduped),
        sha512_concat(&keys.iter().map(Vec::as_slice).collect::<Vec<_>>())
    );
}

#[test]
fn real_capture_unanchored_and_foreign_key_root() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    let root_key = sha256(&inspect(&root).unwrap().public_key);

    let plan = AblPlan::new(&root).expect("the root self-verifies");
    assert_eq!(
        plan.root_verdict(),
        AblVerdict::Verified {
            key_sha256: root_key,
            anchored: false,
        }
    );
    assert!(!plan.is_anchored());

    let system_key = inspect(&system).unwrap().public_key;
    let foreign = AblKey {
        file_offset: 0,
        num_bits: 2048,
        sha256: sha256(&system_key),
        blob: system_key.clone(),
    };
    assert_eq!(
        AblPlan::anchored(&root, &AblKeys::from_keys(vec![foreign.clone()])).unwrap_err(),
        AblVerdict::KeyMismatch {
            expected: sha256(&system_key),
            actual: root_key,
        }
    );
    assert_eq!(
        AblPlan::anchored(&root, &AblKeys::default()).unwrap_err(),
        AblVerdict::Malformed(Defect::NoTrustedKey)
    );

    let later = AblKey {
        file_offset: CANOE_KEY_OFFSET,
        num_bits: 4096,
        sha256: root_key,
        blob: inspect(&root).unwrap().public_key,
    };
    let keys = AblKeys::from_keys(vec![foreign.clone(), later.clone()]);
    let unanchored = AblPlan::anchored(&root, &keys).unwrap_err();
    assert_eq!(
        unanchored,
        AblVerdict::Verified {
            key_sha256: root_key,
            anchored: false,
        }
    );
    assert!(unanchored.anchored() == Some(false));
    assert!(unanchored.is_verified());

    let plan = AblPlan::anchored_with_extra(&root, &keys, &[later])
        .expect("the extra trusted key anchors the root");
    assert!(plan.is_anchored());
    assert_eq!(
        plan.trust_anchor().map(|key| key.sha256),
        Some(sha256(&system_key))
    );
    assert_eq!(plan.trusted_keys().len(), 2);
    assert_eq!(plan.key_set().len(), 2);
}

#[test]
fn real_capture_vendor_bytes_under_the_system_name_are_rejected() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let (Some(system), Some(vendor)) = (
        read(&format!("{CHAINS}/vbmeta_system_b.img")),
        read(&format!("{CHAINS}/vbmeta_vendor_b.img")),
    ) else {
        return;
    };
    let Some((_, keys)) = canon_keys() else {
        return;
    };

    let mut plan = AblPlan::anchored(&root, &keys).unwrap();
    let rejected = plan.supply("vbmeta_system", &vendor).unwrap_err();
    assert_eq!(
        rejected.verdict,
        AblVerdict::WrongPartition {
            need: "vbmeta_system".to_owned(),
            covered: vec!["vendor".to_owned()],
        }
    );
    assert!(plan.supply("vbmeta_vendor", &vendor).is_ok());
    assert!(plan.supply("vbmeta_system", &system).is_ok());
}

#[test]
fn real_capture_reader_path_reproduces_the_recorded_digest() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some((_, keys)) = canon_keys() else {
        return;
    };
    let mut plan = AblPlan::anchored(&root, &keys).expect("anchored root");

    for name in ["boot", "dtbo", "recovery"] {
        let path = format!("{CAPTURE}/{name}_a.img");
        let Some(image) = read(&path) else {
            return;
        };
        let size = image.len() as u64;
        let accepted = plan
            .supply_from(name, size, reader(&image))
            .unwrap_or_else(|rejected| panic!("{name}: {rejected}"));
        assert!(accepted.anchored);
    }
    for (name, path) in [
        ("vbmeta_system", format!("{CHAINS}/vbmeta_system_b.img")),
        ("vbmeta_vendor", format!("{CHAINS}/vbmeta_vendor_b.img")),
    ] {
        let Some(image) = read(&path) else {
            return;
        };
        let size = image.len() as u64;
        plan.supply_from(name, size, reader(&image))
            .unwrap_or_else(|rejected| panic!("{name}: {rejected}"));
    }
    assert!(plan.complete());
    assert_eq!(plan.vbmeta_digest().hex(), EVIDENCE_VBH);
    assert_eq!(plan.vbmeta_digest().total_size, EVIDENCE_TOTAL);

    let mut plan = AblPlan::anchored(&root, &keys).unwrap();
    let rejected = plan
        .supply_from(
            "vbmeta_system",
            4096,
            |_, _: &mut [u8]| Err("io".to_owned()),
        )
        .unwrap_err();
    assert_eq!(
        rejected.verdict,
        AblVerdict::Malformed(Defect::Read("io".to_owned()))
    );
}

#[test]
fn real_capture_duplicate_and_unknown_partitions_are_typed() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let Some(system) = read(&format!("{CHAINS}/vbmeta_system_b.img")) else {
        return;
    };
    let Some((_, keys)) = canon_keys() else {
        return;
    };
    let mut plan = AblPlan::anchored(&root, &keys).unwrap();
    assert_eq!(
        plan.supply("init_boot", &system).unwrap_err().verdict,
        AblVerdict::Malformed(Defect::UnknownPartition("init_boot".to_owned()))
    );
    assert!(plan.supply("vbmeta_system", &system).is_ok());
    assert_eq!(
        plan.supply("vbmeta_system", &system).unwrap_err().verdict,
        AblVerdict::Malformed(Defect::AlreadySupplied("vbmeta_system".to_owned()))
    );
    assert_eq!(plan.needs().len(), 4);
}

#[test]
fn disabled_root_keeps_a_structural_walk_and_no_cmdline_digest() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let mut disabled = root.clone();
    disabled[120..124].copy_from_slice(&VBMETA_FLAG_VERIFICATION_DISABLED.to_be_bytes());
    let flagged = AblPlan::new_unverified(&disabled).expect("still structurally valid");
    assert_eq!(flagged.root_verdict(), AblVerdict::HashMismatch);
    assert_eq!(flagged.libavb_cmdline_digest(), None);
    assert_eq!(flagged.vbmeta_digest().algorithm, HashAlg::Sha256);
    assert_eq!(
        flagged.vbmeta_digest().hex(),
        hex(&sha256(
            &disabled[..inspect(&disabled).expect("header").size]
        ))
    );
}

#[test]
fn authority_hash_requires_every_image_to_be_supplied() {
    let Some(root) = read(&format!("{CAPTURE}/vbmeta_a.img")) else {
        return;
    };
    let plan = AblPlan::new(&root).expect("root self-verifies");
    assert_eq!(
        plan.authority_sha512(),
        None,
        "the real root chains five images, so a partial key set is not the authority value"
    );
}
