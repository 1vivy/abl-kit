//! Real ABL key-scan evidence. Each capture is external; an absent capture is a
//! clean skip, not a failure.

use std::path::Path;

use abl_keys::{AblKeys, abl_keys, sha256};

const CANOE_PE: &str = "/home/vivy/Ghidra/inputs/canoe-abl-parallel-20260902/abl_b.LinuxLoader.efi";
const ABLREPO: &str = "/home/vivy/Projects/efisp-projects/gbl_root_canoe/ablrepo";
const CANOE_KEY_OFFSET: usize = 452022;
const ROOT_KEY: &str = "8d897f62492ea617f777bad41a5711ab621fcac1efc1865b890328ee8c3853bb";

fn read(path: &str) -> Option<Vec<u8>> {
    let path = Path::new(path);
    if !path.is_file() {
        eprintln!("SKIP: required capture is absent: {}", path.display());
        return None;
    }
    Some(std::fs::read(path).expect("capture is readable"))
}

#[test]
fn abl_keys_recovers_the_canoe_key_and_refuses_a_tampered_one() {
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);
    for key in keys.keys() {
        eprintln!(
            "abl_keys: offset {} bits {} sha256 {}",
            key.file_offset,
            key.num_bits,
            abl_keys_hex(&key.sha256)
        );
    }
    let found = keys
        .keys()
        .iter()
        .find(|key| key.file_offset == CANOE_KEY_OFFSET)
        .expect("the embedded OEM key is recovered by structure alone");
    assert_eq!(found.num_bits, 4096);
    assert_eq!(abl_keys_hex(&found.sha256), ROOT_KEY);
    assert_eq!(found.blob.len(), 1032);

    // Corrupting n0inv must make the blob stop being reported: the arithmetic
    // self-consistency checks are what separate a key from a byte pattern.
    let mut tampered = pe.clone();
    tampered[CANOE_KEY_OFFSET + 4] ^= 0xff;
    assert!(
        !abl_keys(&tampered)
            .keys()
            .iter()
            .any(|key| key.file_offset == CANOE_KEY_OFFSET)
    );
    // Corrupting rr (the last byte of the blob) likewise.
    let mut tampered = pe.clone();
    let last = CANOE_KEY_OFFSET + found.blob.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        !abl_keys(&tampered)
            .keys()
            .iter()
            .any(|key| key.file_offset == CANOE_KEY_OFFSET)
    );

    // The trust anchor is the first key in file order, which on this PE is the
    // key the ABL byte-compares against.
    assert_eq!(
        keys.anchor().map(|key| key.file_offset),
        Some(CANOE_KEY_OFFSET)
    );
    assert_eq!(
        keys.anchor().map(|key| abl_keys_hex(&key.sha256)),
        Some(ROOT_KEY.to_owned())
    );
}

#[test]
fn ablrepo_first_key_per_product_is_the_anchor() {
    let entries = match std::fs::read_dir(ABLREPO) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("SKIP: {ABLREPO} is not readable: {error}");
            return;
        }
    };
    type Product = (String, usize, Option<(String, usize, u32)>, usize);
    let mut products: Vec<Product> = Vec::new();
    for entry in entries.flatten() {
        let image = entry.path().join("abl.img");
        if !image.is_file() {
            continue;
        }
        let bytes = std::fs::read(&image).expect("fixture is readable");
        let keys = AblKeys::scan(&bytes);
        let anchor = keys
            .anchor()
            .map(|key| (abl_keys_hex(&key.sha256), key.file_offset, key.num_bits));
        if let Some((_, offset, bits)) = &anchor {
            assert!(matches!(*bits, 2048 | 4096 | 8192));
            assert!(
                keys.keys().iter().all(|key| key.file_offset >= *offset),
                "keys are reported in file order, so the anchor is the first"
            );
        }
        products.push((
            entry.file_name().to_string_lossy().into_owned(),
            bytes.len(),
            anchor,
            keys.len(),
        ));
    }
    products.sort();
    assert_eq!(
        products.len(),
        13,
        "the ablrepo fixture set is 13 products; found {}",
        products.len()
    );
    let keyed = products.iter().filter(|row| row.2.is_some()).count();
    for (product, size, anchor, count) in &products {
        match anchor {
            Some((digest, offset, bits)) => eprintln!(
                "ablrepo {product}: {size} bytes, anchor {digest} ({bits} bits) @ {offset}, {count} key(s)"
            ),
            None => eprintln!(
                "ablrepo {product}: {size} bytes, no structurally complete AVB key in the file"
            ),
        }
    }
    eprintln!("ablrepo: {keyed} of 13 fixtures carry a complete AVB key");
}

#[test]
fn abl_keys_finds_nothing_in_random_data() {
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
}

#[test]
fn key_hash_matches_the_blob_hash() {
    let Some(pe) = read(CANOE_PE) else {
        return;
    };
    let keys = abl_keys(&pe);
    for key in keys.keys() {
        assert_eq!(key.sha256, sha256(&key.blob));
    }
}

fn abl_keys_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
