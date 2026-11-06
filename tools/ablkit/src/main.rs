//! Host inspection of a Qualcomm ABL image and its embedded trust keys.
//!
//! ```text
//! ablkit extract <abl.img> [--out <loader.efi>]
//! ablkit keys <pe> [--json]
//! ablkit anchor <abl.img|pe> [--out <key.avbpubkey>]
//! ```
//!
//! `extract` writes the largest complete ARM64 LinuxLoader PE. `keys` reports
//! every distinct structurally valid AVB key. `anchor` writes the first AVB key,
//! which is the key the stock `AvbValidateVbmetaPublicKey` byte-compares
//! against.
//!
//! The input accepts either a PE or a firmware container. A PE is returned
//! unchanged by the bounded extractor.
//!
//! Hashing uses `sha2`. No external program is run. No key or loader is written
//! when extraction or the key scan fails.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn usage() -> ! {
    eprintln!(
        "usage: ablkit extract <abl.img> [--out <loader.efi>]\n\
         \x20      ablkit keys <pe> [--json]\n\
         \x20      ablkit anchor <abl.img|pe> [--out <key.avbpubkey>]"
    );
    std::process::exit(2)
}

/// Lower-case hex of a SHA-256 digest.
fn digest(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let hash = Sha256::digest(data);
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash.iter() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let limit = u64::try_from(abl_extract::MAX_INPUT).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > abl_extract::MAX_INPUT {
        return Err("ABL image exceeds 32 MiB".into());
    }
    Ok(bytes)
}

fn write_output(bytes: &[u8], out: Option<&Path>) -> std::io::Result<()> {
    match out {
        Some(path) => std::fs::write(path, bytes),
        None => std::io::stdout().write_all(bytes),
    }
}

fn parse_out<'a>(
    args: &'a [String],
    usage_text: &str,
) -> Result<(&'a str, Option<PathBuf>), Box<dyn std::error::Error>> {
    match args {
        [input] => Ok((input.as_str(), None)),
        [input, flag, out] if flag == "--out" => Ok((input.as_str(), Some(PathBuf::from(out)))),
        _ => {
            eprintln!("{usage_text}");
            std::process::exit(2)
        }
    }
}

fn extract(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (input, out) = parse_out(args, "usage: ablkit extract <abl.img> [--out <loader.efi>]")?;
    let input = Path::new(input);
    let image = read_bounded(input)?;
    let loader = abl_extract::extract_linuxloader(&image)?;
    eprintln!("fw_image_sha256={}", digest(&image));
    eprintln!("linuxloader_sha256={}", digest(&loader));
    write_output(&loader, out.as_deref())?;
    Ok(())
}

fn keys(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (input, json) = match args {
        [input] => (input, false),
        [input, flag] if flag == "--json" => (input, true),
        _ => {
            eprintln!("usage: ablkit keys <pe> [--json]");
            std::process::exit(2)
        }
    };
    let input = Path::new(input);
    let image = read_bounded(input)?;
    let keys = abl_keys::abl_keys(&image);
    if json {
        print!("{{\"keys\":[");
        for (index, key) in keys.keys().iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            print!(
                "{separator}{{\"anchor\":{},\"offset\":{},\"bits\":{},\"size\":{},\"sha256\":\"{}\"}}",
                index == 0,
                key.file_offset,
                key.num_bits,
                key.blob.len(),
                digest(&key.blob)
            );
        }
        println!("]}}");
    } else {
        for (index, key) in keys.keys().iter().enumerate() {
            println!(
                "avb-key anchor={} offset={} bits={} size={} sha256={}",
                index == 0,
                key.file_offset,
                key.num_bits,
                key.blob.len(),
                digest(&key.blob)
            );
        }
    }
    if keys.is_empty() {
        eprintln!("ablkit: no AVB public key found");
    }
    Ok(())
}

fn anchor(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (input, out) = parse_out(
        args,
        "usage: ablkit anchor <abl.img|pe> [--out <key.avbpubkey>]",
    )?;
    let input = Path::new(input);
    let image = read_bounded(input)?;
    // A PE input is scanned as given. Only a firmware container is extracted.
    let loader = if image.starts_with(b"MZ") {
        image.clone()
    } else {
        abl_extract::extract_linuxloader(&image)?
    };
    let key = abl_keys::AblKeys::scan(&loader)
        .anchor()
        .map(|key| key.blob.clone())
        .ok_or("ABL LinuxLoader has no embedded AVB public key")?;
    eprintln!("fw_image_sha256={}", digest(&image));
    eprintln!("linuxloader_sha256={}", digest(&loader));
    eprintln!("key_sha256={}", digest(&key));
    write_output(&key, out.as_deref())?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        usage()
    };
    match command.as_str() {
        "extract" => extract(rest),
        "keys" => keys(rest),
        "anchor" => anchor(rest),
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ablkit failed error={error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_is_lower_case_sha256() {
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
