//! Qualcomm firmware image probes for host and Android tools.
//!
//! The crate root extracts the LinuxLoader PE of an `abl` image, bounded and
//! byte-only. [`arb`] reads the anti-rollback metadata of an `xbl_config`
//! image. maOS core crates do not depend on this crate (D81).
//!
//! The extractor is a port of the MIT-licensed `ablfvextractor` crate (same
//! author). The firmware container may hold nested LZMA-alone streams, so the
//! extractor is the byte-only equivalent of extractfv's default largest-PE
//! operation. Provenance: gbl_root_canoe/submodules/ablfvextractor/src/lib.rs
//! at commit 4d7d8ba6666a966ad224b0efc3be0e1ca9a1c753.
pub mod arb;

use lzma_rs::decompress::{Options, UnpackedSize};
use std::io::{self, Cursor, Write};

pub const MAX_INPUT: usize = 32 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_TOTAL: usize = 128 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 512;

/// Bytes of an RSA-2048 modulus, whose only accepted exponent is 65537.
const RSA2048_MODULUS: usize = 256;

#[derive(Debug)]
pub enum Error {
    Size,
    Budget,
    Missing,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Size => "ABL extraction input must be 64 bytes to 32 MiB",
            Self::Budget => "ABL extraction exceeded its bounded scan budget",
            Self::Missing => "ABL contains no complete ARM64 EFI application",
        })
    }
}

impl std::error::Error for Error {}

struct LimitedOutput {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("LZMA output limit exceeded"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Validate the entire PE section table and return the occupied file length.
/// Reject truncation rather than returning a partial loader.
fn pe_size(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0"
        || u16_at(data, pe + 4)? != 0xaa64
        || u16_at(data, pe + 24)? != 0x20b
        || u16_at(data, pe + 0x5c)? != 10
    {
        return None;
    }
    let count = u16_at(data, pe + 6)? as usize;
    let optional = u16_at(data, pe + 20)? as usize;
    if count == 0 || count > 96 || optional < 112 {
        return None;
    }
    let table = pe.checked_add(24)?.checked_add(optional)?;
    let end = table.checked_add(count.checked_mul(40)?)?;
    let mut size = u32_at(data, pe + 0x54)? as usize;
    if end > data.len() || size < end {
        return None;
    }
    for n in 0..count {
        let section = table + n * 40;
        let bytes = u32_at(data, section + 16)? as usize;
        let offset = u32_at(data, section + 20)? as usize;
        size = size.max(offset.checked_add(bytes)?);
    }
    (size <= data.len() && size <= MAX_OUTPUT).then_some(size)
}

struct Scan {
    best: Vec<u8>,
    best_remaining: usize,
    total: usize,
    attempts: usize,
}
impl Scan {
    fn scan(&mut self, data: &[u8], depth: usize) -> Result<(), Error> {
        if depth > 5 {
            return Ok(());
        }
        self.total = self.total.checked_add(data.len()).ok_or(Error::Budget)?;
        if self.total > MAX_TOTAL {
            return Err(Error::Budget);
        }
        for (at, signature) in data.windows(2).enumerate() {
            if signature == b"MZ"
                && data.len() - at > self.best_remaining
                && let Some(size) = pe_size(&data[at..])
            {
                self.best = data[at..at + size].to_vec();
                self.best_remaining = data.len() - at;
            }
        }
        if depth == 5 {
            return Ok(());
        }
        for (at, signature) in data.windows(3).enumerate() {
            if signature != [0x5d, 0, 0] {
                continue;
            }
            self.attempts += 1;
            if self.attempts > MAX_ATTEMPTS {
                return Err(Error::Budget);
            }
            let compressed = &data[at..data.len().min(at + 0x200000)];
            // Raw LZMA properties+payload (UEFI) first, then LZMA-alone.
            // This is the same order as extractfv's synthetic 13-byte header.
            for size in [
                UnpackedSize::UseProvided(None),
                UnpackedSize::ReadFromHeader,
            ] {
                let options = Options {
                    unpacked_size: size,
                    memlimit: Some(MAX_OUTPUT),
                    allow_incomplete: false,
                };
                let mut output = LimitedOutput {
                    bytes: Vec::new(),
                    limit: MAX_OUTPUT.min(MAX_TOTAL - self.total),
                };
                if lzma_rs::lzma_decompress_with_options(
                    &mut Cursor::new(compressed),
                    &mut output,
                    &options,
                )
                .is_ok()
                    && output.bytes.len() > 64
                {
                    self.scan(&output.bytes, depth + 1)?;
                    break;
                }
            }
        }
        // Scanning all bytes already covers uncompressed nested FV ranges;
        // recursing into them again adds no candidates and duplicates budgets.
        Ok(())
    }
}

/// Extract the largest complete ARM64 EFI application from an `abl` partition.
pub fn extract_linuxloader(input: &[u8]) -> Result<Vec<u8>, Error> {
    if !(64..=MAX_INPUT).contains(&input.len()) {
        return Err(Error::Size);
    }
    let mut scan = Scan {
        best: Vec::new(),
        best_remaining: 0,
        total: 0,
        attempts: 0,
    };
    scan.scan(input, 0)?;
    if scan.best.is_empty() {
        Err(Error::Missing)
    } else {
        Ok(scan.best)
    }
}

/// Every 256-byte big-endian RSA-2048 modulus immediately followed by `01 00 01`
/// (e = 65537), in file order, with the modulus odd and its top bit set.
pub fn scan_rsa2048_e65537(pe: &[u8]) -> Vec<[u8; RSA2048_MODULUS]> {
    let mut moduli = Vec::new();
    for record in pe.windows(RSA2048_MODULUS + 3) {
        if record[RSA2048_MODULUS..] != [1, 0, 1]
            || record[0] & 0x80 == 0
            || record[RSA2048_MODULUS - 1] & 1 == 0
        {
            continue;
        }
        let modulus: [u8; RSA2048_MODULUS] = record[..RSA2048_MODULUS].try_into().unwrap();
        if !moduli.contains(&modulus) {
            moduli.push(modulus);
        }
    }
    moduli
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTKEY: &[u8] = include_bytes!("../tests/fixtures/testkey_rsa4096_pub.bin");

    #[test]
    fn reject_invalid_and_truncated() {
        for bytes in [vec![], vec![0; 128], b"MZ".to_vec(), vec![0xff; 4096]] {
            assert!(extract_linuxloader(&bytes).is_err());
        }
        assert!(matches!(extract_linuxloader(&[0; 63]), Err(Error::Size)));
        assert!(matches!(extract_linuxloader(&[0; 64]), Err(Error::Missing)));
    }

    #[test]
    fn reject_decompression_bomb_budget() {
        assert!(extract_linuxloader(&[0x5d, 0, 0].repeat(1024)).is_err());
    }

    #[test]
    fn rsa2048_scanner_matches_only_the_full_encoding() {
        let mut modulus = [0x7f_u8; RSA2048_MODULUS];
        modulus[0] = 0xff;
        modulus[RSA2048_MODULUS - 1] = 0x01;
        let mut record = modulus.to_vec();
        record.extend_from_slice(&[1, 0, 1]);
        assert_eq!(scan_rsa2048_e65537(&record), vec![modulus]);

        // Equal moduli are reported once, in file order.
        let mut repeated = record.clone();
        repeated.extend_from_slice(&record);
        assert_eq!(scan_rsa2048_e65537(&repeated), vec![modulus]);

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
