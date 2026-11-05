// SPDX-License-Identifier: MIT
//! `qcom-arb`: the Qualcomm `xbl_config` anti-rollback probe.
//!
//! ```text
//! qcom-arb scan IMAGE             -> "arb major=1 minor=2 arb=5", or "arb none"
//! qcom-arb check TARGET CURRENT   -> exit 0: allowed; exit 1: refused
//! ```
//!
//! `check` is the decision of [`qcom_fw::arb::seal`]. A refusal prints its
//! reason on stdout, which the maos-bootctl `ota.seal` hook reports. A log
//! line goes to stderr. A usage error exits 2, which also refuses a seal.

use std::io::Read;
use std::process::ExitCode;

use qcom_fw::arb::{self, Seal};

/// The bytes read from an image. [`arb::MAX_SEGMENT`] bounds the segment the
/// scan accepts, so a partition node is read only that far.
fn read(path: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(arb::MAX_SEGMENT).read_to_end(&mut bytes))
        .map_err(|error| format!("{path}: {error}"))?;
    Ok(bytes)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["scan", image] => match read(image) {
            Ok(bytes) => {
                match arb::scan(&bytes) {
                    Some(arb) => println!(
                        "arb major={} minor={} arb={}",
                        arb.major, arb.minor, arb.arb
                    ),
                    None => println!("arb none"),
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("qcom-arb: {error}");
                ExitCode::FAILURE
            }
        },
        ["check", target, current] => {
            let (target, current) = (read(target), read(current));
            match arb::seal(
                target.as_deref().map_err(Clone::clone),
                current.as_deref().map_err(Clone::clone),
            ) {
                Seal::Allow(line) => {
                    eprintln!("qcom-arb: {line}");
                    ExitCode::SUCCESS
                }
                Seal::Refuse(reason) => {
                    println!("{reason}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: qcom-arb scan IMAGE | qcom-arb check TARGET CURRENT");
            ExitCode::from(2)
        }
    }
}
