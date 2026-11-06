# abl-kit

Reusable Rust code for Qualcomm stock-ABL conventions. AVB itself is not here.
The AOSP AVB format comes from [`avb-kit`](https://github.com/1vivy/avb-kit).

License: Apache-2.0. The libraries are `no_std`. Only the CLI uses `std`.

## Crates

| Crate | Runtime | Dependencies | Purpose |
|---|---|---|---|
| `abl-extract` | `std` | `lzma-rs` | Find the LinuxLoader PE in an `abl` firmware container |
| `abl-keys` | `no_std` + `alloc` | `avb-format`, `avb-verify`, `avb-chain` | Scan a LinuxLoader PE for AVB public keys, keep file order, select the first key as the stock anchor, scan for raw RSA-2048 moduli, and hold the ABL plan conventions |
| `tools/ablkit` | `std` | the crates above | Host CLI |

## Tool

```
ablkit extract <abl.img> [--out <file>]
ablkit keys <pe> [--json]
ablkit anchor <abl.img|pe> [--out <file>]
```

- `extract` writes the largest complete ARM64 LinuxLoader PE.
- `keys` lists each AVB key blob with its offset, its size and its SHA-256.
- `anchor` writes the first key blob, which is the input to
  `esp-gen --avb-root-key` and `profile-mint --anchor-key`.

The tool reads and writes files that the caller names. It does not write to a
device.

## Conventions

- The stock ABL byte-compares the root `vbmeta` public key against the first key
  in its compiled-in key array. `abl-keys` reports that first key as the anchor.
- A later key is reported but is not trusted. A caller that trusts it says so
  explicitly.
- The fixed SHA-256 metadata digest that the ABL stores as its VBH belongs to
  the ABL convention layer, not to `avb-chain`.
- See `docs/anchor.md` for the source references and the limits.

## Out of scope

- AVB framing, signatures and the chain walk. These are in `avb-kit`.
- `xbl_config` anti-rollback metadata. maOS keeps it in `qcom-arb`.
- Wrapper packaging: ablwrap owns `pack`, `resolve` and `avbview`.
- Platform trust policy: ODP owns its anchor and EFVS decisions.

## Checks

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-uefi -p abl-keys
```
