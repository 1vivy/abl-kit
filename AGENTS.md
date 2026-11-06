# Working rules for abl-kit

This repository holds Qualcomm stock-ABL conventions. Read `README.md` and
`docs/anchor.md` before a change.

## Boundary

- An item belongs here when a stock ABL does it, and AOSP AVB does not define
  it. Examples: the first embedded key as the trust anchor, the VBH value, the
  `boot` property preference, the LinuxLoader container.
- The AVB format belongs to avb-kit. Do not copy a parser or a signature
  routine into this repository.
- Product policy stays with its owner. Examples: maOS anti-rollback for
  `xbl_config`, ablwrap packaging, ODP platform trust and EFVS.
- A convention needs a source reference. Use the CLO path or the captured
  binary evidence. Do not state a stock behavior from memory.

## Crates

- `abl-extract` is `std` and bounded. It never returns a partial loader.
- `abl-keys` is `no_std + alloc`. It depends on avb-kit by path until avb-kit
  has a remote. Then the dependency becomes a git dependency.
- The scan reports offsets and keeps file order. Do not sort a key list.
- Trust is explicit. A later key is reported, not trusted.

## Style

- Documentation and commit messages use ASD-STE100 style: short sentences, one
  instruction per sentence, active voice, no semicolons.
- Docs describe the current implementation only.

## Checks

Run these before a commit:

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-uefi -p abl-keys
```

Commit with `git commit -S`. Use the agent key, not the owner key.
