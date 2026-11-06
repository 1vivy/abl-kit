# abl-extract provenance

`crates/abl-extract` is the MIT-licensed Qualcomm LinuxLoader extraction
library. Its extraction history was imported from gobbl at `96b4b91`; the
original extraction implementation is a port of MIT `ablfvextractor`, source
`gbl_root_canoe/submodules/ablfvextractor/src/lib.rs` at
`4d7d8ba6666a966ad224b0efc3be0e1ca9a1c753`.

The anti-rollback probe is not part of this crate. It remains with its original
Qualcomm firmware owner.

The checked-in test key in `tests/fixtures/testkey_rsa4096_pub.bin` is copied
unchanged from GBL's `gbl/libgbl/testdata/testkey_rsa4096_pub.bin`. Its SHA-256 is
`7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6`.
It is public test data, not a production signing key or a shipped payload.

`tests/fixtures/synthetic_linuxloader.efi` is a minimal ARM64 PE32+ EFI
application with one section. `tests/fixtures/synthetic_abl.img` is that PE
stored in an LZMA-alone stream, which exercises the extractor's bounded
container walk. Both are generated test data and carry no vendor bytes.

AVB public-key scanning belongs to `crates/abl-keys`. That crate uses the
AOSP-only `avb-format` key blob validation. The public fixture above is scanned
by `crates/abl-keys` as a negative case: it carries no raw RSA-2048 modulus with
exponent 65537.
