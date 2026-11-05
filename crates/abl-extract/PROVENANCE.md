# qcom-fw provenance

`soc/qcom/fw` is the authoritative MIT-licensed Qualcomm firmware image library.
Its extraction history was imported from gobbl at `96b4b91`; the original
extraction implementation is a port of MIT `ablfvextractor`, source
`gbl_root_canoe/submodules/ablfvextractor/src/lib.rs` at
`4d7d8ba6666a966ad224b0efc3be0e1ca9a1c753`.

The anti-rollback probe was transferred from gobbl at the same revision and
relicensed MIT with the owner's approved restructure. Following renames, its Git
authors are exclusively `1vivy <1vivy@tutanota.com>`. `arb.rs` preserves
attribution to the MIT `github.com/syedinsaf/arbscan` port and accepts the
SHA-384 tables of OnePlus 15 images.

The checked-in test key in `tests/fixtures/testkey_rsa4096_pub.bin` is copied
unchanged from GBL's `gbl/libgbl/testdata/testkey_rsa4096_pub.bin`. Its SHA-256 is
`7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6`.
It is public test data, not a production signing key or a shipped payload.

Host anchor key extraction belongs to `soc/qcom/abl-key`. AVB public-key
scanning belongs to `shared/avb-meta`, vendored from avb-kit. `abl-key` uses
`AblKeys`. avb-kit keeps an independent MIT scanner and its parameter tests in
`oracle/tests/support/key_scan.rs` as a cross-check. The public fixture above is
the input of that cross-check.
