# abl-keys provenance

The AVB public-key scanner, `AblKey`, `AblKeys`, and the first-key anchor were
moved from maOS `shared/avb-meta/src/rsa.rs`. The source is the avb-kit lineage
described in that crate's `PROVENANCE.md`.

The raw RSA-2048/e65537 modulus scan was moved from maOS `soc/qcom/fw/src/lib.rs`.
It matches the ODP `patina_qcom_anchor/src/rsa.rs` capability: a bare 256-byte
modulus followed by exponent 65537 is not an AVB key blob and does not anchor AVB
metadata.

The message-based PKCS#1 v1.5 SHA-256 verifier stays in ODP. Its caller is
`patina_qcom_oem_oplus/src/reserve.rs`, which authenticates the OEM
`oplusreserve1` serial record over the raw 25-byte payload. That record is not
AVB metadata and carries no AVB `AvbRSAPublicKeyHeader`, so it does not belong to
an AVB signing-key API.

ABL trust and presentation conventions were moved from maOS
`shared/avb-meta/src/{lib,plan,meta}.rs`: first-key anchor selection, explicit
extra trust, boot-first property selection, partition coverage identity, the
SHA-256 ABL/TEE VBH, and the SHA-512 DICE authority hash. libavb chain semantics
remain in `avb-chain`.

`tests/fixtures/testkey_rsa4096_pub.bin` is copied unchanged from GBL's
`gbl/libgbl/testdata/testkey_rsa4096_pub.bin`. It is public test data, not a
production signing key or a shipped payload. The real capture and PE paths in
`tests/` are external evidence; each test is a clean skip when its capture is
absent.

The stock Qualcomm source references are:

- `QcomModulePkg/Library/avb/libavb/avb_ops.c` `AvbValidateVbmetaPublicKey`
  compares the root key against `OEMPublicKey` byte-for-byte; the header
  `QcomModulePkg/Library/avb/OEMPublicKey.h` holds that fixed array.
- `QcomModulePkg/Library/avb/libavb/avb_rsa.c` `iavb_parse_key_data` accepts
  `key_num_bits` 2048, 4096 and 8192 and requires
  `8 + 2 * key_num_bits / 8` bytes.
- `QcomModulePkg/Library/avb/libavb/avb_crypto.c` holds the PKCS#1 v1.5 padding
  for the ABL's 65537 exponent.
- `Library/avb/VerifiedBoot.c` `ComputeVbMetaDigest` is the SHA-256 ABL/TEE VBH
  over the ordered metadata images.

`OEMPublicKey` is the fixed first key in the stock image. A later structurally
valid key is reported but is not the anchor.
