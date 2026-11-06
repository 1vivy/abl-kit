# Provenance

## Imported history

This repository started from two maOS paths. The import used `git filter-repo`
on a temporary clone. The maOS checkout was not modified.

| Source | Source path | Destination |
|---|---|---|
| maOS `main` at `3a92f93e` | `soc/qcom/fw/` | `crates/abl-extract/` |
| maOS `main` at `3a92f93e` | `soc/qcom/abl-key/` | `tools/ablkit/` |

Authorship is preserved. Rewritten commits lost their signatures, which is
expected.

`crates/abl-extract` came from the MIT-licensed maOS `qcom-fw` crate. The same
author wrote it. The owner relicenses this copy as Apache-2.0.

The extractor is a port of the MIT-licensed `ablfvextractor` crate by the same
author, from `gbl_root_canoe/submodules/ablfvextractor/src/lib.rs` at commit
`4d7d8ba6666a966ad224b0efc3be0e1ca9a1c753`.

## Code moved in

### AVB key scan and first-key anchor

`crates/abl-keys` carries the key scan that maOS `shared/avb-meta` held. That
crate was imported into avb-kit, where the scan was removed because it is a
stock-ABL convention. The copy here keeps the original assertions as tests.

The moved items are:

| From | To |
|---|---|
| `avb_meta::AblKey`, `AblKey::signature_len` | `abl_keys::AblKey` |
| `avb_meta::AblKeys`, `abl_keys()`, `AblKeys::scan/from_keys/anchor/keys/len/is_empty` | `abl_keys::AblKeys` |
| `Plan::anchored`, `Plan::anchored_with_extra` | `AblPlan` in `abl_keys::plan` |
| `Verdict::WrongPartition` and the `vbmeta_<group>` coverage rule | `identity_ok` |
| `Properties` boot-first selection and `properties_source` | `abl_keys::Properties` |
| `Plan::authority_sha512` | ABL authority helper |
| `Plan::vbmeta_digest()` as the fixed SHA-256 VBH | `AblPlan` VBH accessor |

### Raw RSA-2048 modulus scan

`scan_rsa2048_e65537` is a port of ODP
`bootchain/modules/uefi/platform/crates/patina_qcom_anchor/src/rsa.rs`. ODP
distributes that file under MIT. The owner relicenses this copy as Apache-2.0.

The function is not an AVB key check. It reports a bare 256-byte big-endian
modulus followed by `01 00 01`. ODP uses that record for its own authority
facts.

ODP's message-based RSA-2048/SHA-256 verification stays in ODP. It verifies an
arbitrary message digest and is not an AVB algorithm use. A caller that has AVB
metadata uses `avb-verify`.

## Not imported

- `soc/qcom/fw/src/arb.rs` and `src/bin/qcom-arb.rs`: `xbl_config`
  anti-rollback work. It is not AVB metadata. maOS keeps it as `qcom-arb`.
- `soc/qcom/abl-key` shelling to `openssl`: `tools/ablkit` uses the `sha2` crate
  instead.

## License

Every crate declares Apache-2.0. The avb-kit dependency is a path dependency
until avb-kit has a remote. Then it becomes a git dependency.
