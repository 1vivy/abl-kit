# The stock ABL key anchor

This document records what a Qualcomm stock ABL does with AVB keys, and how this
repository reads it.

## Source

The reference is the Qualcomm open-source ABL in CodeLinaro `uefi.lnx`:

- `QcomModulePkg/Library/avb/OEMPublicKey.h:36` holds the fixed `OEMPublicKey[]`
  array. Its header starts `00 00 10 00`, which is 4096 bits;
- `QcomModulePkg/Library/avb/libavb/avb_ops.c` includes that array and its
  `AvbValidateVbmetaPublicKey` byte-compares against it;
- `QcomModulePkg/Library/avb/libavb/avb_rsa.c:47-72` parses the key header and
  accepts 2048, 4096 and 8192 bits. `avb_rsa.c:172` fixes the exponent at 65537;
- `QcomModulePkg/Library/avb/VerifiedBoot.c:1146` holds `ComputeVbMetaDigest`,
  and `:1929` calls it.

The maOS tree records the same functions at
`.refs/mu_aloha_platforms/Platforms/QcomModulePkg/Library/avb/`. That checkout
is not part of this repository.

## Behavior

`AvbValidateVbmetaPublicKey` compares the root `vbmeta` public key with the
first key of the compiled-in array. The comparison is byte for byte. A root
signed by a later key in that array does not pass this check.

The array is part of the LinuxLoader PE. It is therefore present in an `abl`
partition image after the LZMA container is unpacked.

`AblKeys::anchor()` returns the first key in file order. `AblKeys::keys()`
returns every key with its offset. A caller that trusts a later key passes it
explicitly. The AVB chain plan takes the key set from the caller, so this
convention stays out of `avb-chain`.

## Scan

`AblKeys::scan` walks the image byte by byte. At each offset it tries an
`AvbRSAPublicKeyHeader`:

1. read `key_num_bits`, which must be 2048, 4096 or 8192;
2. read `n0inv` and the modulus, and require an odd modulus with its top bit
   set;
3. recompute `n0inv` as `-1 / n[0] mod 2^32`, and `rr` as
   `2^(2 * key_num_bits) mod n`;
4. keep only a blob that passes all four checks.

The scan keeps file order. It removes an exact duplicate blob, so a repeated
copy does not push the real first key out of first place.

This scan is structural. It finds an array of bytes that looks like an AVB key.
It does not prove that the ABL reads that key. A false match is unlikely because
the `n0inv` and `rr` checks are arithmetic constraints, but the result stays
evidence, not proof.

## Raw RSA-2048 record

A second record appears in some images: a bare 256-byte big-endian modulus
immediately followed by the exponent `01 00 01`. It has no AVB header.

`abl-keys::scan_rsa2048_e65537` reports each such modulus whose top bit is set
and whose low bit is set. This record is not an AVB key blob. It does not anchor
AVB metadata. ODP uses it for its own authority facts, and this crate keeps the
same capability so the two projects do not implement the scan twice.

## Limits

- A stock-ABL binary can deviate from the open-source reference. The OnePlus
  package that ablwrap handles takes OS version and security patch from vbmeta
  properties, not from the boot header. Do not generalize one observed binary to
  every device.
- A key found in an image is a candidate. Only the platform trust policy decides
  that the key is the authority.
- The anchor is a convention of the stock ABL. libavb itself takes the trusted
  key from its caller.
