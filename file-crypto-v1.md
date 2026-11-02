# File crypto v1

This is the client encryption contract for `tensamin-file-chunks-v1`.
Iotas validate routing, sizes and ciphertext SHA-256, not plaintext or AEAD tags.
Implement this in the browser/native files SDK, not in an Iota handler.

## Context encoding

Use UTF-8 JSON arrays without whitespace. Encode every integer below as its exact
decimal **string**, not a floating-point number. Authority strings are canonical
principal authorities. Define:

```text
C = JSON(["tensamin-file-v1", origin.authority, decimal(origin.user_id),
          file_id, decimal(version)])
```

The DEK is 32 uniformly random bytes, independently generated for every version.
Use HKDF-SHA-256 with `salt = SHA256(C)` and that DEK as input key material.
Derive independent 32-byte keys with UTF-8 info labels
`tensamin-file-content-v1` and `tensamin-file-manifest-v1`.

## Encrypted manifest

`manifest_ciphertext` is `nonce[24] || XChaCha20-Poly1305(ciphertext || tag[16])`,
with the manifest key and AAD `C`. Use a fresh random nonce. Its plaintext is a
UTF-8 JSON object containing `filename`, `mime_type`, `plaintext_size`,
`chunk_bytes`, `chunk_count`, and optional plaintext SHA-256 and timestamps.
Sizes/counts are decimal strings. `chunk_bytes` is `65536` for this format.
Do not include private folder IDs, names or paths. Keep the encoded encrypted
manifest within the protocol's 16 KiB limit.

Also include `ciphertext_sha256`, `dek_commitment = SHA256(DEK)` and
`owner_signing_key_id` as lowercase hexadecimal strings, plus `owner_signature`
as base64. The key ID is SHA-256 of the authenticated MTP public bundle's binary
encoding. Sign this UTF-8 JSON array using the owner's Ed25519 + ML-DSA-65 dual
signer before encrypting the manifest:

```text
["tensamin-file-owner-v1", C_as_text, filename, mime_type, plaintext_size,
 chunk_bytes, chunk_count, plaintext_sha256_or_null, created_at_or_null,
 updated_at_or_null, ciphertext_sha256, dek_commitment, owner_signing_key_id]
```

All non-null fields are strings. Hash fields are lowercase hex; timestamps are
decimal strings. Verify this signature with the author's independently
authenticated bundle, check its key ID, and compare the DEK commitment and
ciphertext hash before accepting the file. This is necessary for private files
too: possession of a user's public KEM key alone must not let an Iota forge a
replacement file and wrapped key. A metadata rename requires a fresh owner
signature and manifest nonce, but no content re-encryption.

The client must reject invalid field types, impossible sizes, a count other than
`max(1, ceil(plaintext_size / 65536))`, or a ciphertext size other than
`chunk_count * (24 + 65536 + 16)`. Validate names for safe export, not as server
filesystem paths. Never trust a plaintext MIME type until authentication succeeds.

## Content stream

Split plaintext into 65536-byte chunks. Pad the final chunk with zero bytes to
65536 bytes. An empty file has one all-zero chunk. Encrypt each independently
with the content key and a fresh random 24-byte nonce. Each stored record is
`nonce[24] || ciphertext[65536] || tag[16]`, concatenated without headers.

For chunk index `i`, use this UTF-8 JSON array as AAD:

```text
JSON(["tensamin-file-chunk-v1", origin.authority, decimal(origin.user_id),
      file_id, decimal(version), decimal(i), decimal(plaintext_size),
      decimal(chunk_count)])
```

Authenticate every chunk and the manifest. Reject trailing bytes, missing chunks,
an invalid tag or nonzero final padding. Truncate authenticated final padding
only after validating the declared length. Never reuse a nonce with the same
derived key. Hash the entire stored ciphertext stream with SHA-256, including
nonces and tags. Stage ciphertext before upload so its hash and size are known.
MTP transfer ranges need not coincide with crypto records.

## Recipient DEK envelope

Fetch and verify the recipient's authenticated MTP KEM bundle. Define:

```text
W = JSON(["tensamin-file-dek-kem-v1", origin.authority,
          decimal(origin.user_id), file_id, decimal(version),
          recipient.authority, decimal(recipient.user_id), key_id])
```

Encapsulate to that KEM public key. Use HKDF-SHA-256 on the encapsulated shared
secret, with `salt = SHA256(W)`, UTF-8 info `tensamin-file-dek-kem-v1`, and
32-byte output. Encrypt the DEK with XChaCha20-Poly1305 using that wrapping key,
a fresh 24-byte nonce and AAD `W`. `encrypted_dek` contains
`nonce[24] || encrypted DEK[32] || tag[16]`; `kem_ciphertext` is the KEM output.
Use `wrapping_scheme: "tensamin-file-dek-kem-v1"`.

The owner and each recipient have separate envelopes. Sharing does not change
the content or manifest ciphertext. The signed share event authenticates the
descriptor and recipient envelope together. A receiving client must validate the
event's author, recipient and chat before trusting it, even when downloading
from its own Iota. A server checksum is not a signature or AEAD verification.

`ShareOffer` and `ShareRevoke` also have detached signatures so a client can
verify them after its Iota opens the transport seal. `signing_public_key` is the
base64 MTP bundle. `signature` is raw Ed25519 signature followed by ML-DSA-65
signature. Use the exact JSON-array encoding returned by the corresponding
`signing_bytes()` method in `relay-protocol/src/files.rs`. These arrays contain
only strings and byte arrays; integer fields become decimal strings. The
signature field itself is excluded. Servers check that this key belongs to the
verified Relay signer; clients must independently authenticate that binding.
`FileGetManifest.proof` and the file journal preserve these signed offers.

Only authorized clients may persist decryption keys. Never log DEKs, KEM shared
secrets or unwrapped metadata keys. Use an account-only key for private folder
metadata. Provision/recover the account keyring securely before storing data
whose only decryption key would otherwise live on one device.

For private folder names and `Placement.encrypted_metadata`, use an independent,
recoverable account metadata key with XChaCha20-Poly1305 and fresh nonces. Store
`nonce || ciphertext || tag`. Bind folders to this JSON-array AAD:
`["tensamin-file-folder-v1", authority, decimal(user_id), folder_id, parent_folder_id, decimal(revision)]`.
Bind placements to:
`["tensamin-file-placement-v1", authority, decimal(user_id), placement_id, origin.authority, decimal(origin.user_id), file_id, folder_id, hidden, decimal(revision)]`.
`hidden` is a JSON boolean. The encrypted placement body may contain a local
filename override, or an empty JSON object. Re-encrypt when moving or changing a
revision, and verify this AAD when synchronizing. Never share this account key.
Retain authenticated historical public signing keys when rotating private keys.
