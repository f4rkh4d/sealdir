# crypto

## key derivation tree

```
password + salt (16 bytes, stored in sealdir.header)
  |
  | argon2id (opslimit=3, memlimit=64 MiB, default)
  v
master_key (32 bytes, never touches disk)
  |
  +-- blake2b_keyed(master, "sealdir-content-v1", 32)    = content_key
  +-- blake2b_keyed(master, "sealdir-filename-v1", 32)   = filename_key
```

the header carries two "check" blobs:

- `master_check`: encrypt a known plaintext (`"sealdir-hdr-ok\0\0"`, 16 bytes) under `master_key` with a random xchacha20 nonce. on mount we try to decrypt. tag verifies -> password correct.
- `filename_check`: same idea, encrypts `"sealdir-filename-key-ok"` (24 bytes) under `filename_key`. confirms we derived the subkey correctly too, so a future version that wraps `filename_key` independently can keep the same check path.

## file content

each plaintext file becomes one ciphertext file:

```
[24-byte xchacha20 nonce][ciphertext][16-byte poly1305 tag]
```

nonce is fresh `randombytes_buf(24)` per encrypt. xchacha20 has a 192-bit nonce so random collisions are astronomically unlikely. aead primitive is `crypto_aead_xchacha20poly1305_ietf` from libsodium.

no aad in v0.1. v0.2 should bind the file's path (or a stable file_id) as aad to prevent swap-in attacks.

## filename encryption (the tricky bit)

filenames inside a given directory must encrypt deterministically, otherwise `readdir` + `lookup` break. we use a synthetic-iv construction:

```
nonce = blake2b_keyed(filename_key, dir_path || 0x00 || plaintext_name)[:24]
ct    = xchacha20_stream(plaintext_name, nonce, filename_key)
stored_name = base64url_nopad(nonce || ct)
```

properties:
- deterministic: same `(dir, name)` pair always produces the same encoded name.
- two different plaintext names in the same dir: blake2b collisions are ~2^-192, so different nonces, different ct.
- different dirs, same name: different nonce (dir is in the hash input), different ct. so attackers can't tell `dir1/a.md` and `dir2/a.md` are named the same.

### on "is this actually secure"

this is not a standard AEAD. a pure xchacha20 stream has no integrity tag, so we can't detect tampering the usual way. instead, on decrypt:

1. stream-decrypt using the stored nonce, get a candidate plaintext `p'`
2. recompute `nonce' = blake2b_keyed(filename_key, dir_path || 0x00 || p')[:24]`
3. if `nonce' != stored_nonce`, reject.

against an attacker who does *not* know `filename_key`, this works as an integrity check: to forge a new valid ciphertext `(n, c)` for some name `p`, the attacker must satisfy `n = blake2b_keyed(k, dir || p)`, which requires the key. so the security reduces to "blake2b is a good PRF under the key," which it is.

the standard name for this construction is synthetic-iv or deterministic authenticated encryption (DAE). equivalent in spirit to rfc 5297 AES-SIV, just built from libsodium primitives because libsodium doesn't ship AES-SIV. documented compromise: we're rolling a SIV from blake2b + xchacha20 instead of using a named primitive. the security argument is standard but the construction is not as paper-reviewed as AES-SIV itself.

## length limits

ext4 caps single filenames at 255 bytes. base64 of `(24 + n)` plaintext bytes is `ceil((24 + n) * 4 / 3)`. solving for 255:

```
ceil((24 + n) * 4 / 3) <= 255
(24 + n) * 4 / 3 <= 255
n <= 167
```

v0.1 caps plaintext filenames at **180 bytes** as a documented limit; longer names return `ENAMETOOLONG`. v0.2: truncate-and-store scheme (spec'd in the original design but deferred).

## v0.2 roadmap

- per-file content keys, so leaking one file's key doesn't leak the rest
- aad binding (file_id or relative path) on content aead
- merkle integrity tree across the whole vault so directory reshuffling is detectable
- proper rewrap on `change-password` instead of the v0.1 "empty vault only" limitation
- long-filename truncate-and-store
- case-insensitive filename support (optional, for macos compat)
- random padding of filename length so adversaries can't fingerprint names by length
