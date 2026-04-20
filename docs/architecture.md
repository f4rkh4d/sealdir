# architecture

## on-disk layout

```
<vault>/
  sealdir.header         # 256 bytes fixed
  data/
    <enc-name-1>         # one ciphertext file per plaintext file
    <enc-name-2>/        # directories are real directories, with encrypted names
      <enc-name-3>
```

every plaintext file maps to exactly one file on disk. sizes are preserved within the fixed 40-byte aead overhead (24 nonce + 16 tag). directory structure mirrors the plaintext structure exactly; only names are encrypted.

## fuse op -> on-disk op map

| fuse op | what we do |
|---|---|
| `getattr` | stat the mapped on-disk file; subtract 40 bytes for regular-file `st_size`. |
| `readdir` | list on-disk children, `base64url_decode` each name, attempt filename SIV decrypt keyed on the parent dir. entries that fail to decrypt are skipped (treated as garbage). |
| `open` | no open handle cache in v0.1. just check existence. |
| `read` | read full ciphertext, aead-decrypt, copy the `[off, off+size]` slice. |
| `write` | read full plaintext, splice the new buffer at `off`, re-encrypt with a fresh nonce, rewrite atomically-ish (truncate + write). |
| `create` | touch an empty file on disk. empty files produce zero-byte encrypted content. |
| `unlink` | remove the encrypted file. |
| `mkdir` | encrypt the directory name, create an empty on-disk directory. |
| `rmdir` | remove the encrypted directory (must be empty). |
| `rename` | same-directory: `rename()` on disk with the newly-encoded name. cross-directory: v0.1 limitation; the encoded filename depends on the parent dir, so cross-dir moves break the SIV check. v0.2: re-encode then rename. |
| `truncate` | read, resize the plaintext buffer, write. |

## rename handling

filename encoding is `(filename_key, dir_path, plaintext_name) -> encoded`. so:

- **same-dir rename**: just re-encode with the new plaintext name; `dir_path` stays the same. works.
- **cross-dir rename**: requires both re-encoding (new dir_path) and moving. v0.1 implements the naive `fs::rename` which produces a file whose encoded name is wrong for its new parent, making it invisible to readdir. we document this as unsupported in v0.1.

## why the read-whole-rewrite-whole i/o model

it's the simplest correct design for an AEAD per file. random-access writes to a single chunked-and-nonce'd file would require either:

- a chunked layout (one nonce + tag per 4 KiB block, a la gocryptfs). correct, but more code.
- an un-keyed disk cache that lets you defer re-encryption. complicates the threat model.

v0.1 picks "slow but correct". v0.2 should move to fixed-size chunks.
