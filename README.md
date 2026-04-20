# sealdir

encrypted fuse-mounted directory. think gocryptfs, smaller, written in c++20.

[![ci](https://github.com/f4rkh4d/sealdir/actions/workflows/ci.yml/badge.svg)](https://github.com/f4rkh4d/sealdir/actions/workflows/ci.yml)

## what it is

you point sealdir at a directory. it writes an encrypted header and a `data/` subfolder full of ciphertext blobs with scrambled names. when you `mount` it, a fuse filesystem shows up at your chosen mountpoint and reads/writes look normal to every other program on the machine. unmount and all that's left on disk is unreadable bytes.

## comparison

- **gocryptfs**: same shape. battle-tested, more mature, pure go. sealdir is smaller and readable in an afternoon.
- **veracrypt**: container files of fixed size. sealdir is per-file so syncing with rclone/dropbox only sends the changed files.
- **cryfs**: hides file sizes and directory structure by chunking. sealdir does not. if that matters to your threat model, use cryfs.

## quick start

```
sealdir init ~/vault
sealdir mount ~/vault ~/plain &
cp secrets.txt ~/plain/
ls ~/vault/data/            # encrypted names, encrypted content
sealdir unmount ~/plain
```

## how the crypto works (short)

- argon2id derives a 32-byte master key from your password + a 16-byte salt stored in `sealdir.header`
- blake2b branches the master into a `content_key` and a `filename_key`
- file content: xchacha20-poly1305 with a random 24-byte nonce per file
- filenames: synthetic-iv style, deterministic so `readdir` works, keyed with `filename_key`
- everything goes through libsodium. zero hand-rolled primitives.

see [docs/crypto.md](docs/crypto.md) for the full tree + open questions.

## platforms

- linux: libfuse3. primary target.
- macos: macfuse. builds + unit tests pass; mount integration requires macfuse installed.
- windows: not supported.

ci runs linux only for v0.1. macos is verified locally.

## security model

sealdir protects against "laptop gets stolen and powered off". it does not protect against an attacker with persistent access to your running machine, or an attacker who can modify files while the vault is mounted and you're still using it.

## build

```
cmake -B build
cmake --build build
ctest --test-dir build
```

dependencies: libsodium, libfuse3 (linux) or macfuse (macos), cmake >= 3.20, a c++20 compiler.

## status

v0.1. good enough for "my laptop holds keepass-style notes and i want a second seatbelt". not audited.
