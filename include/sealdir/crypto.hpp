// crypto.hpp
// libsodium wrappers. no hand-rolled primitives live here.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sealdir {

// key sizes
constexpr std::size_t kMasterKeyBytes = 32;
constexpr std::size_t kContentKeyBytes = 32;
constexpr std::size_t kFilenameKeyBytes = 32;
constexpr std::size_t kSaltBytes = 16;           // argon2id salt (libsodium wants 16)
constexpr std::size_t kXChaChaNonceBytes = 24;
constexpr std::size_t kPoly1305TagBytes = 16;

using Key = std::array<std::uint8_t, 32>;
using Salt = std::array<std::uint8_t, kSaltBytes>;
using Nonce = std::array<std::uint8_t, kXChaChaNonceBytes>;

// kdf params. defaults target ~500ms on a laptop. v0.1: fixed defaults.
struct KdfParams {
  std::uint32_t opslimit = 3;          // argon2id opslimit_interactive-ish
  std::uint64_t memlimit = 64ULL * 1024 * 1024; // 64 MiB
};

// initialize libsodium. call once at program start. returns false on failure.
bool sodium_init_once();

// derive the master key from password + salt via argon2id.
// throws std::runtime_error on libsodium failure (oom etc).
Key derive_master_key(std::string_view password, const Salt& salt, const KdfParams& params);

// derive subkey via blake2b keyed hash. context is a short string literal.
Key derive_subkey(const Key& master, std::string_view context, std::size_t out_len = 32);

// encrypt a buffer with xchacha20-poly1305-ietf. random nonce prepended.
// output layout: [24-byte nonce][ciphertext || 16-byte tag]
std::vector<std::uint8_t> encrypt_blob(const Key& key, const std::uint8_t* plaintext, std::size_t len);

// decrypt a blob produced by encrypt_blob. returns nullopt on auth failure.
std::optional<std::vector<std::uint8_t>> decrypt_blob(const Key& key, const std::uint8_t* blob, std::size_t len);

// encrypt with caller-supplied nonce + no aad. for check-blobs where nonce is chosen.
// returns 24+len+16 bytes: nonce || ct || tag. nonce arg is written into output.
std::vector<std::uint8_t> encrypt_with_nonce(const Key& key, const Nonce& nonce,
                                             const std::uint8_t* plaintext, std::size_t len);

// filename SIV-ish construction. deterministic per (dir_path, plaintext).
// see docs/crypto.md. returns the raw (nonce || ciphertext) bytes before base64.
std::vector<std::uint8_t> encrypt_filename_raw(const Key& filename_key,
                                               std::string_view dir_path,
                                               std::string_view plaintext);

// inverse. takes raw bytes (not base64). returns nullopt if auth-equivalent check fails.
// note: because this is a deterministic SIV built from blake2b+stream, we cannot "verify"
// a mac on decrypt. instead we recompute the nonce from the recovered plaintext and dir_path,
// and confirm it matches the stored nonce. mismatch -> tamper.
std::optional<std::string> decrypt_filename_raw(const Key& filename_key,
                                                std::string_view dir_path,
                                                const std::uint8_t* raw, std::size_t len);

// zero a buffer securely (sodium_memzero).
void secure_zero(void* ptr, std::size_t len);

}  // namespace sealdir
