// crypto.cpp
// all primitives come from libsodium. if sodium doesn't have it, we don't do it.
#include "sealdir/crypto.hpp"

#include <sodium.h>

#include <cstring>
#include <mutex>
#include <stdexcept>

namespace sealdir {

bool sodium_init_once() {
  static std::once_flag flag;
  static bool ok = false;
  std::call_once(flag, [] { ok = (sodium_init() >= 0); });
  return ok;
}

Key derive_master_key(std::string_view password, const Salt& salt, const KdfParams& params) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  Key out{};
  int rc = crypto_pwhash(
      out.data(), out.size(),
      password.data(), password.size(),
      salt.data(),
      params.opslimit, static_cast<std::size_t>(params.memlimit),
      crypto_pwhash_ALG_ARGON2ID13);
  if (rc != 0) throw std::runtime_error("argon2id oom or internal failure");
  return out;
}

Key derive_subkey(const Key& master, std::string_view context, std::size_t out_len) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  if (out_len > 32) throw std::invalid_argument("subkey > 32 bytes not supported");
  Key out{};
  // keyed blake2b: key = master, input = context. produces pseudorandom subkey.
  if (crypto_generichash(out.data(), out_len,
                         reinterpret_cast<const std::uint8_t*>(context.data()),
                         context.size(),
                         master.data(), master.size()) != 0) {
    throw std::runtime_error("blake2b failed");
  }
  return out;
}

std::vector<std::uint8_t> encrypt_blob(const Key& key, const std::uint8_t* plaintext, std::size_t len) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  std::vector<std::uint8_t> out(kXChaChaNonceBytes + len + kPoly1305TagBytes);
  randombytes_buf(out.data(), kXChaChaNonceBytes);
  unsigned long long ct_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          out.data() + kXChaChaNonceBytes, &ct_len,
          plaintext, len,
          nullptr, 0,          // no aad in v0.1; v0.2 could bind file_id
          nullptr,
          out.data(),          // nonce
          key.data()) != 0) {
    throw std::runtime_error("xchacha20-poly1305 encrypt failed");
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> decrypt_blob(const Key& key, const std::uint8_t* blob, std::size_t len) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  if (len < kXChaChaNonceBytes + kPoly1305TagBytes) return std::nullopt;
  std::vector<std::uint8_t> out(len - kXChaChaNonceBytes - kPoly1305TagBytes);
  unsigned long long pt_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          out.data(), &pt_len,
          nullptr,
          blob + kXChaChaNonceBytes, len - kXChaChaNonceBytes,
          nullptr, 0,
          blob,
          key.data()) != 0) {
    return std::nullopt;
  }
  out.resize(pt_len);
  return out;
}

std::vector<std::uint8_t> encrypt_with_nonce(const Key& key, const Nonce& nonce,
                                             const std::uint8_t* plaintext, std::size_t len) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  std::vector<std::uint8_t> out(kXChaChaNonceBytes + len + kPoly1305TagBytes);
  std::memcpy(out.data(), nonce.data(), kXChaChaNonceBytes);
  unsigned long long ct_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          out.data() + kXChaChaNonceBytes, &ct_len,
          plaintext, len,
          nullptr, 0, nullptr,
          nonce.data(), key.data()) != 0) {
    throw std::runtime_error("xchacha20-poly1305 encrypt failed");
  }
  return out;
}

// ---------- filename SIV ----------
//
// construction (v0.1):
//   nonce = blake2b_keyed(key=filename_key, input = dir_path || 0x00 || plaintext)[:24]
//   ct    = xchacha20_stream(plaintext, nonce, filename_key)   // no mac
//   stored = nonce || ct
//
// properties:
//   - deterministic: same (dir, name) -> same ciphertext. readdir lookups work.
//   - different plaintext -> different nonce (with overwhelming probability) -> different ct.
//   - tamper: if attacker flips a ct byte, decrypt yields a different plaintext p',
//     and blake2b(key, dir||p') != stored_nonce with overwhelming probability. we reject.
//     *however* this is weaker than a full aead mac: an attacker who knows key could forge,
//     but that's trivially true for any scheme. against outside attackers the SIV-recheck
//     acts as an integrity check keyed on filename_key. documented compromise.

static std::array<std::uint8_t, kXChaChaNonceBytes>
filename_nonce(const Key& filename_key, std::string_view dir_path, std::string_view plaintext) {
  std::array<std::uint8_t, kXChaChaNonceBytes> nonce{};
  crypto_generichash_state st;
  crypto_generichash_init(&st, filename_key.data(), filename_key.size(), kXChaChaNonceBytes);
  crypto_generichash_update(&st,
      reinterpret_cast<const std::uint8_t*>(dir_path.data()), dir_path.size());
  const std::uint8_t sep = 0;
  crypto_generichash_update(&st, &sep, 1);
  crypto_generichash_update(&st,
      reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size());
  crypto_generichash_final(&st, nonce.data(), nonce.size());
  return nonce;
}

std::vector<std::uint8_t> encrypt_filename_raw(const Key& filename_key,
                                               std::string_view dir_path,
                                               std::string_view plaintext) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  auto nonce = filename_nonce(filename_key, dir_path, plaintext);
  std::vector<std::uint8_t> out(kXChaChaNonceBytes + plaintext.size());
  std::memcpy(out.data(), nonce.data(), kXChaChaNonceBytes);
  // pure stream cipher. no tag.
  if (crypto_stream_xchacha20_xor(
          out.data() + kXChaChaNonceBytes,
          reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size(),
          nonce.data(), filename_key.data()) != 0) {
    throw std::runtime_error("xchacha20 stream failed");
  }
  return out;
}

std::optional<std::string> decrypt_filename_raw(const Key& filename_key,
                                                std::string_view dir_path,
                                                const std::uint8_t* raw, std::size_t len) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  if (len < kXChaChaNonceBytes) return std::nullopt;
  std::string pt(len - kXChaChaNonceBytes, '\0');
  if (crypto_stream_xchacha20_xor(
          reinterpret_cast<std::uint8_t*>(pt.data()),
          raw + kXChaChaNonceBytes, len - kXChaChaNonceBytes,
          raw, filename_key.data()) != 0) {
    return std::nullopt;
  }
  // SIV recheck: recompute the nonce from recovered plaintext and compare.
  auto expect = filename_nonce(filename_key, dir_path, pt);
  if (sodium_memcmp(expect.data(), raw, kXChaChaNonceBytes) != 0) {
    return std::nullopt;
  }
  return pt;
}

void secure_zero(void* ptr, std::size_t len) {
  sodium_memzero(ptr, len);
}

}  // namespace sealdir
