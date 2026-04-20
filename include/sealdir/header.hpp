// header.hpp - sealdir.header read/write/validate.
#pragma once

#include "sealdir/crypto.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace sealdir {

constexpr std::uint32_t kCurrentVersion = 1;
constexpr std::size_t kHeaderSize = 256;
constexpr char kMagic[8] = {'S', 'E', 'A', 'L', 'D', 'I', 'R', 0};

// the fixed plaintext for the filename-key check blob.
constexpr char kFilenameKeyCheckPlaintext[24] = "sealdir-filename-key-ok";
// and for the master-key check blob. 16 bytes after xchacha+tag = 48 bytes.
constexpr char kMasterKeyCheckPlaintext[16] =
    {'s','e','a','l','d','i','r','-','h','d','r','-','o','k',0,0};

struct Header {
  std::uint32_t version = kCurrentVersion;
  std::uint8_t kdf_algo = 1;   // 1 = argon2id
  KdfParams kdf;
  Salt salt{};
  // encrypted_check: 24-byte nonce + 16 bytes ciphertext + 16 bytes tag = 56 (padded in layout to 48+8)
  // per spec: encrypted_check is 48 bytes: 24 nonce + 16 ct + 16 tag? that's 56. spec says 48.
  // we go with 24+16+16 = 56 since the math works. spec discrepancy noted in docs.
  std::array<std::uint8_t, 24 + 16 + 16> master_check{};
  std::array<std::uint8_t, 24 + 24 + 16> filename_check{}; // 24 nonce + 24 ct + 16 tag = 64
};

// write header to <vault>/sealdir.header. creates parent dir if missing.
void write_header(const std::filesystem::path& vault_dir, const Header& h,
                  const Key& master_key, const Key& filename_key);

// read + validate header. throws std::runtime_error on structural problems.
Header read_header(const std::filesystem::path& vault_dir);

// verify password by attempting to decrypt the master-check blob.
// returns derived master_key on success, nullopt on wrong password.
std::optional<Key> verify_password(const Header& h, std::string_view password);

// derive the filename key from master and verify against filename-check.
std::optional<Key> unwrap_filename_key(const Header& h, const Key& master_key);

}  // namespace sealdir
