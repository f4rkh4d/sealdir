// vault.hpp - in-memory state of an opened vault.
#pragma once

#include "sealdir/crypto.hpp"
#include "sealdir/header.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace sealdir {

class Vault {
 public:
  // create a new vault on disk. password confirmation is caller's job.
  static void init(const std::filesystem::path& vault_dir, std::string_view password);

  // open an existing vault. nullopt on wrong password.
  static std::optional<Vault> open(const std::filesystem::path& vault_dir,
                                   std::string_view password);

  ~Vault();
  Vault(const Vault&) = delete;
  Vault& operator=(const Vault&) = delete;
  Vault(Vault&&) = default;
  Vault& operator=(Vault&&) = default;

  const std::filesystem::path& vault_dir() const { return vault_dir_; }
  const std::filesystem::path& data_dir() const { return data_dir_; }
  const Header& header() const { return header_; }

  // change password in place. returns false if old password wrong.
  bool change_password(std::string_view old_pw, std::string_view new_pw);

  // total number of encrypted files under data/. best-effort stat.
  std::size_t count_files() const;

  // encode/decode a single path component in a parent dir.
  // `plain_dir_rel` is the plaintext relative dir (e.g. "" for root, "docs" for subdir).
  std::string encode_name(std::string_view plain_dir_rel, std::string_view plain_name) const;
  std::optional<std::string> decode_name(std::string_view plain_dir_rel,
                                         std::string_view on_disk_name) const;

  // map a full plaintext relative path -> on-disk path under data/.
  // empty input -> data_dir itself.
  std::filesystem::path to_on_disk_path(std::string_view plain_rel_path) const;

  // encrypt/decrypt file content blobs with the content key.
  std::vector<std::uint8_t> seal(const std::uint8_t* plaintext, std::size_t len) const;
  std::optional<std::vector<std::uint8_t>> unseal(const std::uint8_t* blob, std::size_t len) const;

 private:
  Vault() = default;

  std::filesystem::path vault_dir_;
  std::filesystem::path data_dir_;
  Header header_{};
  Key master_key_{};
  Key content_key_{};
  Key filename_key_{};
};

}  // namespace sealdir
