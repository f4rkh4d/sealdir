// vault.cpp
#include "sealdir/vault.hpp"

#include "sealdir/base64url.hpp"

#include <sodium.h>

#include <sstream>
#include <stdexcept>

namespace sealdir {

namespace fs = std::filesystem;

// v0.1 filename limit. documented in docs/crypto.md.
// longer plaintext names -> return error to caller (fs::create etc -> ENAMETOOLONG).
constexpr std::size_t kMaxPlaintextName = 180;

void Vault::init(const fs::path& vault_dir, std::string_view password) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  if (fs::exists(vault_dir / "sealdir.header")) {
    throw std::runtime_error("vault already initialized at this path");
  }
  fs::create_directories(vault_dir);
  fs::create_directories(vault_dir / "data");

  Header h;
  h.version = kCurrentVersion;
  h.kdf_algo = 1;
  h.kdf = KdfParams{};
  randombytes_buf(h.salt.data(), h.salt.size());

  Key master = derive_master_key(password, h.salt, h.kdf);
  Key filename_key = derive_subkey(master, "sealdir-filename-v1");
  write_header(vault_dir, h, master, filename_key);

  secure_zero(master.data(), master.size());
  secure_zero(filename_key.data(), filename_key.size());
}

std::optional<Vault> Vault::open(const fs::path& vault_dir, std::string_view password) {
  Vault v;
  v.vault_dir_ = vault_dir;
  v.data_dir_ = vault_dir / "data";
  v.header_ = read_header(vault_dir);
  auto master = verify_password(v.header_, password);
  if (!master) return std::nullopt;
  auto fnk = unwrap_filename_key(v.header_, *master);
  if (!fnk) return std::nullopt;
  v.master_key_ = *master;
  v.filename_key_ = *fnk;
  v.content_key_ = derive_subkey(v.master_key_, "sealdir-content-v1");
  return v;
}

Vault::~Vault() {
  secure_zero(master_key_.data(), master_key_.size());
  secure_zero(content_key_.data(), content_key_.size());
  secure_zero(filename_key_.data(), filename_key_.size());
}

bool Vault::change_password(std::string_view old_pw, std::string_view new_pw) {
  auto master = verify_password(header_, old_pw);
  if (!master) return false;
  // re-salt + re-derive. keeps filename_key material identical across rekey by
  // re-wrapping it under the new master. v0.1: filename_key is deterministic from master,
  // so changing master changes on-disk filenames. we therefore re-encrypt all file names.
  // for v0.1 we simplify: refuse change-password if vault is non-empty, to avoid a
  // partially-done rekey on crash. documented compromise. v0.2 = proper rewrap + atomic rename.
  if (count_files() > 0) {
    throw std::runtime_error(
        "v0.1 limitation: change-password only supported on empty vaults. "
        "see docs/crypto.md for v0.2 plan.");
  }
  Header h = header_;
  randombytes_buf(h.salt.data(), h.salt.size());
  Key new_master = derive_master_key(new_pw, h.salt, h.kdf);
  Key new_fnk = derive_subkey(new_master, "sealdir-filename-v1");
  write_header(vault_dir_, h, new_master, new_fnk);
  header_ = h;
  master_key_ = new_master;
  filename_key_ = new_fnk;
  content_key_ = derive_subkey(master_key_, "sealdir-content-v1");
  return true;
}

std::size_t Vault::count_files() const {
  if (!fs::exists(data_dir_)) return 0;
  std::size_t n = 0;
  for (const auto& e : fs::recursive_directory_iterator(data_dir_)) {
    if (e.is_regular_file()) ++n;
  }
  return n;
}

std::string Vault::encode_name(std::string_view plain_dir_rel,
                               std::string_view plain_name) const {
  if (plain_name.size() > kMaxPlaintextName) {
    throw std::length_error("filename exceeds v0.1 180-byte limit");
  }
  auto raw = encrypt_filename_raw(filename_key_, plain_dir_rel, plain_name);
  return base64url_encode(raw.data(), raw.size());
}

std::optional<std::string> Vault::decode_name(std::string_view plain_dir_rel,
                                              std::string_view on_disk_name) const {
  auto raw = base64url_decode(std::string(on_disk_name));
  if (!raw) return std::nullopt;
  return decrypt_filename_raw(filename_key_, plain_dir_rel, raw->data(), raw->size());
}

fs::path Vault::to_on_disk_path(std::string_view plain_rel_path) const {
  if (plain_rel_path.empty() || plain_rel_path == "/") return data_dir_;
  fs::path cur = data_dir_;
  std::string acc_dir;  // accumulated plaintext relative dir
  std::string_view p = plain_rel_path;
  if (!p.empty() && p.front() == '/') p.remove_prefix(1);

  std::size_t start = 0;
  while (start <= p.size()) {
    std::size_t end = p.find('/', start);
    if (end == std::string_view::npos) end = p.size();
    std::string_view comp = p.substr(start, end - start);
    if (!comp.empty()) {
      std::string enc = encode_name(acc_dir, comp);
      cur /= enc;
      if (!acc_dir.empty()) acc_dir += "/";
      acc_dir.append(comp);
    }
    if (end == p.size()) break;
    start = end + 1;
  }
  return cur;
}

std::vector<std::uint8_t> Vault::seal(const std::uint8_t* plaintext, std::size_t len) const {
  return encrypt_blob(content_key_, plaintext, len);
}

std::optional<std::vector<std::uint8_t>> Vault::unseal(const std::uint8_t* blob,
                                                       std::size_t len) const {
  return decrypt_blob(content_key_, blob, len);
}

}  // namespace sealdir
