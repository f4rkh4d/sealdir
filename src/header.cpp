// header.cpp
#include "sealdir/header.hpp"

#include <sodium.h>

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace sealdir {

namespace fs = std::filesystem;

namespace {

// layout offsets inside the 256-byte header block.
constexpr std::size_t kOffMagic = 0;       // 8
constexpr std::size_t kOffVersion = 8;     // u32
constexpr std::size_t kOffKdfAlgo = 12;    // u8
constexpr std::size_t kOffOpslimit = 13;   // u32
constexpr std::size_t kOffMemlimit = 17;   // u64
constexpr std::size_t kOffSalt = 25;       // 16
constexpr std::size_t kOffMasterCheck = 41;   // 56
constexpr std::size_t kOffFilenameCheck = 97; // 64
// end of used region = 161, pad to 256.

void put_u32(std::uint8_t* p, std::uint32_t v) {
  p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
std::uint32_t get_u32(const std::uint8_t* p) {
  return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
         (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
void put_u64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) p[i] = (v >> (8 * i)) & 0xff;
}
std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= std::uint64_t(p[i]) << (8 * i);
  return v;
}

}  // namespace

void write_header(const fs::path& vault_dir, const Header& h,
                  const Key& master_key, const Key& filename_key) {
  if (!sodium_init_once()) throw std::runtime_error("sodium_init failed");
  fs::create_directories(vault_dir);

  std::array<std::uint8_t, kHeaderSize> buf{};
  std::memcpy(buf.data() + kOffMagic, kMagic, 8);
  put_u32(buf.data() + kOffVersion, h.version);
  buf[kOffKdfAlgo] = h.kdf_algo;
  put_u32(buf.data() + kOffOpslimit, h.kdf.opslimit);
  put_u64(buf.data() + kOffMemlimit, h.kdf.memlimit);
  std::memcpy(buf.data() + kOffSalt, h.salt.data(), kSaltBytes);

  // master-check: encrypt kMasterKeyCheckPlaintext (16 bytes) with master_key, random nonce.
  auto mc = encrypt_blob(master_key,
                         reinterpret_cast<const std::uint8_t*>(kMasterKeyCheckPlaintext),
                         16);
  if (mc.size() != 24 + 16 + 16) throw std::runtime_error("unexpected mc size");
  std::memcpy(buf.data() + kOffMasterCheck, mc.data(), mc.size());

  // filename-check: encrypt kFilenameKeyCheckPlaintext (24 bytes) with filename_key.
  auto fc = encrypt_blob(filename_key,
                         reinterpret_cast<const std::uint8_t*>(kFilenameKeyCheckPlaintext),
                         24);
  if (fc.size() != 24 + 24 + 16) throw std::runtime_error("unexpected fc size");
  std::memcpy(buf.data() + kOffFilenameCheck, fc.data(), fc.size());

  fs::path hdr_path = vault_dir / "sealdir.header";
  std::ofstream f(hdr_path, std::ios::binary | std::ios::trunc);
  if (!f) throw std::runtime_error("cannot open header for write");
  f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
  if (!f) throw std::runtime_error("write failed");
}

Header read_header(const fs::path& vault_dir) {
  fs::path hdr_path = vault_dir / "sealdir.header";
  std::ifstream f(hdr_path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open header");
  std::array<std::uint8_t, kHeaderSize> buf{};
  f.read(reinterpret_cast<char*>(buf.data()), buf.size());
  if (f.gcount() != static_cast<std::streamsize>(kHeaderSize)) {
    throw std::runtime_error("short header");
  }
  if (std::memcmp(buf.data() + kOffMagic, kMagic, 8) != 0) {
    throw std::runtime_error("bad magic (not a sealdir vault)");
  }
  Header h{};
  h.version = get_u32(buf.data() + kOffVersion);
  if (h.version != kCurrentVersion) {
    throw std::runtime_error("unsupported vault version");
  }
  h.kdf_algo = buf[kOffKdfAlgo];
  if (h.kdf_algo != 1) throw std::runtime_error("unsupported kdf algo");
  h.kdf.opslimit = get_u32(buf.data() + kOffOpslimit);
  h.kdf.memlimit = get_u64(buf.data() + kOffMemlimit);
  std::memcpy(h.salt.data(), buf.data() + kOffSalt, kSaltBytes);
  std::memcpy(h.master_check.data(), buf.data() + kOffMasterCheck, h.master_check.size());
  std::memcpy(h.filename_check.data(), buf.data() + kOffFilenameCheck, h.filename_check.size());
  return h;
}

std::optional<Key> verify_password(const Header& h, std::string_view password) {
  Key master = derive_master_key(password, h.salt, h.kdf);
  auto pt = decrypt_blob(master, h.master_check.data(), h.master_check.size());
  if (!pt || pt->size() != 16 ||
      std::memcmp(pt->data(), kMasterKeyCheckPlaintext, 16) != 0) {
    secure_zero(master.data(), master.size());
    return std::nullopt;
  }
  return master;
}

std::optional<Key> unwrap_filename_key(const Header& h, const Key& master_key) {
  Key fnk = derive_subkey(master_key, "sealdir-filename-v1");
  auto pt = decrypt_blob(fnk, h.filename_check.data(), h.filename_check.size());
  if (!pt || pt->size() != 24 ||
      std::memcmp(pt->data(), kFilenameKeyCheckPlaintext, 24) != 0) {
    secure_zero(fnk.data(), fnk.size());
    return std::nullopt;
  }
  return fnk;
}

}  // namespace sealdir
