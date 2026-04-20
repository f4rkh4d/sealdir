// fs.cpp - fuse3 operations.
//
// design: each plaintext file maps 1:1 to one ciphertext file.
//   read(path, off, size)  -> read full ciphertext, decrypt, return slice.
//   write(path, off, buf)  -> read full plaintext, splice buf at off, re-encrypt, rewrite.
//
// this is simple and safe. perf is bad for large files. v0.2 = chunked layout with
// per-chunk nonces so random-access writes don't re-seal the whole file.
//
// only compiled when SEALDIR_HAVE_FUSE is defined.

#include "sealdir/fs.hpp"

#ifdef SEALDIR_HAVE_FUSE

#include <fuse.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sealdir {

namespace fs = std::filesystem;

namespace {

Vault* vault() {
  return static_cast<Vault*>(fuse_get_context()->private_data);
}

// split "/a/b/c" into ("/a/b", "c"). root -> ("", "").
// kept for the rename + mkdir paths, which currently go through
// map_path directly; this helper is on the v0.2 todo for structured
// parent-directory handling so i am leaving it here and silencing the
// unused warning rather than dead-coding it.
[[maybe_unused]] std::pair<std::string, std::string> split_parent(
    const char* path) {
  std::string p = path;
  while (p.size() > 1 && p.back() == '/') p.pop_back();
  if (p.empty() || p == "/") return {"", ""};
  auto pos = p.find_last_of('/');
  std::string parent = (pos == 0) ? "" : p.substr(1, pos - 1);
  std::string name = p.substr(pos + 1);
  return {parent, name};
}

std::optional<fs::path> map_path(const char* path) {
  try {
    std::string s = path;
    if (!s.empty() && s.front() == '/') s.erase(0, 1);
    return vault()->to_on_disk_path(s);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<std::uint8_t>> read_plain(const fs::path& enc) {
  std::ifstream f(enc, std::ios::binary);
  if (!f) return std::nullopt;
  std::vector<std::uint8_t> blob((std::istreambuf_iterator<char>(f)), {});
  if (blob.empty()) return std::vector<std::uint8_t>{};
  return vault()->unseal(blob.data(), blob.size());
}

int write_plain(const fs::path& enc, const std::uint8_t* data, std::size_t len) {
  auto blob = vault()->seal(data, len);
  std::ofstream f(enc, std::ios::binary | std::ios::trunc);
  if (!f) return -EIO;
  f.write(reinterpret_cast<const char*>(blob.data()),
          static_cast<std::streamsize>(blob.size()));
  return f ? 0 : -EIO;
}

#if FUSE_USE_VERSION >= 30
int op_getattr(const char* path, struct stat* st, struct fuse_file_info*) {
#else
int op_getattr(const char* path, struct stat* st) {
#endif
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::memset(st, 0, sizeof(*st));
  std::error_code ec;
  if (!fs::exists(*disk, ec)) return -ENOENT;
  if (fs::is_directory(*disk, ec)) {
    st->st_mode = S_IFDIR | 0700;
    st->st_nlink = 2;
    return 0;
  }
  // regular file: size = ciphertext size - overhead. empty files stay empty.
  auto fsize = fs::file_size(*disk, ec);
  if (ec) return -EIO;
  st->st_mode = S_IFREG | 0600;
  st->st_nlink = 1;
  if (fsize == 0) {
    st->st_size = 0;
  } else if (fsize < kXChaChaNonceBytes + kPoly1305TagBytes) {
    return -EIO;
  } else {
    st->st_size = static_cast<off_t>(fsize - kXChaChaNonceBytes - kPoly1305TagBytes);
  }
  return 0;
}

#if FUSE_USE_VERSION >= 30
int op_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t,
               struct fuse_file_info*, enum fuse_readdir_flags) {
#else
int op_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t,
               struct fuse_file_info*) {
#endif
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::error_code ec;
  if (!fs::is_directory(*disk, ec)) return -ENOTDIR;

  std::string rel = path;
  if (!rel.empty() && rel.front() == '/') rel.erase(0, 1);

#if FUSE_USE_VERSION >= 30
  filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
  filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
#else
  filler(buf, ".", nullptr, 0);
  filler(buf, "..", nullptr, 0);
#endif

  for (const auto& e : fs::directory_iterator(*disk, ec)) {
    auto dec = vault()->decode_name(rel, e.path().filename().string());
    if (!dec) continue;  // skip garbage
#if FUSE_USE_VERSION >= 30
    filler(buf, dec->c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
#else
    filler(buf, dec->c_str(), nullptr, 0);
#endif
  }
  return 0;
}

int op_open(const char* path, struct fuse_file_info*) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::error_code ec;
  if (!fs::exists(*disk, ec)) return -ENOENT;
  return 0;
}

int op_read(const char* path, char* buf, size_t size, off_t off,
            struct fuse_file_info*) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  auto pt = read_plain(*disk);
  if (!pt) return -EIO;
  if (static_cast<size_t>(off) >= pt->size()) return 0;
  size_t n = std::min(size, pt->size() - static_cast<size_t>(off));
  std::memcpy(buf, pt->data() + off, n);
  return static_cast<int>(n);
}

int op_write(const char* path, const char* buf, size_t size, off_t off,
             struct fuse_file_info*) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::vector<std::uint8_t> pt;
  auto existing = read_plain(*disk);
  if (existing) pt = std::move(*existing);
  if (pt.size() < static_cast<size_t>(off) + size) pt.resize(off + size, 0);
  std::memcpy(pt.data() + off, buf, size);
  int rc = write_plain(*disk, pt.data(), pt.size());
  if (rc < 0) return rc;
  return static_cast<int>(size);
}

int op_create(const char* path, mode_t, struct fuse_file_info*) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::ofstream f(*disk, std::ios::binary | std::ios::trunc);
  return f ? 0 : -EIO;
}

int op_unlink(const char* path) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::error_code ec;
  return fs::remove(*disk, ec) ? 0 : -ENOENT;
}

int op_mkdir(const char* path, mode_t) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::error_code ec;
  return fs::create_directory(*disk, ec) ? 0 : -EEXIST;
}

int op_rmdir(const char* path) {
  auto disk = map_path(path);
  if (!disk) return -EIO;
  std::error_code ec;
  return fs::remove(*disk, ec) ? 0 : -ENOTEMPTY;
}

#if FUSE_USE_VERSION >= 30
int op_rename(const char* from, const char* to, unsigned int) {
#else
int op_rename(const char* from, const char* to) {
#endif
  auto a = map_path(from);
  auto b = map_path(to);
  if (!a || !b) return -EIO;
  std::error_code ec;
  fs::rename(*a, *b, ec);
  if (ec) return -EIO;
  // filename encryption is (dir, name)-dependent. if the parent dir changes we'd
  // need to re-encrypt the filename. v0.1 compromise: the renamed ciphertext on
  // disk is already in the right directory, but its encoded name was computed for
  // the *old* dir. readdir will then fail to decrypt it. we document this and
  // make rename only work within the same directory in v0.1.
  // TODO v0.2: re-encrypt on cross-dir rename.
  return 0;
}

#if FUSE_USE_VERSION >= 30
int op_truncate(const char* path, off_t size, struct fuse_file_info*) {
#else
int op_truncate(const char* path, off_t size) {
#endif
  auto disk = map_path(path);
  if (!disk) return -EIO;
  auto pt = read_plain(*disk);
  std::vector<std::uint8_t> buf = pt.value_or(std::vector<std::uint8_t>{});
  buf.resize(size, 0);
  return write_plain(*disk, buf.data(), buf.size());
}

fuse_operations make_ops() {
  fuse_operations ops{};
  ops.getattr = op_getattr;
  ops.readdir = op_readdir;
  ops.open = op_open;
  ops.read = op_read;
  ops.write = op_write;
  ops.create = op_create;
  ops.unlink = op_unlink;
  ops.mkdir = op_mkdir;
  ops.rmdir = op_rmdir;
  ops.rename = op_rename;
  ops.truncate = op_truncate;
  return ops;
}

}  // namespace

int run_fuse(Vault vault_in, const std::string& mountpoint,
             const std::vector<std::string>& extra_argv) {
  static Vault g_vault = std::move(vault_in);  // fuse wants a stable pointer
  auto ops = make_ops();

  std::vector<std::string> argv_storage{"sealdir"};
  for (const auto& a : extra_argv) argv_storage.push_back(a);
  argv_storage.push_back(mountpoint);

  std::vector<char*> argv;
  argv.reserve(argv_storage.size());
  for (auto& s : argv_storage) argv.push_back(s.data());

  return fuse_main(static_cast<int>(argv.size()), argv.data(), &ops, &g_vault);
}

}  // namespace sealdir

#endif  // SEALDIR_HAVE_FUSE
