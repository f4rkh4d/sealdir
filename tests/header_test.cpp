#include "sealdir/header.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <random>

using namespace sealdir;
namespace fs = std::filesystem;

static fs::path tmpdir(const std::string& tag) {
  auto root = fs::temp_directory_path();
  std::random_device rd;
  auto p = root / ("sealdir_test_" + tag + "_" + std::to_string(rd()));
  fs::create_directories(p);
  return p;
}

TEST_CASE("header write + read roundtrip", "[header]") {
  auto dir = tmpdir("hdr");

  Header h;
  h.version = kCurrentVersion;
  h.kdf_algo = 1;
  h.kdf = KdfParams{1, 8ULL * 1024 * 1024};  // fast for tests
  for (std::size_t i = 0; i < h.salt.size(); ++i) h.salt[i] = i;

  Key master = derive_master_key("correct horse", h.salt, h.kdf);
  Key fnk = derive_subkey(master, "sealdir-filename-v1");
  write_header(dir, h, master, fnk);

  Header read = read_header(dir);
  REQUIRE(read.version == h.version);
  REQUIRE(read.kdf.opslimit == h.kdf.opslimit);
  REQUIRE(read.kdf.memlimit == h.kdf.memlimit);
  REQUIRE(read.salt == h.salt);

  auto ok = verify_password(read, "correct horse");
  REQUIRE(ok.has_value());

  auto bad = verify_password(read, "wrong");
  REQUIRE_FALSE(bad.has_value());

  auto fnk2 = unwrap_filename_key(read, *ok);
  REQUIRE(fnk2.has_value());

  fs::remove_all(dir);
}

TEST_CASE("corrupted magic rejected", "[header]") {
  auto dir = tmpdir("magic");
  Header h;
  h.kdf = KdfParams{1, 8ULL * 1024 * 1024};
  Key master = derive_master_key("pw", h.salt, h.kdf);
  Key fnk = derive_subkey(master, "sealdir-filename-v1");
  write_header(dir, h, master, fnk);

  // corrupt byte 0
  std::fstream f(dir / "sealdir.header", std::ios::binary | std::ios::in | std::ios::out);
  f.seekp(0);
  char c = 'X';
  f.write(&c, 1);
  f.close();

  REQUIRE_THROWS(read_header(dir));
  fs::remove_all(dir);
}

TEST_CASE("short file rejected", "[header]") {
  auto dir = tmpdir("short");
  fs::create_directories(dir);
  std::ofstream(dir / "sealdir.header", std::ios::binary) << "SEALDIR";
  REQUIRE_THROWS(read_header(dir));
  fs::remove_all(dir);
}
