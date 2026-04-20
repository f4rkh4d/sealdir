#include "sealdir/vault.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <random>

using namespace sealdir;
namespace fs = std::filesystem;

static fs::path tmpdir(const std::string& tag) {
  auto root = fs::temp_directory_path();
  std::random_device rd;
  auto p = root / ("sealdir_vault_" + tag + "_" + std::to_string(rd()));
  return p;
}

// init uses production KDF params which are slow. for tests we stub a faster path by
// writing a header directly, then opening. but open() also runs argon2id.
// so these tests take ~500ms each. that's fine for a unit suite.
// to keep ci snappy we only run a couple of full-path tests.

TEST_CASE("vault init + open + wrong password", "[vault]") {
  auto dir = tmpdir("open");
  // v0.1: Vault::init uses defaults. we override via header directly for speed.
  // instead, we write our own faster init here.
  Header h;
  h.kdf = KdfParams{1, 8ULL * 1024 * 1024};
  for (std::size_t i = 0; i < h.salt.size(); ++i) h.salt[i] = i + 7;
  fs::create_directories(dir / "data");
  Key master = derive_master_key("pw", h.salt, h.kdf);
  Key fnk = derive_subkey(master, "sealdir-filename-v1");
  write_header(dir, h, master, fnk);

  auto v = Vault::open(dir, "pw");
  REQUIRE(v.has_value());
  REQUIRE(v->count_files() == 0);

  auto bad = Vault::open(dir, "not pw");
  REQUIRE_FALSE(bad.has_value());

  fs::remove_all(dir);
}

TEST_CASE("vault seals + unseals content", "[vault]") {
  auto dir = tmpdir("seal");
  Header h;
  h.kdf = KdfParams{1, 8ULL * 1024 * 1024};
  fs::create_directories(dir / "data");
  Key master = derive_master_key("pw", h.salt, h.kdf);
  Key fnk = derive_subkey(master, "sealdir-filename-v1");
  write_header(dir, h, master, fnk);

  auto v = Vault::open(dir, "pw");
  REQUIRE(v.has_value());

  std::string pt = "hello vault";
  auto blob = v->seal(reinterpret_cast<const std::uint8_t*>(pt.data()), pt.size());
  auto out = v->unseal(blob.data(), blob.size());
  REQUIRE(out.has_value());
  REQUIRE(std::string(out->begin(), out->end()) == pt);

  fs::remove_all(dir);
}

TEST_CASE("vault encodes names deterministically", "[vault]") {
  auto dir = tmpdir("names");
  Header h;
  h.kdf = KdfParams{1, 8ULL * 1024 * 1024};
  fs::create_directories(dir / "data");
  Key master = derive_master_key("pw", h.salt, h.kdf);
  Key fnk = derive_subkey(master, "sealdir-filename-v1");
  write_header(dir, h, master, fnk);

  auto v = Vault::open(dir, "pw");
  REQUIRE(v.has_value());

  auto a = v->encode_name("", "readme.md");
  auto b = v->encode_name("", "readme.md");
  REQUIRE(a == b);
  auto dec = v->decode_name("", a);
  REQUIRE(dec.has_value());
  REQUIRE(*dec == "readme.md");

  fs::remove_all(dir);
}
