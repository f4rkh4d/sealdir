#include "sealdir/base64url.hpp"
#include "sealdir/crypto.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace sealdir;

TEST_CASE("filename determinism", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  auto a = encrypt_filename_raw(k, "docs", "notes.md");
  auto b = encrypt_filename_raw(k, "docs", "notes.md");
  REQUIRE(a == b);
}

TEST_CASE("different plaintext -> different ciphertext", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  auto a = encrypt_filename_raw(k, "docs", "a.md");
  auto b = encrypt_filename_raw(k, "docs", "b.md");
  REQUIRE(a != b);
}

TEST_CASE("same name in different dir -> different ciphertext", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  auto a = encrypt_filename_raw(k, "dir1", "notes.md");
  auto b = encrypt_filename_raw(k, "dir2", "notes.md");
  REQUIRE(a != b);
}

TEST_CASE("filename roundtrip", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  std::string plaintext = "super secret filename with spaces.txt";
  auto ct = encrypt_filename_raw(k, "subdir/x", plaintext);
  auto pt = decrypt_filename_raw(k, "subdir/x", ct.data(), ct.size());
  REQUIRE(pt.has_value());
  REQUIRE(*pt == plaintext);
}

TEST_CASE("filename decrypt rejects wrong dir", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  auto ct = encrypt_filename_raw(k, "dir1", "a.md");
  auto pt = decrypt_filename_raw(k, "dir2", ct.data(), ct.size());
  REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("filename tamper fails SIV recheck", "[filename]") {
  Key k{};
  for (std::size_t i = 0; i < 32; ++i) k[i] = i;
  auto ct = encrypt_filename_raw(k, "d", "hello.txt");
  ct.back() ^= 0x01;  // flip a ct byte
  auto pt = decrypt_filename_raw(k, "d", ct.data(), ct.size());
  REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("base64url roundtrip", "[base64]") {
  std::vector<std::uint8_t> data{0, 1, 2, 3, 4, 5, 0xff, 0xfe, 0xfd, 0x80, 0x7f};
  auto s = base64url_encode(data.data(), data.size());
  REQUIRE(s.find('+') == std::string::npos);
  REQUIRE(s.find('/') == std::string::npos);
  REQUIRE(s.find('=') == std::string::npos);
  auto back = base64url_decode(s);
  REQUIRE(back.has_value());
  REQUIRE(*back == data);
}

TEST_CASE("base64url empty + tiny inputs", "[base64]") {
  REQUIRE(base64url_encode(nullptr, 0) == "");
  REQUIRE(base64url_decode("")->empty());

  std::uint8_t one[1] = {0xab};
  auto enc = base64url_encode(one, 1);
  auto dec = base64url_decode(enc);
  REQUIRE(dec.has_value());
  REQUIRE(dec->size() == 1);
  REQUIRE((*dec)[0] == 0xab);
}

TEST_CASE("base64url rejects invalid chars", "[base64]") {
  REQUIRE_FALSE(base64url_decode("abc$").has_value());
}
