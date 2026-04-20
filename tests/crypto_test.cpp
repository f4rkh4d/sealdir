#include "sealdir/crypto.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>

using namespace sealdir;

TEST_CASE("blob roundtrip", "[crypto]") {
  REQUIRE(sodium_init_once());
  Key k{};
  for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(i);

  std::string pt = "attack at dawn, same password twice should not collide";
  auto blob = encrypt_blob(k, reinterpret_cast<const std::uint8_t*>(pt.data()), pt.size());
  REQUIRE(blob.size() == pt.size() + 24 + 16);

  auto out = decrypt_blob(k, blob.data(), blob.size());
  REQUIRE(out.has_value());
  REQUIRE(std::string(out->begin(), out->end()) == pt);
}

TEST_CASE("tamper detection", "[crypto]") {
  Key k{};
  for (std::size_t i = 0; i < k.size(); ++i) k[i] = 0xA5;
  std::string pt = "hello world";
  auto blob = encrypt_blob(k, reinterpret_cast<const std::uint8_t*>(pt.data()), pt.size());

  // flip a byte in the ciphertext portion
  blob[30] ^= 0x01;
  auto out = decrypt_blob(k, blob.data(), blob.size());
  REQUIRE_FALSE(out.has_value());
}

TEST_CASE("wrong key fails", "[crypto]") {
  Key k1{}; Key k2{};
  for (std::size_t i = 0; i < 32; ++i) { k1[i] = i; k2[i] = i ^ 1; }
  std::string pt = "secret";
  auto blob = encrypt_blob(k1, reinterpret_cast<const std::uint8_t*>(pt.data()), pt.size());
  auto out = decrypt_blob(k2, blob.data(), blob.size());
  REQUIRE_FALSE(out.has_value());
}

TEST_CASE("argon2id derives deterministic keys", "[crypto]") {
  Salt salt{};
  for (std::size_t i = 0; i < salt.size(); ++i) salt[i] = i;
  // keep opslimit small so the test runs fast
  KdfParams fast{1, 8ULL * 1024 * 1024};
  Key a = derive_master_key("hunter2", salt, fast);
  Key b = derive_master_key("hunter2", salt, fast);
  Key c = derive_master_key("hunter3", salt, fast);
  REQUIRE(std::memcmp(a.data(), b.data(), 32) == 0);
  REQUIRE(std::memcmp(a.data(), c.data(), 32) != 0);
}

TEST_CASE("subkey derivation separates contexts", "[crypto]") {
  Key master{};
  for (std::size_t i = 0; i < 32; ++i) master[i] = 0x42;
  Key k1 = derive_subkey(master, "content-v1");
  Key k2 = derive_subkey(master, "filename-v1");
  REQUIRE(std::memcmp(k1.data(), k2.data(), 32) != 0);
}
