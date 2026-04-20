// base64url.cpp - rfc 4648 section 5, no padding.
#include "sealdir/base64url.hpp"

#include <array>

namespace sealdir {

namespace {
constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr std::array<int, 256> make_rev() {
  std::array<int, 256> r{};
  for (auto& v : r) v = -1;
  for (int i = 0; i < 64; ++i) r[static_cast<unsigned char>(kAlphabet[i])] = i;
  return r;
}
constexpr auto kRev = make_rev();
}  // namespace

std::string base64url_encode(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve((len * 4 + 2) / 3);
  std::size_t i = 0;
  while (i + 3 <= len) {
    std::uint32_t v = (std::uint32_t(data[i]) << 16) |
                      (std::uint32_t(data[i + 1]) << 8) |
                      std::uint32_t(data[i + 2]);
    out += kAlphabet[(v >> 18) & 0x3f];
    out += kAlphabet[(v >> 12) & 0x3f];
    out += kAlphabet[(v >> 6) & 0x3f];
    out += kAlphabet[v & 0x3f];
    i += 3;
  }
  if (i < len) {
    std::uint32_t v = std::uint32_t(data[i]) << 16;
    if (i + 1 < len) v |= std::uint32_t(data[i + 1]) << 8;
    out += kAlphabet[(v >> 18) & 0x3f];
    out += kAlphabet[(v >> 12) & 0x3f];
    if (i + 1 < len) out += kAlphabet[(v >> 6) & 0x3f];
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> base64url_decode(const std::string& s) {
  std::vector<std::uint8_t> out;
  out.reserve(s.size() * 3 / 4);
  std::uint32_t buf = 0;
  int bits = 0;
  for (char c : s) {
    int v = kRev[static_cast<unsigned char>(c)];
    if (v < 0) return std::nullopt;
    buf = (buf << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xff));
    }
  }
  // trailing bits must be zero for canonical encoding
  if (bits > 0 && (buf & ((1u << bits) - 1u)) != 0) return std::nullopt;
  return out;
}

}  // namespace sealdir
