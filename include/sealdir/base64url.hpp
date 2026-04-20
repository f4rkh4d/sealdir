// base64url.hpp - url-safe base64 without padding.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sealdir {

std::string base64url_encode(const std::uint8_t* data, std::size_t len);
std::optional<std::vector<std::uint8_t>> base64url_decode(const std::string& s);

}  // namespace sealdir
