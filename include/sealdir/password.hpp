// password.hpp - tty password reading with echo disabled.
#pragma once

#include <string>
#include <string_view>

namespace sealdir {

// read a line from /dev/tty with echo off. returns the password (no trailing \n).
// prints prompt to stderr. throws std::runtime_error if no tty.
std::string read_password(std::string_view prompt);

// read twice and require match. throws on mismatch.
std::string read_password_confirmed(std::string_view prompt);

}  // namespace sealdir
