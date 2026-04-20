// password.cpp - posix termios. no echo.
#include "sealdir/password.hpp"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace sealdir {

namespace {
int open_tty() {
  int fd = ::open("/dev/tty", O_RDWR | O_NOCTTY);
  if (fd < 0) throw std::runtime_error("no controlling tty");
  return fd;
}
}  // namespace

std::string read_password(std::string_view prompt) {
  int fd = open_tty();
  // write prompt
  ::write(fd, prompt.data(), prompt.size());

  termios oldt{}, newt{};
  if (tcgetattr(fd, &oldt) != 0) {
    ::close(fd);
    throw std::runtime_error("tcgetattr failed");
  }
  newt = oldt;
  newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
  if (tcsetattr(fd, TCSAFLUSH, &newt) != 0) {
    ::close(fd);
    throw std::runtime_error("tcsetattr failed");
  }

  std::string out;
  char ch;
  while (true) {
    ssize_t n = ::read(fd, &ch, 1);
    if (n <= 0) break;
    if (ch == '\n' || ch == '\r') break;
    if (ch == 0x7f || ch == 0x08) {  // backspace
      if (!out.empty()) out.pop_back();
      continue;
    }
    out.push_back(ch);
    if (out.size() > 4096) break;  // sanity
  }

  tcsetattr(fd, TCSAFLUSH, &oldt);
  ::write(fd, "\n", 1);
  ::close(fd);
  return out;
}

std::string read_password_confirmed(std::string_view prompt) {
  std::string a = read_password(prompt);
  std::string b = read_password("confirm: ");
  if (a != b) {
    throw std::runtime_error("passwords do not match");
  }
  return a;
}

}  // namespace sealdir
