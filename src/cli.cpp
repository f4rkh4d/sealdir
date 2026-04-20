// cli.cpp - hand-rolled arg parser. no deps.
#include "sealdir/crypto.hpp"
#include "sealdir/header.hpp"
#include "sealdir/password.hpp"
#include "sealdir/vault.hpp"

#ifdef SEALDIR_HAVE_FUSE
#include "sealdir/fs.hpp"
#endif

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace sealdir {

namespace {

void print_usage() {
  std::cerr <<
    "sealdir 0.1.0 - encrypted fuse-mounted directory\n"
    "\n"
    "usage:\n"
    "  sealdir init <vault-dir>\n"
    "  sealdir mount <vault-dir> <mountpoint> [-f] [-d] [--daemon]\n"
    "  sealdir unmount <mountpoint>\n"
    "  sealdir change-password <vault-dir>\n"
    "  sealdir info <vault-dir>\n";
}

int cmd_init(int argc, char** argv) {
  if (argc < 1) { print_usage(); return 2; }
  std::string dir = argv[0];
  std::string pw = read_password_confirmed("new password: ");
  if (pw.empty()) {
    std::cerr << "empty password refused\n";
    return 1;
  }
  Vault::init(dir, pw);
  std::cerr << "vault initialized at " << dir << "\n";
  return 0;
}

int cmd_info(int argc, char** argv) {
  if (argc < 1) { print_usage(); return 2; }
  Header h = read_header(argv[0]);
  std::cout << "sealdir vault: " << argv[0] << "\n";
  std::cout << "  version: " << h.version << "\n";
  std::cout << "  kdf: argon2id opslimit=" << h.kdf.opslimit
            << " memlimit=" << h.kdf.memlimit << " bytes\n";
  // count files without opening vault (we can just count data/ entries recursively).
  std::size_t n = 0;
  std::error_code ec;
  std::filesystem::path data = std::filesystem::path(argv[0]) / "data";
  if (std::filesystem::exists(data, ec)) {
    for (const auto& e : std::filesystem::recursive_directory_iterator(data, ec)) {
      if (e.is_regular_file()) ++n;
    }
  }
  std::cout << "  encrypted files: " << n << "\n";
  return 0;
}

int cmd_change_password(int argc, char** argv) {
  if (argc < 1) { print_usage(); return 2; }
  std::string old_pw = read_password("current password: ");
  auto v = Vault::open(argv[0], old_pw);
  if (!v) { std::cerr << "wrong password\n"; return 1; }
  std::string new_pw = read_password_confirmed("new password: ");
  if (!v->change_password(old_pw, new_pw)) {
    std::cerr << "failed\n"; return 1;
  }
  std::cerr << "password changed\n";
  return 0;
}

int cmd_unmount(int argc, char** argv) {
  if (argc < 1) { print_usage(); return 2; }
  // wrap fusermount3 -u on linux, umount on macos.
#ifdef __linux__
  const char* tool = "fusermount3";
  const char* flag = "-u";
#else
  const char* tool = "umount";
  const char* flag = nullptr;
#endif
  pid_t pid = fork();
  if (pid == 0) {
    if (flag) execlp(tool, tool, flag, argv[0], nullptr);
    else      execlp(tool, tool, argv[0], nullptr);
    std::perror("exec");
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int cmd_mount(int argc, char** argv) {
#ifndef SEALDIR_HAVE_FUSE
  (void)argc; (void)argv;
  std::cerr << "this build was compiled without fuse support.\n"
               "install libfuse3-dev (linux) or macfuse (macos) and rebuild.\n";
  return 2;
#else
  if (argc < 2) { print_usage(); return 2; }
  std::string vault_dir = argv[0];
  std::string mountpoint = argv[1];

  std::vector<std::string> extra;
  bool daemon = false;
  bool foreground = true;  // default per spec
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-f") foreground = true;
    else if (a == "-d") { extra.push_back("-d"); foreground = true; }
    else if (a == "--daemon") daemon = true;
    else { std::cerr << "unknown mount flag: " << a << "\n"; return 2; }
  }
  if (foreground && !daemon) extra.push_back("-f");

  std::string pw = read_password("password: ");
  auto v = Vault::open(vault_dir, pw);
  if (!v) { std::cerr << "wrong password or invalid vault\n"; return 1; }
  return run_fuse(std::move(*v), mountpoint, extra);
#endif
}

}  // namespace

int cli_main(int argc, char** argv) {
  if (!sodium_init_once()) {
    std::cerr << "libsodium init failed\n";
    return 1;
  }
  if (argc < 2) { print_usage(); return 2; }
  std::string sub = argv[1];
  int sub_argc = argc - 2;
  char** sub_argv = argv + 2;
  try {
    if (sub == "init") return cmd_init(sub_argc, sub_argv);
    if (sub == "mount") return cmd_mount(sub_argc, sub_argv);
    if (sub == "unmount" || sub == "umount") return cmd_unmount(sub_argc, sub_argv);
    if (sub == "change-password") return cmd_change_password(sub_argc, sub_argv);
    if (sub == "info") return cmd_info(sub_argc, sub_argv);
    if (sub == "-h" || sub == "--help" || sub == "help") { print_usage(); return 0; }
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  print_usage();
  return 2;
}

}  // namespace sealdir
