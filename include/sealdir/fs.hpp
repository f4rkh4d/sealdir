// fs.hpp - fuse operations bridge.
#pragma once

#include "sealdir/vault.hpp"

namespace sealdir {

// runs fuse_main with the given vault mounted at mountpoint. blocks until unmounted.
// extra_argv: forwarded to fuse (e.g. "-f", "-d"). returns fuse's exit code.
int run_fuse(Vault vault, const std::string& mountpoint,
             const std::vector<std::string>& extra_argv);

}  // namespace sealdir
