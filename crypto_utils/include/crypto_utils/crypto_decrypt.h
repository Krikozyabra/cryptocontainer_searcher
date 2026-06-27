#pragma once
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace crypto_decrypt {

// Return constants
constexpr int SUCCESS = 0;
constexpr int ERR_PIPE_OPEN = 1;
constexpr int ERR_DECRYPT = 2;
constexpr int ERR_MOUNT = 3;
constexpr int ERR_LOOP_DEVICE = 4;
constexpr int ERR_QUERY_PIPE = 5;

int encfs(const fs::path &, const std::string& password);
int truecrypt(const fs::path &, const std::string&, const fs::path &, const bool is_veracrypt = false);
int pgp(const fs::path &, const std::string& password);
int luks(const fs::path &, const std::string& password);

}
