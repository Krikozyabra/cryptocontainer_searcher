#pragma once
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace crypto_decrypt {

// Return constants
constexpr int SUCCESS = 0;
constexpr int ERR_DECRYPT = 1;
constexpr int ERR_LUKS_WIN = 2;

int encfs(const fs::path &, const std::string&, const fs::path &);
int truecrypt(const fs::path &, const std::string&, const fs::path &);
int veracrypt(const fs::path &, const std::string&, const fs::path &);
int pgp(const fs::path &, const std::string&, const fs::path &);
int luks(const fs::path &, const std::string&, const fs::path &);

}
