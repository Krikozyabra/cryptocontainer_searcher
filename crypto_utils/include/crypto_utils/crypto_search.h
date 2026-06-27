#pragma once
#include <filesystem>

namespace fs = std::filesystem;

namespace crypto_search{

    bool encfs_file(const fs::path &file);
    bool luks_file(const fs::path &file);
    bool pgp_file(const fs::path &file);
    bool veracrypt_truecrypt_file(const fs::path &file);

}
