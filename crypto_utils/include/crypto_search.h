#pragma once
#include <filesystem>

namespace fs = std::filesystem;

namespace crypto_search{

    bool check_for_encfs_file(const fs::directory_entry &file);
    bool check_for_luks_file(const fs::directory_entry &file);
    bool check_for_pgp_file(const fs::directory_entry &file);
    bool check_for_veracrypt(const fs::directory_entry &file);

}
