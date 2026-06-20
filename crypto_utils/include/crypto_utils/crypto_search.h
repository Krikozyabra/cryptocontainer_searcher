#define once
#include <filesystem>

namespace fs = std::filesystem;

namespace crypto_search{

    bool encfs_file(const fs::directory_entry &file);
    bool luks_file(const fs::directory_entry &file);
    bool pgp_file(const fs::directory_entry &file);
    bool veracrypt_truecrypt_file(const fs::directory_entry &file);

}
