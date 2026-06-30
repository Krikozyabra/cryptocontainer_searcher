#pragma once
#include <filesystem>

namespace fs = std::filesystem;

namespace luksdecrypt {
    int decrypt_to_file(const fs::path &, const std::string &, const fs::path &);
} // namespace luksdecrypt
