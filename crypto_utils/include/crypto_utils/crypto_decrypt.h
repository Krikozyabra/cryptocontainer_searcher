#pragma once
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace crypto_decrypt {

void encfs(const fs::path &, const std::string& password);
void truecrypt(const fs::path &, const std::string& password);
void veracrypt(const fs::path &, const std::string& password);
void pgp(const fs::path &, const std::string& password);
void luks(const fs::path &, const std::string& password);

}
