#include "crypto_utils/crypto_search.h"
#include "entropy/shannon_entropy.h"
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace fs = std::filesystem;

namespace {
// Helper: Safely reads a fixed-size header into a std::array
template <size_t N>
bool read_header(const fs::path &path, std::array<char, N> &buffer) {
    std::ifstream byte_stream(path, std::ios::binary);
    if (!byte_stream) {
        return false;
    }
    return static_cast<bool>(byte_stream.read(buffer.data(), N));
}
} // namespace

namespace crypto_search {

bool encfs_file(const fs::path &file) {
    // Direct path comparison avoids converting to std::string and heap
    // allocation
    const auto filename = file.filename();
    return filename == ".encfs6" || filename == ".encfs6.xml";
}

bool luks_file(const fs::path &file) {
    std::array<char, 4> magic;
    if (read_header(file, magic)) {
        return std::memcmp(magic.data(), "LUKS", 4) == 0;
    }
    return false;
}

bool pgp_file(const fs::path &file) {
    // Cast hex constants to char to avoid compilation warnings on signed-char
    // systems
    constexpr std::array<char, 6> pgp_magic{
        static_cast<char>(0x8c), static_cast<char>(0x0d),
        static_cast<char>(0x04), static_cast<char>(0x09),
        static_cast<char>(0x03), static_cast<char>(0x0A)};

    std::array<char, 6> magic;
    if (read_header(file, magic)) {
        return magic == pgp_magic;
    }
    return false;
}

bool veracrypt_truecrypt_file(const fs::path &file) {
    std::error_code ec;
    const uintmax_t fsize = fs::file_size(file, ec);

    // Gracefully handle restricted/unreadable file errors instead of throwing
    if (ec || fsize == 0 || fsize % 512 != 0) {
        return false;
    }

    // Only instantiate the entropy checker if the file fits the criteria
    entropy::ShannonEncryptionChecker checker;
    return checker.get_file_entropy(file.string()) > 7.9;
}

} // namespace crypto_search
