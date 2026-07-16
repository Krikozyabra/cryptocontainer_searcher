#include "crypto_utils/crypto_search.h"
#include "Tyfe/Tyfe.hpp"
#include "entropy/shannon_entropy.h"
#include "gpgutil.hpp"
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#ifdef LOG_ENABLED
#include <spdlog/spdlog.h>
#endif
#include <system_error>
#include <tinyxml2.h>

namespace fs = std::filesystem;

namespace {
// Helper: Safely reads a fixed-size header into a std::array
template <typename T, size_t N>
bool read_header(const fs::path &path, std::array<T, N> &buffer) {
    std::ifstream byte_stream(path, std::ios::binary);
    if (!byte_stream) {
        return false;
    }
    return static_cast<bool>(byte_stream.read(
        reinterpret_cast<char *>(buffer.data()), N * sizeof(T)));
}

bool is_valid_config(const fs::path &path) {
#ifdef LOG_ENABLED
    spdlog::info("Started checking EncFS config validation");
#endif
    tinyxml2::XMLDocument cfg;
    if (auto result = cfg.LoadFile(path.string().c_str());
        result != tinyxml2::XML_SUCCESS) {
#ifdef LOG_ENABLED
        spdlog::warn("EncFS config was not parse successefully");
#endif
        return false;
    }

    auto *root = cfg.FirstChildElement("boost_serialization");
    if (!root) {
#ifdef LOG_ENABLED
        spdlog::warn("No correct root in config");
#endif
        return false;
    }

    if (auto *cfgElement = root->FirstChildElement("cfg");
        cfgElement != nullptr) {
        if (auto *cipherElement = cfgElement->FirstChildElement("cipherAlg");
            cipherElement != nullptr) {
            if (!cipherElement->NoChildren()) {
                return true;
            }
#ifdef LOG_ENABLED
            else {
                spdlog::warn("Child 'cipherAlg' does not have childs");
            }
#endif
        }
#ifdef LOG_ENABLED
        else {
            spdlog::warn("Child 'cipherAlg' was not found");
        }
#endif
    }
#ifdef LOG_ENABLED
    else {
        spdlog::warn("Child 'cfg' was not found");
    }
#endif
    return false;
}

double get_file_chi_square(const fs::path &file) {
#ifdef LOG_ENABLED
    spdlog::info("Chi square calculation started");
#endif
    std::ifstream ifs(file, std::ios::binary);
    if (!ifs) {
        return -1.0; // Error indicator
    }

    std::vector<uint64_t> counts(256, 0);
    uint64_t total_bytes = 0;

    constexpr size_t buffer_size = 65536;
    std::vector<char> buffer(buffer_size);

    while (ifs.read(buffer.data(), buffer_size) || ifs.gcount() > 0) {
        std::streamsize bytes_read = ifs.gcount();
        for (std::streamsize i = 0; i < bytes_read; ++i) {
            unsigned char byte_val = static_cast<unsigned char>(buffer[i]);
            counts[byte_val]++;
        }
        total_bytes += bytes_read;
    }

    if (total_bytes == 0) {
        return -1.0;
    }

    double sum_sq = 0.0;
    for (int i = 0; i < 256; ++i) {
        sum_sq += static_cast<double>(counts[i]) * counts[i];
    }

    return (256.0 / total_bytes) * sum_sq - total_bytes;
}
} // namespace

namespace crypto_search {

bool encfs_file(const fs::path &file) {
    #ifdef LOG_ENABLED
       spdlog::info("EncFS detection started for " + file.string());
    #endif
    const auto filename = file.filename();
    return (filename == ".encfs6" || filename == ".encfs6.xml") &&
           is_valid_config(file);
}

bool luks_file(const fs::path &file) {
    #ifdef LOG_ENABLED
       spdlog::info("LUKS detection started for " + file.string());
    #endif
    std::array<uint8_t, 8> magic;
    std::array<uint8_t, 8> luks1 = {0x4c, 0x55, 0x4b, 0x53,
                                    0xba, 0xbe, 0x00, 0x01};
    std::array<uint8_t, 8> luks2 = {0x4c, 0x55, 0x4b, 0x53,
                                    0xba, 0xbe, 0x00, 0x02};
    if (read_header(file, magic)) {
        return (magic == luks1) || (magic == luks2);
    }
    return false;
}

bool pgp_file(const fs::path &file) {
    #ifdef LOG_ENABLED
       spdlog::info("PGP detection started for " + file.string());
    #endif

    std::ifstream fileStream(file.string(), std::ios::binary);
    if (!fileStream) {
        return false;
    }

    unsigned char firstByte = 0;
    if (!fileStream.read(reinterpret_cast<char*>(&firstByte), 1)) {
        return false;
    }

    if ((firstByte & 0x80) == 0) {
        return false;
    }

    bool isNewFormat = (firstByte & 0x40) != 0;
    int packetTag = 0;

    if (isNewFormat) {
        packetTag = firstByte & 0x3F;
    } else {
        packetTag = (firstByte >> 2) & 0x0F;
    }

    if (packetTag != 3) {
        return false;
    }
	
	unsigned char secondByte = 0;
    if (!fileStream.read(reinterpret_cast<char*>(&secondByte), 1)) {
        return false;
    }

    if ((secondByte & 0x80) == 0) {
        return false;
    }

    isNewFormat = (secondByte & 0x40) != 0;

    if (isNewFormat) {
        packetTag = secondByte & 0x3F;
    } else {
        packetTag = (secondByte >> 2) & 0x0F;
    }

    if (packetTag == 3 || packetTag == 9 || packetTag == 18) {
        return true;
    }

    return false;
}

bool veracrypt_truecrypt_file(const fs::path &file) {
    #ifdef LOG_ENABLED
       spdlog::info("True/Vera Crypt detection started for " + file.string());
    #endif
    std::error_code ec;
    const uintmax_t fsize = fs::file_size(file, ec);
    Tyfe check_magic;
    if (check_magic.check(file.string()) != TYFES::NOTHING)
        return false;
    if (ec || fsize == 0 || fsize % 512 != 0)
        return false;

    entropy::ShannonEncryptionChecker checker;
    if (checker.get_file_entropy(file.string()) <= 7.99)
        return false;

    double chi_square = get_file_chi_square(file);
    return (chi_square >= 190 &&
            chi_square <=
                325); // bitween 1 and 99% of critical values of 256 degrees
}

} // namespace crypto_search
