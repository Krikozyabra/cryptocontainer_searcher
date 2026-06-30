#include "crypto_utils/luksdecrypt.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <libcryptsetup.h>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace luksdecrypt {
int decrypt_to_file(const fs::path &encrypted_file, const std::string &password,
                    const fs::path &decrypted_file) {
    const std::string stem = encrypted_file.stem().string();
    const std::string mapping_device = stem + "_device";
    const fs::path mapped_path{"/dev/mapper/" + mapping_device};

    struct crypt_device *cd = nullptr;

    // 1. Initialize device context
    if (crypt_init(&cd, encrypted_file.c_str()) < 0) {
        std::cerr << "Failed to initialize crypt device context.\n";
        return 1;
    }

    // 2. Load the LUKS header
    if (crypt_load(cd, CRYPT_LUKS, nullptr) < 0) {
        std::cerr << "Failed to load LUKS header.\n";
        crypt_free(cd);
        return 1;
    }

    // 3. Activate the device (creates /dev/mapper/temp_decrypted_mapping)
    // We open it read-only for safety.
    int act_status = crypt_activate_by_passphrase(
        cd, mapping_device.c_str(), CRYPT_ANY_SLOT, password.c_str(),
        strlen(password.c_str()), CRYPT_ACTIVATE_READONLY);

    if (act_status < 0) {
        std::cerr
            << "Activation failed. Incorrect passphrase or error occurred.\n";
        crypt_free(cd);
        return 1;
    }

    std::ifstream src{mapped_path, std::ios::binary};
    if (!src) {
        std::cerr << "Error: Failed to open mapped device for reading: "
                  << mapped_path << "\n";
        return 1;
    }

    std::ofstream dest(decrypted_file, std::ios::binary);
    if (!dest) {
        std::cerr << "Error: Failed to open output file for writing: "
                  << decrypted_file << "\n";
        return 1;
    }

    std::vector<char> buffer(4096 * 1024);
    while (src.read(buffer.data(), buffer.size())) {
        dest.write(buffer.data(), src.gcount());
    }
    // Write any final remaining bytes
    if (src.gcount() > 0) {
        dest.write(buffer.data(), src.gcount());
    }

    if (crypt_deactivate(cd, mapping_device.c_str()) < 0) {
        std::cerr << "Warning: Failed to deactivate mapping: " << mapping_device
                  << "\n";
    }

    crypt_free(cd);
    return 0;
}
} // namespace luksdecrypt
