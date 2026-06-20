#include "crypto_search.h"
#include <cstring>
#include <filesystem>
#include <fstream>
#include "entropy/shannon_entropy.h"

namespace fs = std::filesystem;

namespace crypto_search {

bool check_for_encfs_file(const fs::directory_entry &file) {
    std::string filename = file.path().filename().string();

    if (filename.compare(".encfs6") == 0 ||
        filename.compare(".encfs6.xml") == 0) {
        return true;
    }
    return false;
}

bool check_for_luks_file(const fs::directory_entry &file) {
    std::ifstream byte_stream(file.path().string(), std::ios::binary);
    if (byte_stream) {
        uint8_t magic[4];
        if (byte_stream.read(reinterpret_cast<char *>(magic), sizeof(magic))) {
            if (std::memcmp(magic, "LUKS", 4) == 0) {
                return true;
            }
        }
    }
    return false;
}

bool check_for_pgp_file(const fs::directory_entry &file){
    std::ifstream byte_stream(file.path().string(), std::ios::binary);
    uint8_t pgp_magic[6]{0x8c, 0x0d, 0x04, 0x09, 0x03, 0x0A};
    uint8_t magic[6]{};
    if(byte_stream.read(reinterpret_cast<char *>(magic), sizeof(magic))){
        if (std::memcmp(magic, pgp_magic, 6) == 0){
            return true;
        }
    }
    return false;
}


bool check_for_veracrypt(const fs::directory_entry &file){
    uintmax_t fsize = fs::file_size(file);
    
    entropy::ShannonEncryptionChecker checker;

    if(fsize > 0 && fsize % 512 == 0){
        double entropy_value =  checker.get_file_entropy(file.path().string());
        if (entropy_value > 7.9) {
            return true;
        }
    }
    return false;
}

} // namespace crypto_search
