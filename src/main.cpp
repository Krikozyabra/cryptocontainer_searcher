#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <cstdlib> 
#include <entropy/shannon_entropy.h>

namespace fs = std::filesystem;

void usage_exit(){
    std::cout << "Crypto search works only with TrueCrypt/VeraCrypt, EncFS, LUKS, PGP containers.\n \
                 Usage:\n\
                 \tcrypto_search --folder 'Folder' [--recursive]\n\n\
                 You can use the following commands:\n\
                 \t--help - to see this message\n\
                 \t--version - to see version of the program\n\
                 \t--folder - to set folder to search in\n\
                 \t--recursive - to check nested folders\n";
    std::exit(EXIT_SUCCESS);
}

void version_exit(){
    std::cout << "0.0.2\n";
    std::exit(EXIT_SUCCESS);
}

void check_for_enc_container(const fs::directory_entry& path_to_object, entropy::ShannonEncryptionChecker& checker){
    std::error_code ec;
    
    if (fs::is_regular_file(path_to_object, ec)) {
        std::string filename = path_to_object.path().filename().string();
        
        // Check for EncFS 
        if (filename == ".encfs6" || filename == ".encfs6.xml") {
            std::cout << path_to_object.path().parent_path() << "\n";
            std::cout << "This folder is encrypted with EncFS\n";
            return;
        }

        // Check for LUKS header (exactly 4 bytes)
        std::ifstream byte_stream(path_to_object.path(), std::ios::binary);
        if (byte_stream) {
            char magic[4];
            if (byte_stream.read(magic, sizeof(magic))) {
                if (std::memcmp(magic, "LUKS", 4) == 0) {
                    std::cout << path_to_object.path() << "\n";
                    std::cout << "File is encrypted with LUKS\n";
                    return;
                }
            }
        }

        // Check for TrueCrypt/VeraCrypt 
        uintmax_t fsize = fs::file_size(path_to_object, ec);
        if (!ec && fsize > 0 && fsize % 512 == 0) {
            double entropy_value = checker.get_file_entropy(path_to_object.path());
            if (entropy_value > 7.9) {
                std::cout << path_to_object.path() << "\n";
                std::cout << "File is encrypted with TrueCrypt\\VeraCrypt\n";
                return;
            }
        }
    }
}

void folder_traveler(const fs::path& searching_folder, entropy::ShannonEncryptionChecker& checker, const bool is_recursive){
    std::error_code ec;
    auto dir_iter = fs::directory_iterator(searching_folder, ec);
    if (ec) {
        std::cerr << "Warning: Cannot access folder " << searching_folder << " (" << ec.message() << ")\n";
        return;
    }

    for (const auto& entry : dir_iter) {
        std::error_code entry_ec;
        bool is_dir = entry.is_directory(entry_ec);
        if (entry_ec) {
            continue; 
        }

        // Run detection logic
        check_for_enc_container(entry, checker);

        // Recurse 
        if (is_recursive && is_dir) {
            folder_traveler(entry.path(), checker, is_recursive);
        }
    }
}

int main(int argc, char** argv) {
    std::setlocale(LC_ALL, 0);
    fs::path searching_folder{"/"}; 
    bool is_recursive = false;

    entropy::ShannonEncryptionChecker checker;
    
    if (argc < 2) {
        usage_exit();
    }

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0) {
            usage_exit();
        } else if (std::strcmp(argv[i], "--version") == 0) {
            version_exit();
        } else if (std::strcmp(argv[i], "--folder") == 0) {
            if (i + 1 < argc) {
                fs::path pathname{argv[++i]};
                std::error_code ec;
                if (!fs::exists(pathname, ec)) {
                    std::cerr << "Error: Folder '" << pathname << "' does not exist.\n";
                    return EXIT_FAILURE;
                }
                searching_folder = pathname;
            } else {
                std::cerr << "Error: --folder requires an argument.\n";
                usage_exit();
            }
        } else if (std::strcmp(argv[i], "--recursive") == 0) {
            is_recursive = true;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            usage_exit();
        }
    }

    try {
        folder_traveler(searching_folder, checker, is_recursive);
    } 
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
