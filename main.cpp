#include "crypto_utils/crypto_search.h"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

void usage_exit() {
    std::cout << "Crypto search works only with TrueCrypt/VeraCrypt, EncFS, "
                 "LUKS, PGP containers.\n"
                 "Usage:\n"
                 "\tcrypto_search --folder [folder] [--recursive]\n\n"
                 "You can use the following commands:\n"
                 "\t--help - to see this message\n"
                 "\t--version - to see version of the program\n"
                 "\t--folder - to set folder to search in (default='/')\n"
                 "\t--recursive - to check nested folders\n";
    std::exit(EXIT_SUCCESS);
}

void version_exit() {
    std::cout << "0.0.3\n";
    std::exit(EXIT_SUCCESS);
}

void check_for_enc_container(const fs::directory_entry &path_to_object) {
    std::error_code ec;

    if (fs::is_regular_file(path_to_object, ec)) {
        if (crypto_search::check_for_encfs_file(path_to_object)) {
            std::cout << path_to_object.path().parent_path() << std::endl;
            std::cout << "This folder is encrypted with EncFS" << std::endl;
        }
        if (crypto_search::check_for_luks_file(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with LUKS" << std::endl;
        }
        if (crypto_search::check_for_pgp_file(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with PGP" << std::endl;
        }
        if (crypto_search::check_for_veracrypt(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with TrueCrypt\\VeraCrypt" << std::endl;
        }
    }
}

void folder_traveler(const fs::path &searching_folder,
                     const bool is_recursive) {
    std::error_code ec;
    auto dir_iter = fs::directory_iterator(searching_folder, ec);
    if (ec) {
        std::cerr << "Warning: Cannot access folder " << searching_folder
                  << " (" << ec.message() << ")\n";
        return;
    }

    for (const auto &entry : dir_iter) {
        std::error_code entry_ec;
        bool is_dir = entry.is_directory(entry_ec);
        if (entry_ec) {
            continue;
        }

        // Run detection logic
        check_for_enc_container(entry);

        // Recurse
        if (is_recursive && is_dir) {
            folder_traveler(entry.path(), is_recursive);
        }
    }
}

int main(int argc, char **argv) {
    std::setlocale(LC_ALL, 0);
    fs::path searching_folder{"/"};
    bool is_recursive = false;

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
                    std::cerr << "Error: Folder '" << pathname
                              << "' does not exist.\n";
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
        folder_traveler(searching_folder, is_recursive);
    } catch (const std::exception &e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
