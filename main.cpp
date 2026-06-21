#include "crypto_utils/crypto_search.h"
#include "crypto_utils/crypto_decrypt.h"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <fstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

void usage_exit() {
    std::cout << "Crypto search works only with TrueCrypt/VeraCrypt, EncFS, "
                 "LUKS, PGP containers.\n"
                 "Usage:\n"
                 "\tcrypto_search --folder [folder] [--recursive]\n\n"
                 "You can use the following commands:\n"
                 "\t--help - to see this message\n"
                 "\t--version - to see version of the program\n"
                 "\t--folder - to set folder to search in (default='/')\n"
                 "\t--recursive - to check nested folders\n"
                 "\t--decrypt [file] - to try decryption every found container "
                 "with passwords in file\n";
    std::exit(EXIT_SUCCESS);
}

void version_exit() {
    std::cout << "0.0.3\n";
    std::exit(EXIT_SUCCESS);
}

int check_for_enc_container(const fs::directory_entry &path_to_object, const bool try_to_decrypt, const json& pass_file) {
    std::error_code ec;
    int return_code{crypto_decrypt::SUCCESS};

    if (fs::is_regular_file(path_to_object, ec)) {
        if (crypto_search::encfs_file(path_to_object)) {
            std::cout << path_to_object.path().parent_path() << std::endl;
            std::cout << "This folder is encrypted with EncFS" << std::endl;
            if (try_to_decrypt){
                for (const std::string& passphrase : pass_file["encfs"]){
                    return_code = crypto_decrypt::encfs(path_to_object, passphrase);
                    if(return_code == crypto_decrypt::SUCCESS) break;  
                }
            }
            return return_code;
        }
        if (crypto_search::luks_file(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with LUKS"
                      << std::endl;
            if (try_to_decrypt){
                for (const std::string& passphrase : pass_file["luks"]){
                    return_code = crypto_decrypt::luks(path_to_object, passphrase);
                    if(return_code == crypto_decrypt::SUCCESS) break;  
                }
            }
            return return_code;
        }
        if (crypto_search::pgp_file(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with PGP"
                      << std::endl;
            if (try_to_decrypt){
                for (const std::string& passphrase : pass_file["pgp"]){
                    return_code = crypto_decrypt::pgp(path_to_object, passphrase);
                    if(return_code == crypto_decrypt::SUCCESS) break;  
                }
            }
            return return_code;
        }
        if (crypto_search::veracrypt_truecrypt_file(path_to_object)) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with "
                         "TrueCrypt\\VeraCrypt"
                      << std::endl;
            if (try_to_decrypt){
                for (const std::string& passphrase : pass_file["truecrypt"]){
                    return_code = crypto_decrypt::truecrypt(path_to_object, passphrase);
                    if(return_code == crypto_decrypt::SUCCESS) break;  
                }
                for (const std::string& passphrase : pass_file["veracrypt"]){
                    return_code = crypto_decrypt::truecrypt(path_to_object, passphrase, true);
                    if(return_code == crypto_decrypt::SUCCESS) break;  
                }
            }
            return return_code;
        }
    }

    if (ec == std::errc::permission_denied) {
        std::cout << path_to_object.path() << std::endl;
        std::cout << "No access to this file. Run in 'sudo' mode" << std::endl;
    }

    return return_code;
}

void folder_traveler(const fs::path &searching_folder,
                     const json &pass_file, const bool is_recursive, const bool try_to_decrypt) {
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
        int return_result = check_for_enc_container(entry, try_to_decrypt, pass_file);
        switch (return_result) {
            case crypto_decrypt::ERR_DECRYPT:
                std::cerr << "No password found for this container" << std::endl;
                break;
            case crypto_decrypt::ERR_MOUNT:
                std::cerr << "An error occurred while mounting" << std::endl;
                break;
            case crypto_decrypt::ERR_PIPE_OPEN:
                std::cerr << "An error occurred while openning pipe for password" << std::endl;
                break;
            case crypto_decrypt::ERR_QUERY_PIPE:
                std::cerr << "An error occured while openning pipe for read loop device path" << std::endl;
                break;
            case crypto_decrypt::ERR_LOOP_DEVICE:
                std::cerr << "An error occured while creating loop device" << std::endl;
                break;
        }
        // Recurse
        if (is_recursive && is_dir) {
            folder_traveler(entry.path(), pass_file, is_recursive, try_to_decrypt);
        }
    }
}

bool is_command_in_path(const std::string &command) {
    const char *path_env = std::getenv("PATH");
    if (!path_env)
        return false;

    std::stringstream ss(path_env);
    std::string directory{};

    const char delimiter{':'};

    while (std::getline(ss, directory, delimiter)) {
        fs::path full_path = fs::path(directory) / command;

        if (fs::exists(full_path) && fs::is_regular_file(full_path)) {
            if (access(full_path.c_str(), X_OK) == 0) {
                return true;
            }
        }
    }
    return false;
}

int main(int argc, char **argv) {
    std::setlocale(LC_ALL, 0);
    fs::path searching_folder{"/"};
    json pass_file{};
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
        } else if (std::strcmp(argv[i], "--decrypt") == 0) {
            if (i + 1 < argc) {
                fs::path file{argv[++i]};
                std::error_code ec;
                if (!fs::exists(file, ec)) {
                    std::cerr << "Error: file '" << file
                              << "' does not exist.\n";
                    return EXIT_FAILURE;
                }
                if (!fs::is_regular_file(file, ec)) {
                    std::cerr << "Error: the '" << file << "' is not a file.\n";
                    return EXIT_FAILURE;
                }
                std::ifstream json_file(file.string());
                pass_file = json::parse(json_file);
            } else {
                std::cerr << "Error: --decrypt requires an argument.\n";
                usage_exit();
            }
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            usage_exit();
        }
    }

    const bool try_to_decrypt = (!pass_file.empty());

    if (try_to_decrypt) {
        uint8_t not_installed_count{0};
        for (const std::string &util :
             {"encfs", "gpg", "cryptsetup"}) {
            if (!is_command_in_path(util)) {
                std::cerr << util
                          << " is not installed, please install and try again"
                          << std::endl;
                not_installed_count++;
            }
        }
        if (not_installed_count > 0) {
            return EXIT_FAILURE;
        }
    }

    try {
        folder_traveler(searching_folder, pass_file, is_recursive, try_to_decrypt);
    } catch (const std::exception &e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
