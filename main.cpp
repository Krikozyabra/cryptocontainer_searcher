#include "crypto_utils/crypto_decrypt.h"
#include "crypto_utils/crypto_search.h"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#ifdef LOG_ENABLED
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#endif
#include <sstream>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

struct AppConfig {
    fs::path searching_folder{"/"};
    fs::path decrypt_file{};
    fs::path out_decrypted{};
    bool is_recursive{false};
    bool show_help{false};
    bool show_version{false};
};

void print_usage() {
    std::cout
        << "Crypto search works only with TrueCrypt/VeraCrypt, EncFS, "
           "LUKS, PGP containers.\n"
           "Usage:\n"
           "\tcrypto_search --folder [folder] [--recursive]\n\n"
           "You can use the following commands:\n"
           "\t--help - to see this message\n"
           "\t--version - to see version of the program\n"
           "\t--folder - to set folder to search in (default='/')\n"
           "\t--recursive - to check nested folders\n"
           "\t--decrypt [file] - to try decryption every found container "
           "with passwords in file\n"
           "\t--out-decrypted - set the folder for decrypted containers\n";
}

void print_version() { std::cout << "0.1.0\n"; }

int check_for_enc_container(const fs::directory_entry &path_to_object,
                            const bool try_to_decrypt, const json &pass_file,
                            const fs::path &out_decrypted) {
    std::error_code ec;
    int return_code{crypto_decrypt::SUCCESS};

    if (fs::is_regular_file(path_to_object, ec)) {
#ifdef LOG_ENABLED
        spdlog::info("File analyzing started for " +
                     path_to_object.path().string());
#endif
        if (crypto_search::encfs_file(path_to_object.path())) {
            std::cout << path_to_object.path().parent_path() << std::endl;
            std::cout << "This folder is encrypted with EncFS" << std::endl;
#ifdef LOG_ENABLED
            spdlog::info("Folder " +
                         path_to_object.path().parent_path().string() +
                         " was determined as EncFS");
#endif
            if (try_to_decrypt) {
#ifdef LOG_ENABLED
                spdlog::info("Decryption for this folder was started");
#endif
                for (const std::string &passphrase : pass_file["encfs"]) {
#ifdef LOG_ENABLED
                    spdlog::info("Trying to decrypt with passphrase " +
                                 passphrase);
#endif
                    return_code = crypto_decrypt::encfs(
                        path_to_object, passphrase, out_decrypted);
#ifdef LOG_ENABLED
                    spdlog::info("Return code for decryption is " +
                                 std::to_string(return_code));
#endif
                    if (return_code == crypto_decrypt::SUCCESS)
                        break;
                }
            }
            return return_code;
        }
        if (crypto_search::luks_file(path_to_object.path())) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with LUKS"
                      << std::endl;
#ifdef LOG_ENABLED
            spdlog::info("This file " + path_to_object.path().string() +
                         " was determined as LUKS");
#endif
            if (try_to_decrypt) {
#ifdef LOG_ENABLED
                spdlog::info("Decryption for this file was started");
#endif
                for (const std::string &passphrase : pass_file["luks"]) {
#ifdef LOG_ENABLED
                    spdlog::info("Trying to decrypt with passphrase " +
                                 passphrase);
#endif
                    return_code = crypto_decrypt::luks(
                        path_to_object, passphrase, out_decrypted);
#ifdef LOG_ENABLED
                    spdlog::info("Return code for decryption is " +
                                 std::to_string(return_code));
#endif
                    if (return_code == crypto_decrypt::SUCCESS)
                        break;
                }
            }
            return return_code;
        }
        if (crypto_search::pgp_file(path_to_object.path())) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with PGP"
                      << std::endl;
#ifdef LOG_ENABLED
            spdlog::info("This file " + path_to_object.path().string() +
                         " was determined as PGP");
#endif
            if (try_to_decrypt) {
#ifdef LOG_ENABLED
                spdlog::info("Decryption for this file was started");
#endif
                for (const std::string &passphrase : pass_file["pgp"]) {
#ifdef LOG_ENABLED
                    spdlog::info("Trying to decrypt with passphrase " +
                                 passphrase);
#endif
                    return_code = crypto_decrypt::pgp(
                        path_to_object, passphrase, out_decrypted);
#ifdef LOG_ENABLED
                    spdlog::info("Return code for decryption is " +
                                 std::to_string(return_code));
#endif
                    if (return_code == crypto_decrypt::SUCCESS)
                        break;
                }
            }
            return return_code;
        }
        if (crypto_search::veracrypt_truecrypt_file(path_to_object.path())) {
            std::cout << path_to_object.path() << std::endl;
            std::cout << "This is the container and encrypted with "
                         "TrueCrypt\\VeraCrypt"
                      << std::endl;
#ifdef LOG_ENABLED
            spdlog::info("This file " + path_to_object.path().string() +
                         " was determined as VeraCrypt or TrueCrypt");
#endif
            if (try_to_decrypt) {
#ifdef LOG_ENABLED
                spdlog::info("Decryption for this file was started");
#endif
                for (const std::string &passphrase : pass_file["truecrypt"]) {
#ifdef LOG_ENABLED
                    spdlog::info(
                        "Trying to decrypt like TrueCrypt with passphrase " +
                        passphrase);
#endif
                    return_code = crypto_decrypt::truecrypt(
                        path_to_object, passphrase, out_decrypted);
#ifdef LOG_ENABLED
                    spdlog::info("Return code for decryption is " +
                                 std::to_string(return_code));
#endif
                    if (return_code == crypto_decrypt::SUCCESS)
                        break;
                }
                if (return_code != crypto_decrypt::SUCCESS) {
                    for (const std::string &passphrase :
                         pass_file["veracrypt"]) {
#ifdef LOG_ENABLED
                        spdlog::info("Trying to decrypt like VeraCrypt with "
                                     "passphrase " +
                                     passphrase);
#endif
                        return_code = crypto_decrypt::veracrypt(
                            path_to_object, passphrase, out_decrypted);
#ifdef LOG_ENABLED
                        spdlog::info("Return code for decryption is " +
                                     std::to_string(return_code));
#endif
                        if (return_code == crypto_decrypt::SUCCESS)
                            break;
                    }
                }
            }
            return return_code;
        }
    }

    if (ec == std::errc::permission_denied) {
        std::cout << path_to_object.path() << std::endl;
        std::cout << "No access to this file. Run in 'sudo' mode" << std::endl;
    }

#ifdef LOG_ENABLED
    spdlog::warn("This file " + path_to_object.path().string() +
                 " was determined as nothing");
#endif

    return return_code;
}

void folder_traveler(const fs::path &searching_folder, const json &pass_file,
                     const bool is_recursive, const bool try_to_decrypt,
                     const fs::path &out_decrypted) {
#ifdef LOG_ENABLED
    spdlog::info("Folder traveling started");
#endif
    std::error_code ec;
    auto dir_iter = fs::directory_iterator(searching_folder, ec);
    if (ec) {
        std::cerr << "Warning: Cannot access folder " << searching_folder
                  << " (" << ec.message() << ")\n";
#ifdef LOG_ENABLED
        spdlog::error("Cannot access the searching folder " +
                      searching_folder.string());
#endif
        return;
    }

    for (const auto &entry : dir_iter) {
        std::error_code entry_ec;
        bool is_dir = entry.is_directory(entry_ec);
        if (entry_ec) {
#ifdef LOG_ENABLED
            spdlog::warn("File " + entry.path().string() +
                         " cannot be accessed");
#endif
            continue;
        }
#ifdef LOG_ENABLED
        spdlog::info("Going into detection logic with file: " +
                     entry.path().string());
#endif
        // Run detection logic
        int return_result = check_for_enc_container(entry, try_to_decrypt,
                                                    pass_file, out_decrypted);
        switch (return_result) {
        case crypto_decrypt::ERR_DECRYPT:
            std::cerr << "No password found for this container" << std::endl;
#ifdef LOG_ENABLED
            spdlog::warn("For entry " + entry.path().string() +
                         " password not found");
#endif
            break;
        }
        // Recurse
        if (is_recursive && is_dir) {
#ifdef LOG_ENABLED
            spdlog::info("Go recursive to " + entry.path().string());
#endif
            folder_traveler(entry.path(), pass_file, is_recursive,
                            try_to_decrypt, out_decrypted);
        }
    }
}

bool is_command_in_path(const std::string &command) {
    const char *path_env = std::getenv("PATH");
    if (!path_env) {
        return false;
    }

    std::stringstream ss(path_env);
    std::string directory{};

#ifdef _WIN32
    const char delimiter{';'};
#else
    const char delimiter{':'};
#endif

    while (std::getline(ss, directory, delimiter)) {
        fs::path full_path = fs::path(directory) / command;
        std::error_code ec;

        if (fs::exists(full_path, ec) && fs::is_regular_file(full_path, ec)) {
            auto perms = fs::status(full_path, ec).permissions();
            if (!ec) {
                // Check if executable by owner, group, or others
                bool is_exec =
                    (perms & (fs::perms::owner_exec | fs::perms::group_exec |
                              fs::perms::others_exec)) != fs::perms::none;
                if (is_exec) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool parse_arguments(int argc, char **argv, AppConfig &config) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0) {
            config.show_help = true;
        } else if (std::strcmp(argv[i], "--version") == 0) {
            config.show_version = true;
        } else if (std::strcmp(argv[i], "--folder") == 0) {
            if (i + 1 < argc) {
                config.searching_folder = argv[++i];
            } else {
                std::cerr << "Error: --folder requires an argument\n";
                return false;
            }
        } else if (std::strcmp(argv[i], "--recursive") == 0) {
            config.is_recursive = true;
        } else if (std::strcmp(argv[i], "--decrypt") == 0) {
            if (i + 1 < argc) {
                config.decrypt_file = argv[++i];
            } else {
                std::cerr << "Error: --decrypt requires an argument\n";
                return false;
            }
        } else if (std::strcmp(argv[i], "--out-decrypted") == 0) {
            if (i + 1 < argc) {
                config.out_decrypted = argv[++i];
            } else {
                std::cerr << "Error: --out-decrypted requires an argument\n";
                return false;
            }
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            return false;
        }
    }
    return true;
}

#ifdef LOG_ENABLED
void setup_file_logging() {
    try {
        auto my_logger =
            spdlog::basic_logger_mt("file_logger", "logs/last_log.txt", true);

        spdlog::set_default_logger(my_logger);

        spdlog::set_level(spdlog::level::debug);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        spdlog::flush_on(spdlog::level::info);

    } catch (const spdlog::spdlog_ex &ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
}
#endif

int main(int argc, char **argv) {
    std::setlocale(LC_ALL, "");
    AppConfig config;

#ifdef LOG_ENABLED
    setup_file_logging();
    spdlog::info("Some info new logger");
    spdlog::error("error in logs");
#endif
    if (argc < 2) {
        print_usage();
#ifdef LOG_ENABLED
        spdlog::error("Count of arguments less than 2");
#endif
        return EXIT_SUCCESS;
    }

    if (!parse_arguments(argc, argv, config)) {
        print_usage();
#ifdef LOG_ENABLED
        spdlog::error("Arguement parse error");
#endif
        return EXIT_FAILURE;
    }

    if (config.show_help) {
        print_usage();
#ifdef LOG_ENABLED
        spdlog::info("Help was called");
#endif
        return EXIT_SUCCESS;
    }

    if (config.show_version) {
        print_version();
#ifdef LOG_ENABLED
        spdlog::info("Version was called");
#endif
        return EXIT_SUCCESS;
    }

    // Validate searching folder
    std::error_code ec;
    if (!fs::exists(config.searching_folder, ec)) {
        std::cerr << "Error: Folder '" << config.searching_folder
                  << "' does not exist.\n";
#ifdef LOG_ENABLED
        spdlog::error("Proceed foler " + config.searching_folder.string() +
                      " does not exist");
#endif
        return EXIT_FAILURE;
    }

    if (!config.out_decrypted.empty() &&
        !fs::is_directory(config.out_decrypted, ec)) {
        std::cerr << "Errot: the argument for --out-decrypted '"
                  << config.out_decrypted << "' is not a directory.\n";
#ifdef LOG_ENABLED
        spdlog::error("The folder " + config.out_decrypted.string() +
                      " for decrypted containers is not a directory");
#endif
        return EXIT_FAILURE;
    }

    json pass_file{};
    if (!config.decrypt_file.empty()) {
        if (!fs::exists(config.decrypt_file, ec)) {
            std::cerr << "Error: file '" << config.decrypt_file
                      << "' does not exist.\n";
#ifdef LOG_ENABLED
            spdlog::error("File with passwords " +
                          config.decrypt_file.string() + " does not exist");
#endif
            return EXIT_FAILURE;
        }
        if (!fs::is_regular_file(config.decrypt_file, ec)) {
            std::cerr << "Error: '" << config.decrypt_file
                      << "' is not a file.\n";
#ifdef LOG_ENABLED
            spdlog::error("Proceed object for a password file " +
                          config.decrypt_file.string() + " is not a file");
#endif
            return EXIT_FAILURE;
        }

        std::ifstream json_file(config.decrypt_file.string());
        if (!json_file.is_open()) {
            std::cerr << "Error: Could not open file '" << config.decrypt_file
                      << "'\n";
#ifdef LOG_ENABLED
            spdlog::error("File with passwords " +
                          config.decrypt_file.string() + " can not be opened");
#endif
            return EXIT_FAILURE;
        }

        try {
            pass_file = json::parse(json_file);
        } catch (const json::parse_error &e) {
            std::cerr << "Fatal Error parsing JSON: " << e.what() << "\n";
#ifdef LOG_ENABLED
            spdlog::error("File with passwords " +
                          config.decrypt_file.string() +
                          " generated the error while parsing: " + e.what());
#endif
            return EXIT_FAILURE;
        }
    }

    const bool try_to_decrypt = !pass_file.empty();

    try {
        folder_traveler(config.searching_folder, pass_file, config.is_recursive,
                        try_to_decrypt, config.out_decrypted);
    } catch (const std::exception &e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
#ifdef LOG_ENABLED
        spdlog::error("Fatal error for the program: " + std::string(e.what()));
#endif
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
