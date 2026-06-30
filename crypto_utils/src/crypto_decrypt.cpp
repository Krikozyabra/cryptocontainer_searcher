#include "crypto_utils/crypto_decrypt.h"
#include "encfs_decrypt.h"
#include "gpgdecrypt.h"
#include "tcdecrypt.hpp"
#include "vcdecrypt.hpp"
#ifdef SUPPORT_LUKS
#include "crypto_utils/luksdecrypt.h"
#endif
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

// On MSVC the POSIX pipe functions are spelled with a leading underscore.
#if defined(_MSC_VER)
#define popen _popen
#define pclose _pclose
#endif

namespace {
// Helper: trim trailing whitespace from system command output
void trim_trailing_whitespace(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            s.end());
}

// Helper: Wrap path in quotes to handle spaces in folder/file names safely
std::string quote(const fs::path &path) { return "\"" + path.string() + "\""; }

// Helper: Deduplicates the pipe open/write password pattern
int execute_with_password(const std::string &command,
                          const std::string &password) {
    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        return -1;
    }
    std::fputs(password.c_str(), pipe);
    std::fputs("\n", pipe);
    return pclose(pipe);
}

// Helper: Safely creates directory, reporting failure via return status
bool safe_create_directory(const fs::path &dir) {
    std::error_code ec;
    fs::create_directory(dir, ec);
    if (ec) {
        std::cerr << "Error creating directory " << dir << ": " << ec.message()
                  << '\n';
        return false;
    }
    return true;
}
} // namespace

namespace crypto_decrypt {

int encfs(const fs::path &file, const std::string &password,
          const fs::path &out_decrypted) {
    const fs::path enc = file.parent_path();
    const std::string out =
        (out_decrypted / (enc.filename().string() + "_decrypted"));
    encfs_decrypt::DecryptOptions o;
    o.rootDir = enc;
    o.destDir = out;
    o.password = password;
    auto result = encfs_decrypt::decryptFolder(o);
    if (!result.ok) {
        return ERR_DECRYPT;
    }

    std::cout << "The decrypted encfs folder was decrypted at:\n"
              << out << '\n';
    return SUCCESS;
}

int luks(const fs::path &file, const std::string &password,
         const fs::path &out_decrypted) {
    const std::string file_stem = file.stem().string();
    const fs::path out_file{out_decrypted / fs::path(file_stem + "_decrypted")};
#ifdef SUPPORT_LUKS
    int res = luksdecrypt::decrypt_to_file(file, password, out_file);

    if (res != 0)
        return ERR_DECRYPT;

    std::cout << "The decrypted luks container was decrypted at:\n"
              << out_file << "\n";

    return SUCCESS;
#else
    std::cerr << "LUKS decryption is not supported on this operating system.\n";
    return -1;
#endif
}

int pgp(const fs::path &file, const std::string &password,
        const fs::path &out_decrypted) {
    const std::string stem_str = file.stem().string();
    const fs::path decrypted_file{out_decrypted /
                                  fs::path(stem_str + "_decrypted")};
    if (!pgpdecrypt::initialize()) {
        return ERR_PIPE_OPEN;
    }
    if (!pgpdecrypt::decryptSymmetric(file.string(), decrypted_file.string(),
                                      password))
        return ERR_DECRYPT;

    std::cout << "File was decrypted in " << decrypted_file << "\n";
    return SUCCESS;
}

int truecrypt(const fs::path &file, const std::string &password,
              const fs::path &out_decrypted) {
    const std::string stem_str = file.stem().string();
    const fs::path decrypted_file(out_decrypted /
                                  fs::path(stem_str + "_decrypted"));
    tcdecrypt::OpenOptions opt;
    opt.password = password;
    opt.path = file.string();
    uint64_t some_number{0};
    try {
        some_number = tcdecrypt::decryptToFile(opt, decrypted_file.string());
    } catch (...) {
        return ERR_DECRYPT;
    }
    std::cout << "File was decrypted in " << decrypted_file << "\n";

    return SUCCESS;
}

int veracrypt(const fs::path &file, const std::string &password,
              const fs::path &out_decrypted) {
    const std::string stem_str = file.stem().string();
    const fs::path decrypted_file(out_decrypted /
                                  fs::path(stem_str + "_decrypted"));
    vcdecrypt::OpenOptions opt;
    opt.password = password;
    opt.path = file.string();
    uint64_t some_number{0};
    try {
        vcdecrypt::decryptToFile(opt, decrypted_file.string());
    } catch (...) {
        return ERR_DECRYPT;
    }
    std::cout << "File was decrypted in " << decrypted_file << "\n";

    return SUCCESS;
}
} // namespace crypto_decrypt
