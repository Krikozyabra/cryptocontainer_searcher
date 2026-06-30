#include "crypto_utils/crypto_decrypt.h"
#include "encfs_decrypt.h"
#include "gpgdecrypt.h"
#include "tcdecrypt.hpp"
#include "vcdecrypt.hpp"
#ifdef SUPPORT_LUKS
#include "crypto_utils/luksdecrypt.h"
#endif
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

// On MSVC the POSIX pipe functions are spelled with a leading underscore.
#if defined(_MSC_VER)
#define popen _popen
#define pclose _pclose
#endif

namespace crypto_decrypt {

int encfs(const fs::path &file, const std::string &password,
          const fs::path &out_decrypted) {
    const fs::path enc = file.parent_path();
    const fs::path out =
        (out_decrypted / (enc.filename().string() + "_decrypted"));
    encfs_decrypt::DecryptOptions o;
    o.rootDir = enc.string();
    o.destDir = out.string();
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
