#include "gpgutil.hpp"
#include <gpgme.h>
#include <locale.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <filesystem>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#endif

static bool g_gpgmeInitialized = false;

static std::filesystem::path get_executable_directory() {
#ifdef _WIN32
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::filesystem::path(path).parent_path();
#else
    return std::filesystem::read_symlink("/proc/self/exe").parent_path();
#endif
}

static gpgme_error_t passphrase_cb(void *hook, const char *uid_hint, const char *passphrase_info,
                                    int prev_was_bad, int fd) {
    if (prev_was_bad) {
        std::cerr << "[GPGME Callback] Error: The provided passphrase was incorrect." << std::endl;
        return gpg_error(GPG_ERR_CANCELED);
    }
    const char *passphrase = static_cast<const char*>(hook);
    if (!passphrase) return gpg_error(GPG_ERR_CANCELED);

    size_t len = std::strlen(passphrase);
    if (gpgme_io_writen(fd, passphrase, len) < 0) return gpg_error_from_syserror();
    if (gpgme_io_writen(fd, "\n", 1) < 0) return gpg_error_from_syserror();
    return 0;
}

bool pgputil::initialize() {
    if (g_gpgmeInitialized) return true;

    std::setlocale(LC_ALL, "");
    if (!gpgme_check_version(nullptr)) return false;

    std::filesystem::path exeDir = get_executable_directory();
    std::filesystem::path portableGpgBin = exeDir / "gpg_portable" / "bin" / "gpg.exe";
    std::filesystem::path portableHomeDir = exeDir / "gpg_portable" / "home";

#ifndef _WIN32
    portableGpgBin = exeDir / "gpg_portable" / "bin" / "gpg";
#endif

    if (std::filesystem::exists(portableGpgBin)) {
        gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, 
                              portableGpgBin.string().c_str(), 
                              portableHomeDir.string().c_str());
    } else {
#ifdef _WIN32
        std::string gpgPath = "C:\\Program Files\\GnuPG\\bin\\gpg.exe";
        if (!std::filesystem::exists(gpgPath)) {
            gpgPath = "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe";
        }

        if (std::filesystem::exists(gpgPath)) {
            gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, gpgPath.c_str(), nullptr);
        } else {
            std::cerr << "[WARNING] Portable GnuPG and default Gpg4win path not found. Relying on system PATH." << std::endl;
        }
#endif
    }

    gpgme_set_locale(nullptr, LC_CTYPE, std::setlocale(LC_CTYPE, nullptr));
#ifdef LC_MESSAGES
    gpgme_set_locale(nullptr, LC_MESSAGES, std::setlocale(LC_MESSAGES, nullptr));
#endif

    if (gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) return false;

    g_gpgmeInitialized = true;
    return true;
}

bool pgputil::decryptSymmetric(const std::string& inputPath, 
                               const std::string& outputPath, 
                               const std::string& passphrase) {
    if (!g_gpgmeInitialized) return false;

    gpgme_ctx_t ctx = nullptr;
    gpgme_data_t cipher = nullptr;
    gpgme_data_t plain = nullptr;
    bool success = false;

    if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) return false;
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    
    if (gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK) != GPG_ERR_NO_ERROR) goto cleanup;
    gpgme_set_passphrase_cb(ctx, passphrase_cb, const_cast<char*>(passphrase.c_str()));

    {
        std::filesystem::path p(inputPath);
        
        auto u8_str = p.u8string();
        std::string utf8_path(u8_str.begin(), u8_str.end());

        if (!std::filesystem::exists(p)) {
            std::cerr << "[GPGME] Error: Input file does not exist: " << utf8_path << std::endl;
            goto cleanup;
        }

        if (gpgme_data_new_from_file(&cipher, utf8_path.c_str(), 1) != GPG_ERR_NO_ERROR) {
            goto cleanup;
        }
        
        if (gpgme_data_new(&plain) != GPG_ERR_NO_ERROR) goto cleanup;
        
        gpgme_error_t decryptErr = gpgme_op_decrypt(ctx, cipher, plain);
        if (decryptErr != GPG_ERR_NO_ERROR) {
            std::cerr << "[GPGME] Decryption failed: " << gpgme_strerror(decryptErr) << std::endl;
            goto cleanup;
        }

        gpgme_data_seek(plain, 0, SEEK_SET);
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) goto cleanup;

        char buffer[4096];
        gpgme_ssize_t bytesRead = 0;
        while ((bytesRead = gpgme_data_read(plain, buffer, sizeof(buffer))) > 0) {
            outFile.write(buffer, bytesRead);
        }
        success = true;
    }

cleanup:
    if (cipher) gpgme_data_release(cipher);
    if (plain) gpgme_data_release(plain);
    if (ctx) gpgme_release(ctx);
    return success;
}