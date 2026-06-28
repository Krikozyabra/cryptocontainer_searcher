#include "gpgdecrypt.h"
#include <gpgme.h>
#include <locale.h>
#include <iostream>
#include <fstream>
#include <cstring>

static bool g_gpgmeInitialized = false;

// Passphrase callback function executed by GPGME
static gpgme_error_t passphrase_cb(void *hook, const char *uid_hint, const char *passphrase_info,
                                    int prev_was_bad, int fd) {
    if (prev_was_bad) {
        // Prevents entering an infinite loop if the passphrase was wrong
        std::cerr << "[GPGME Callback] Error: The provided passphrase was incorrect." << std::endl;
        return gpg_error(GPG_ERR_CANCELED);
    }

    const char *passphrase = static_cast<const char*>(hook);
    if (!passphrase) {
        return gpg_error(GPG_ERR_CANCELED);
    }

    // According to the GPGME documentation, we must write the passphrase followed by a newline 
    // to the file descriptor (fd) provided. We use gpgme_io_writen for cross-platform compatibility.
    size_t len = std::strlen(passphrase);
    if (gpgme_io_writen(fd, passphrase, len) < 0) {
        return gpg_error_from_syserror();
    }
    if (gpgme_io_writen(fd, "\n", 1) < 0) {
        return gpg_error_from_syserror();
    }

    return 0; // Success
}

bool pgpdecrypt::initialize() {
    if (g_gpgmeInitialized) {
        return true;
    }

    // Initialize locale as GPGME relies on it for formatting
    std::setlocale(LC_ALL, "");
    
    // GPGME mandates checking the version first to initialize internal subsystems
    const char* version = gpgme_check_version(nullptr);
    if (!version) {
        std::cerr << "Failed to initialize GPGME: Library version check failed." << std::endl;
        return false;
    }

    gpgme_set_locale(nullptr, LC_CTYPE, std::setlocale(LC_CTYPE, nullptr));
#ifdef LC_MESSAGES
    gpgme_set_locale(nullptr, LC_MESSAGES, std::setlocale(LC_MESSAGES, nullptr));
#endif

    // Validate if the OpenPGP engine is present and functioning
    gpgme_error_t err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "OpenPGP engine is not available: " << gpgme_strerror(err) << std::endl;
        return false;
    }

    g_gpgmeInitialized = true;
    return true;
}

bool pgpdecrypt::decryptSymmetric(const std::string& inputPath, 
                                     const std::string& outputPath, 
                                     const std::string& passphrase) {
    if (!g_gpgmeInitialized) {
        std::cerr << "GpgDecryptor is not initialized. Call GpgDecryptor::initialize() first." << std::endl;
        return false;
    }

    gpgme_ctx_t ctx = nullptr;
    gpgme_data_t cipher = nullptr;
    gpgme_data_t plain = nullptr;
    bool success = false;

    // Create a new context
    gpgme_error_t err = gpgme_new(&ctx);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "Failed to create GPGME context: " << gpgme_strerror(err) << std::endl;
        return false;
    }

    // Set the protocol to OpenPGP
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

    // Force loopback pinentry so the passphrase callback is used instead of system prompts
    err = gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "Failed to set loopback pinentry mode: " << gpgme_strerror(err) << std::endl;
        goto cleanup;
    }

    // Register our callback, passing the passphrase pointer as the hook value
    gpgme_set_passphrase_cb(ctx, passphrase_cb, const_cast<char*>(passphrase.c_str()));

    // Load the encrypted file into memory
    err = gpgme_data_new_from_file(&cipher, inputPath.c_str(), 1);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "Failed to load input file: " << gpgme_strerror(err) << std::endl;
        goto cleanup;
    }

    // Allocate an empty data buffer to hold the decrypted plaintext
    err = gpgme_data_new(&plain);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "Failed to initialize plaintext buffer: " << gpgme_strerror(err) << std::endl;
        goto cleanup;
    }

    // Perform the actual decryption
    err = gpgme_op_decrypt(ctx, cipher, plain);
    if (err != GPG_ERR_NO_ERROR) {
        std::cerr << "Decryption failed: " << gpgme_strerror(err) << std::endl;
        goto cleanup;
    }

    // Rewind plain buffer to the beginning to start reading
    gpgme_data_seek(plain, 0, SEEK_SET);

    // Stream the data out to the output file
    {
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to open output file: " << outputPath << std::endl;
            goto cleanup;
        }

        char buffer[4096];
        ssize_t bytesRead = 0;
        while ((bytesRead = gpgme_data_read(plain, buffer, sizeof(buffer))) > 0) {
            outFile.write(buffer, bytesRead);
        }
    }

    success = true;

cleanup:
    if (cipher) gpgme_data_release(cipher);
    if (plain) gpgme_data_release(plain);
    if (ctx) gpgme_release(ctx);

    return success;
}
