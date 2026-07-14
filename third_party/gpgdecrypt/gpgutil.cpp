#include "gpgutil.hpp"
#include <gpgme.h> 
#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/interfaces/passphraseprovider.h>
#include <gpgme++/engineinfo.h>
#include <gpgme++/global.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <cstring> 
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <mutex>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

// Helper to reliably retrieve the directory path of the current executable
static std::string getExecutableDir() {
#ifdef _WIN32
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len > 0) {
        std::string p(path, len);
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) {
            return p.substr(0, pos);
        }
    }
#else
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        std::string p(path);
        size_t pos = p.find_last_of("/");
        if (pos != std::string::npos) {
            return p.substr(0, pos);
        }
    }
#endif
    return ".";
}

static bool fileExists(const std::string& path) {
    struct stat buffer;   
    return (stat(path.c_str(), &buffer) == 0); 
}

class MyPassphraseProvider : public GpgME::PassphraseProvider {
private:
    std::string m_passphrase;
public:
    MyPassphraseProvider(const std::string& passphrase) : m_passphrase(passphrase) {}

    char* getPassphrase(const char* useridHint, const char* description,
                        bool previousWasBad, bool& wasCanceled) override {
        std::cout<<"TEST!\n";
        wasCanceled = false;
        char* pw = static_cast<char*>(std::malloc(m_passphrase.length() + 1));
        if (pw) {
            std::strcpy(pw, m_passphrase.c_str());
        }
        return pw;
    }
};

static std::once_flag gpgme_init_flag;
static bool gpgme_init_success = false;

bool pgputil::initialize() {
    std::call_once(gpgme_init_flag, []() {
        GpgME::initializeLibrary(0);

        std::string exeDir = getExecutableDir();
        std::string portableGpgBin = exeDir + "/gpg_portable/bin/gpg";
#ifdef _WIN32
        portableGpgBin += ".exe";
#endif
        std::string portableGpgHome = exeDir + "/gpg_portable/home";

        if (fileExists(portableGpgBin)) {
            gpgme_error_t raw_err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, 
                                                          portableGpgBin.c_str(), 
                                                          portableGpgHome.c_str());
            if (raw_err != GPG_ERR_NO_ERROR) {
                std::cerr << "Warning: Failed to map portable GnuPG engine: " 
                          << gpgme_strerror(raw_err) << std::endl;
            }
        }

        GpgME::Error err = GpgME::checkEngine(GpgME::OpenPGP);
        if (err) {
            std::cerr << "GPGME Engine initialization failed: " << err.asString() << std::endl;
            gpgme_init_success = false;
        } else {
            gpgme_init_success = true;
        }
    });

    return gpgme_init_success;
}

bool pgputil::decryptSymmetric(const std::string& inputPath, 
                               const std::string& outputPath, 
                               const std::string& passphrase) {
    if (!initialize()) {
        std::cerr << "Error: GPGME is not initialized correctly." << std::endl;
        return false;
    }

    std::unique_ptr<GpgME::Context> ctx(GpgME::Context::createForProtocol(GpgME::OpenPGP));
    if (!ctx) {
        std::cerr << "Error: Failed to create GpgME context." << std::endl;
        return false;
    }

    ctx->setPinentryMode(GpgME::Context::PinentryLoopback);
    MyPassphraseProvider provider(passphrase);
    ctx->setPassphraseProvider(&provider);

    FILE* fp = fopen(inputPath.c_str(), "rb");
    if (!fp) {
        std::cerr << "Error loading ciphertext file: Could not open " << inputPath << std::endl;
        return false;
    }
    // Automatically close fp when exiting scope (even on failure)
    std::unique_ptr<FILE, decltype(&fclose)> filePtr(fp, &fclose);

    // Provide the stream to GPGME to avoid off_t ABI issues
    gpgme_data_t raw_cipher = nullptr;
    if (gpgme_data_new_from_stream(&raw_cipher, fp) != GPG_ERR_NO_ERROR) {
        std::cerr << "Error: Failed to initialize GPGME data stream." << std::endl;
        return false;
    }
    
    GpgME::Data cipherData(raw_cipher);
    GpgME::Data plainData;

    GpgME::DecryptionResult result = ctx->decrypt(cipherData, plainData);
    if (result.error()) {
        std::cerr << "Decryption failed: " << result.error().asString() << std::endl;
        return false;
    }

    plainData.seek(0, SEEK_SET); 
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error: Could not open output file: " << outputPath << std::endl;
        return false;
    }
    
    std::vector<char> buffer(4096);
    ssize_t bytesRead;
    while ((bytesRead = plainData.read(buffer.data(), buffer.size())) > 0) {
        outFile.write(buffer.data(), bytesRead);
    }

    return true;
}

pgputil::PgpContainerType pgputil::analyzePgpEncryption(const std::string& filePath) {
    if (!initialize()) {
        return PgpContainerType::UnknownError;
    }

    std::unique_ptr<GpgME::Context> ctx(GpgME::Context::createForProtocol(GpgME::OpenPGP));
    if (!ctx) {
        return PgpContainerType::UnknownError;
    }

    // Measure the actual file size
    std::ifstream checkIn(filePath, std::ios::binary | std::ios::ate);
    if (!checkIn.good()) {
        return PgpContainerType::NotPgpOrInvalid;
    }
    std::streamsize fileSize = checkIn.tellg();
    checkIn.close();

    if (fileSize <= 0) {
        return PgpContainerType::NotPgpOrInvalid;
    }

    GpgME::Data cipherData(filePath.c_str(), (off_t)0, (size_t)fileSize);
    GpgME::Data dummyPlainData;
    
    // FIX 2: Ensure pinentry loopback is enforced here as well with an empty provider.
    // If we guess wrongly, this prevents a rogue GUI passphrase popup from blocking the CLI tool.
    MyPassphraseProvider provider("");
    ctx->setPinentryMode(GpgME::Context::PinentryLoopback);
    ctx->setPassphraseProvider(&provider);

    GpgME::DecryptionResult result = ctx->decrypt(cipherData, dummyPlainData);

    GpgME::Error decError = result.error();
    
    if (decError.code() == GPG_ERR_NO_DATA || decError.code() == GPG_ERR_BAD_DATA) {
        return PgpContainerType::NotPgpOrInvalid;
    }

    if (decError.code() == GPG_ERR_NO_SECKEY || !result.recipients().empty()) {
        return PgpContainerType::Asymmetric;
    }

    if (result.recipients().empty()) {
        return PgpContainerType::Symmetric;
    }

    return PgpContainerType::UnknownError;
}