#include "gpgutil.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/global.h>
#include <gpgme.h>
#endif

static std::string normalizePath(const std::string& path) {
    std::error_code ec;
    std::filesystem::path p = std::filesystem::absolute(path, ec);
    if (ec) return path;
    return p.generic_string(); 
}

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
    std::error_code ec;
    return std::filesystem::exists(path, ec) && std::filesystem::is_regular_file(path, ec);
}

static std::string getGpgBinary() {
    std::string exeDir = getExecutableDir();
    std::string portableGpgBin = exeDir + "/gpg_portable/bin/gpg";
#ifdef _WIN32
    portableGpgBin += ".exe";
#endif
    return normalizePath(portableGpgBin);
}

static std::string getGpgHome() {
    std::string exeDir = getExecutableDir();
    return normalizePath(exeDir + "/gpg_portable/home");
}

#ifdef _WIN32
static std::string execCommandWithStdin(const std::string& rawCmd, const std::string& inputData, int& exitCode) {
    std::string result;
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hStdOutRead, hStdOutWrite;
    HANDLE hStdInRead, hStdInWrite;
    
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return "";
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return "";
    }
    SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    si.hStdInput = hStdInRead;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Prevents console flash on Windows

    PROCESS_INFORMATION pi = {0};
    std::vector<char> cmdBuf(rawCmd.begin(), rawCmd.end());
    cmdBuf.push_back('\0');

    if (!CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdOutRead);
        CloseHandle(hStdInRead);
        CloseHandle(hStdInWrite);
        exitCode = -1;
        return "";
    }

    // Close our handles to the inherited ends
    CloseHandle(hStdOutWrite);
    CloseHandle(hStdInRead);

    // Write input data (passphrase) to stdin safely without disk I/O
    if (!inputData.empty()) {
        DWORD bytesWritten;
        WriteFile(hStdInWrite, inputData.c_str(), inputData.length(), &bytesWritten, nullptr);
    }
    CloseHandle(hStdInWrite); // Send EOF to stdin

    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD dExitCode = 0;
    GetExitCodeProcess(pi.hProcess, &dExitCode);
    exitCode = static_cast<int>(dExitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);

    return result;
}
#endif

bool pgputil::initialize() {
    std::string bin = getGpgBinary();
    
#ifdef _WIN32
    if (!fileExists(bin)) {
        std::cerr << "Warning: Portable GnuPG binary not found at " << bin << std::endl;
        return false;
    }
    return true;
#else
    GpgME::initializeLibrary(0);
    gpgme_check_version(nullptr);
    
    std::string home = getGpgHome();
    
    gpgme_error_t err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, bin.c_str(), home.c_str());
    if (err) {
        std::cerr << "Warning: Failed to set GPGME engine info." << std::endl;
        return false;
    }
    return true;
#endif
}

bool pgputil::decryptSymmetric(const std::string& inputPath, 
                               const std::string& outputPath, 
                               const std::string& passphrase) {
    if (!initialize()) {
        std::cerr << "Error: GPG is not initialized correctly." << std::endl;
        return false;
    }

    std::string cleanInput = normalizePath(inputPath);
    std::string cleanOutput = normalizePath(outputPath);
    
    if (!fileExists(cleanInput)) {
        std::cerr << "Error: File does not exist: " << cleanInput << std::endl;
        return false;
    }

#ifdef _WIN32
    std::string gpgBin = getGpgBinary();
    std::string gpgHome = getGpgHome();
    std::string rawCmd = "\"" + gpgBin + "\" --homedir \"" + gpgHome + "\" --batch --yes --no-tty --pinentry-mode loopback --passphrase-fd 0 --decrypt --output \"" + cleanOutput + "\" \"" + cleanInput + "\"";

    int exitCode = 0;
    execCommandWithStdin(rawCmd, passphrase, exitCode);

    return (exitCode == 0 && fileExists(cleanOutput));
#else
    auto ctx = GpgME::Context::createForProtocol(GpgME::OpenPGP);
    if (!ctx) return false;

    class SymPassphraseProvider : public GpgME::PassphraseProvider {
        std::string pass;
    public:
        SymPassphraseProvider(const std::string& p) : pass(p) {}
        const char* getPassphrase(const char*, const char*, bool, bool&) override {
            return pass.c_str();
        }
    };

    SymPassphraseProvider provider(passphrase);
    ctx->setPassphraseProvider(&provider);
    ctx->setPinentryMode(GpgME::Context::PinentryLoopback);

    FILE* inFile = fopen(cleanInput.c_str(), "rb");
    if (!inFile) return false;
    
    FILE* outFile = fopen(cleanOutput.c_str(), "wb");
    if (!outFile) {
        fclose(inFile);
        return false;
    }

    gpgme_data_t raw_in, raw_out;
    gpgme_data_new_from_stream(&raw_in, inFile);
    gpgme_data_new_from_stream(&raw_out, outFile);

    GpgME::Data inData(raw_in);
    GpgME::Data outData(raw_out);

    GpgME::DecryptionResult res = ctx->decrypt(inData, outData);

    fclose(inFile);
    fclose(outFile);

    if (res.error()) {
        std::cerr << "GPGME Decryption error: " << res.error().asString() << std::endl;
        std::filesystem::remove(cleanOutput);
        return false;
    }

    return fileExists(cleanOutput);
#endif
}