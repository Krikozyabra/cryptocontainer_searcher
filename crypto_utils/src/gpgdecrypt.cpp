#include "crypto_utils/gpgdecrypt.hpp"
#include <string>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <spdlog/spdlog.h>

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
#include <gpgme++/interfaces/passphraseprovider.h>
#include <gpgme++/global.h>
#endif

static std::string normalizePath(const std::string& path) {
    std::error_code ec;
    std::filesystem::path p = std::filesystem::absolute(path, ec);
    if (ec) return path;
    return p.generic_string(); 
}

static bool fileExists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && std::filesystem::is_regular_file(path, ec);
}

#ifdef _WIN32
static std::string getExecutableDir() {
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len > 0) {
        std::string p(path, len);
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) {
            return p.substr(0, pos);
        }
    }
    return ".";
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
        #ifdef LOG_ENABLED
           spdlog::error("Error: Creating pipe fault.");
        #endif
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
        #ifdef LOG_ENABLED
           spdlog::error("Error: Due creating proccess with calling portable GnuPG.");
        #endif
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
#ifdef _WIN32
    std::string bin = getGpgBinary();
    if (!fileExists(bin)) {
        #ifdef LOG_ENABLED
           spdlog::error("Warning: Portable GnuPG binary not found at " + bin);
        #endif
        return false;
    }
    return true;
#else
    GpgME::initializeLibrary();
    
    return true;
#endif
}


bool pgputil::decryptSymmetric(const std::string& inputPath, 
                               const std::string& outputPath, 
                               const std::string& passphrase) {
    if (!initialize()) {
        #ifdef LOG_ENABLED
           spdlog::error("Error: GPG is not initialized correctly.");
        #endif
        return false;
    }

    std::string cleanInput = normalizePath(inputPath);
    std::string cleanOutput = normalizePath(outputPath);
    
    if (!fileExists(cleanInput)) {
        #ifdef LOG_ENABLED
           spdlog::error("Error: File does not exist: " + cleanInput);
        #endif
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
        char* getPassphrase(const char*, const char*, bool, bool&) override {
            return strdup(pass.c_str());
        }
    };

    SymPassphraseProvider provider(passphrase);
    ctx->setPassphraseProvider(&provider);
    ctx->setPinentryMode(GpgME::Context::PinentryLoopback);
    
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(cleanInput, ec);
    if (ec) {
        #ifdef LOG_ENABLED
           spdlog::error("Error: Could not determine file size: " + ec.message());
        #endif
        return false;
    }

    // 2. Pass the file size as the length parameter
    GpgME::Data inData(cleanInput.c_str(), static_cast<off_t>(0), static_cast<size_t>(fileSize));

    GpgME::Data outData;

    GpgME::DecryptionResult res = ctx->decrypt(inData, outData);

    if (res.error()) {
        #ifdef LOG_ENABLED
           spdlog::error("GPGME Decryption error: " + res.error().asStdString());
        #endif
        return false;
    }

    std::ofstream outFile(cleanOutput, std::ios::binary);
    if (!outFile) {
        #ifdef LOG_ENABLED
           spdlog::error("Error: Could not open output file for writing: " + cleanOutput);
        #endif
        return false;
    }

    // Rewind outData to the beginning
    outData.seek(0, SEEK_SET);

    char buffer[4096];
    ssize_t bytesRead;
    while ((bytesRead = outData.read(buffer, sizeof(buffer))) > 0) {
        outFile.write(buffer, bytesRead);
    }

    outFile.close();
    return fileExists(cleanOutput);
#endif
}
