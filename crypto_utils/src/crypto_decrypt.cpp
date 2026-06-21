#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <iostream>

#include "crypto_utils/crypto_decrypt.h"

namespace fs = std::filesystem;

namespace {
// Helper: trim trailing whitespace from system command output
void trim_trailing_whitespace(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            s.end());
}

// Helper: Wrap path in quotes to handle spaces in folder/file names safely
std::string quote(const fs::path &path) {
    return "\"" + path.string() + "\"";
}

// Helper: Deduplicates the pipe open/write password pattern
int execute_with_password(const std::string &command, const std::string &password) {
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
        std::cerr << "Error creating directory " << dir << ": " << ec.message() << '\n';
        return false;
    }
    return true;
}
} // namespace

namespace crypto_decrypt {

int encfs(const fs::path &file, const std::string &password) {
    // 1) Get the directory
    const fs::path enc_directory = file.parent_path();
    
    // 2) Create mount directory using path concatenation operator
    fs::path mount_directory = enc_directory;
    mount_directory += "_mount";
    
    if (!safe_create_directory(mount_directory)) {
        return ERR_MOUNT;
    }

    // 3) Mount
    const std::string command = "encfs --stdinpass " + quote(enc_directory) + " " + quote(mount_directory);
    int result = execute_with_password(command, password);

    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }

    // 4) Print the mount link
    std::cout << "\nThe decrypted encfs folder was mounted at:\n" << mount_directory << '\n';
    return SUCCESS;
}

int luks(const fs::path &file, const std::string &password) {
    // 1) Create mount point
    const fs::path mount_directory = fs::path("/mnt") / (file.stem().string() + "_mount");
    if (!safe_create_directory(mount_directory)) {
        return ERR_MOUNT;
    }

    // 2) Decrypt and create device
    const std::string device_name = file.stem().string() + "_device";
    const std::string command = "cryptsetup open " + quote(file) + " " + device_name + " -";

    int result = execute_with_password(command, password);
    if (result == -1) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }
    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }

    // 3) Mount device to mount point
    const std::string mount_command = "mount /dev/mapper/" + device_name + " " + quote(mount_directory);
    result = std::system(mount_command.c_str());

    // 4) Print mount point
    if (result == 0) {
        std::cout << "The decrypted LUKS container mounted at:\n" << mount_directory << '\n';
        return SUCCESS;
    } else {
        fs::remove(mount_directory);
        const std::string close_command = "cryptsetup close " + device_name;
        std::system(close_command.c_str());
        return ERR_MOUNT;
    }
}

int pgp(const fs::path &file, const std::string &password) {
    const std::string stem_str = file.stem().string();
    const fs::path mount_directory = fs::path("/mnt") / (stem_str + "_mount");
    const fs::path decrypted_file = file.parent_path() / (stem_str + "_decrypted");

    if (!safe_create_directory(mount_directory)) {
        return ERR_MOUNT;
    }

    // 1) Decrypt the container
    const std::string command = "gpg --batch --yes --passphrase-fd 0 -o " + quote(decrypted_file) + " -d " + quote(file);
    int result = execute_with_password(command, password);
    if (result == -1) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }
    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }

    // 2) Connect device, get the device link
    const std::string loop_command = "losetup -fP " + quote(decrypted_file);
    result = std::system(loop_command.c_str());
    if (result != 0) {
        fs::remove(decrypted_file);
        fs::remove(mount_directory);
        return ERR_LOOP_DEVICE;
    }

    // Get the path to loop device that was automatically selected
    const std::string query_command = "losetup -a | grep " + quote(decrypted_file) + " | cut -d: -f1";
    FILE *pipe = popen(query_command.c_str(), "r");
    if (!pipe) {
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
        return ERR_QUERY_PIPE;
    }

    std::array<char, 64> buffer;
    std::string loop_device_path{};
    while (std::fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        loop_device_path += buffer.data();
    }
    pclose(pipe);

    trim_trailing_whitespace(loop_device_path);

    // 3) Mount device
    const std::string mount_command = "mount " + quote(loop_device_path) + " " + quote(mount_directory);
    result = std::system(mount_command.c_str());

    // 4) Print mount point
    if (result == 0) {
        std::cout << "The decrypted PGP container mounted at:\n" << mount_directory << '\n';
        return SUCCESS;
    } else {
        const std::string detach_command = "losetup -d " + quote(loop_device_path);
        std::system(detach_command.c_str());
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
        return ERR_MOUNT;
    }
}

int truecrypt(const fs::path &file, const std::string &password,
              const bool is_veracrypt) {
    // 1) Init mount point, device name
    const std::string stem_str = file.stem().string();
    const fs::path mount_directory = fs::path("/mnt") / (stem_str + "_mount");
    const std::string device_name = stem_str + "_device";
    const fs::path device_path = fs::path("/dev/mapper") / device_name;

    if (!safe_create_directory(mount_directory)) {
        return ERR_MOUNT;
    }

    // 2) Decrypt and create device
    const std::string command = std::string("cryptsetup open --type tcrypt ") +
                                (is_veracrypt ? "--veracrypt " : "") +
                                quote(file) + " " + quote(device_name) + " -";

    int result = execute_with_password(command, password);
    if (result == -1) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }
    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }

    // 3) Mount device to mount point
    const std::string mount_command = "mount " + quote(device_path) + " " + quote(mount_directory);
    result = std::system(mount_command.c_str());

    // 4) Print mount point  
    if (result == 0) {
        std::cout << "The decrypted TrueCrypt/VeraCrypt container mounted at:\n" << mount_directory << '\n';
        return SUCCESS;
    } else {
        const std::string close_command = "cryptsetup close " + quote(device_name);
        std::system(close_command.c_str());
        fs::remove(mount_directory);
        return ERR_MOUNT;
    }
}
} // namespace crypto_decrypt
