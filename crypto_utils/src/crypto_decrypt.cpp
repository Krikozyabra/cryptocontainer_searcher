#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <iostream>

#include "crypto_utils/crypto_decrypt.h"

namespace fs = std::filesystem;

int trim_trailing_whitespace(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            s.end());
    return 0;
}

namespace crypto_decrypt {
int encfs(const fs::path &file, const std::string &password) {
    // 1) get the directory
    const fs::path enc_directory = file.parent_path();
    // 2) create mount directory and file with password
    const fs::path mount_directory{enc_directory.string() + "_mount"};
    fs::create_directory(mount_directory);
    // 3) mount
    const std::string command = "encfs --stdinpass " + enc_directory.string() +
                                " " + mount_directory.string();
    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        return ERR_PIPE_OPEN;
    }

    std::fputs(password.c_str(), pipe);
    std::fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }
    // 4) print the mount link
    std::cout << "\nThe decrypted encfs folder was mounted at:" << std::endl;
    std::cout << mount_directory << std::endl;
    return SUCCESS;
}

int luks(const fs::path &file, const std::string &password) {
    // 1) create mount point
    const fs::path mount_directory{"/mnt/" + file.filename().string() +
                                   "_mount"};
    fs::create_directory(mount_directory);
    // 2) decrypt and create device
    const std::string device_name{file.filename().string() + "_device"};
    std::string command{"cryptsetup open " + file.string() + " " + device_name +
                        " -"};

    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }
    // 3) mount device to mount point
    command =
        "mount /dev/mapper/" + device_name + " " + mount_directory.string();
    result = system(command.c_str());
    // 4) print mount point
    if (!result) {
        std::cout << "The decrypted LUKS container mounted at:" << std::endl;
        std::cout << mount_directory << std::endl;
        return SUCCESS;
    } else {
        fs::remove(mount_directory);
        return ERR_MOUNT;
    }
}

int pgp(const fs::path &file, const std::string &password) {
    const std::string stem_str = file.stem().string();
    const fs::path mount_directory{"/mnt/" + stem_str + "_mount"};
    const std::string decrypted_file =
        file.parent_path().string() + "/" + file.stem().string() + "_decrypted";

    fs::create_directory(mount_directory);
    // 1) decrypt the container
    std::string command = "gpg --batch --yes --passphrase-fd 0 -o \"" +
                          decrypted_file + "\" -d \"" + file.string() + "\"";
    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }
    // 2) connect device, get the device link
    command = "losetup -fP \"" + decrypted_file + "\"";
    result = system(command.c_str());
    if (result != 0) {
        fs::remove(decrypted_file);
        fs::remove(mount_directory);
        return ERR_LOOP_DEVICE;
    }

    command = "losetup -a | grep \"" + decrypted_file + "\" | cut -d: -f1";
    pipe = popen(command.c_str(), "r");

    if (!pipe) {
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
        return ERR_QUERY_PIPE;
    }

    std::array<char, 64> buffer;
    std::string loop_device_path{};

    while(fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        loop_device_path += buffer.data();
    }

    pclose(pipe);

    trim_trailing_whitespace(loop_device_path);

    // 3) mount device
    command = "mount \"" + loop_device_path + "\" \"" +
              mount_directory.string() + "\"";
    result = system(command.c_str());

    // 4) print mount point
    if (!result) {
        std::cout << "The decrypted PGP container mounted at:" << std::endl;
        std::cout << mount_directory << std::endl;
        return SUCCESS;
    } else {
        command = "losetup -d \"" + loop_device_path + "\"";
        system(command.c_str());
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
        return ERR_MOUNT;
    }
}

int truecrypt(const fs::path &file, const std::string &password,
              const bool is_veracrypt) {
    // 1) init mount point, device name
    const std::string stem_str = file.stem().string();
    const fs::path mount_directory{"/mnt/" + stem_str + "_mount"};
    const std::string device_name = stem_str + "_device";
    const fs::path device_path{"/dev/mapper/" + device_name};

    fs::create_directory(mount_directory);
    // 2) decrypt and create device
    std::string command = std::string("cryptsetup open --type tcrypt ") +
                          (is_veracrypt ? "--veracrypt " : "") + "\"" +
                          file.string() + "\" \"" + device_name + "\" -";

    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        fs::remove(mount_directory);
        return ERR_PIPE_OPEN;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        fs::remove(mount_directory);
        return ERR_DECRYPT;
    }
    // 3) mount device to mount point
    command = "mount \"" + device_path.string() + "\" \"" +
              mount_directory.string() + "\"";
    result = system(command.c_str());
    // 4) print mount point
    if (!result) {
        std::cout << "The decrypted LUKS container mounted at:" << std::endl;
        std::cout << mount_directory << std::endl;
        return SUCCESS;
    } else {
        command = "cryptsetup close \"" + device_name + "\"";
        system(command.c_str());
        fs::remove(mount_directory);
        return ERR_MOUNT;
    }
}
} // namespace crypto_decrypt
