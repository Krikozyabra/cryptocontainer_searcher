#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

void trim_trailing_whitespace(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            s.end());
}

namespace crypto_decrypt {

void encfs(const fs::path &file, const std::string &password) {
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
        std::cerr << "An error occured while attempting to open pipe"
                  << std::endl;
        return;
    }

    std::fputs(password.c_str(), pipe);
    std::fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        std::cerr << "An error occurred while attempting to mount" << std::endl;
        fs::remove(mount_directory);
        return;
    }
    // 4) print the mount link
    std::cout << "\nThe decrypted encfs folder was mounted at:" << std::endl;
    std::cout << mount_directory << std::endl;
}

void luks(const fs::path &file, const std::string &password) {
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
        std::cerr << "An error occurred while pipe openning" << std::endl;
        fs::remove(mount_directory);
        return;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        std::cerr << "An error occurred while attempting to decrypt"
                  << std::endl;
        fs::remove(mount_directory);
        return;
    }
    // 3) mount device to mount point
    command =
        "mount /dev/mapper/" + device_name + " " + mount_directory.string();
    result = system(command.c_str());
    // 4) print mount point
    if (!result) {
        std::cout << "The decrypted LUKS container mounted at:" << std::endl;
        std::cout << mount_directory << std::endl;
    } else {
        std::cerr << "Failed to mount device" << std::endl;
        fs::remove(mount_directory);
    }
}

void pgp(const fs::path &file, const std::string &password) {
    const std::string stem_str = file.stem().string();
    const fs::path mount_directory{"/mnt/" + stem_str + "_mount"};
    const std::string decrypted_file = stem_str + "_decrypted";

    fs::create_directory(mount_directory);
    // 1) decrypt the container
    std::string command = "gpg --batch --yes --passphrase-fd 0 -o \"" +
                          decrypted_file + "\" -d \"" + file.string() + "\"";
    FILE *pipe = popen(command.c_str(), "w");
    if (!pipe) {
        std::cerr << "An error occurred while pipe openning" << std::endl;
        fs::remove(mount_directory);
        return;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0) {
        std::cerr << "An error occurred while attempting to decrypt"
                  << std::endl;
        fs::remove(mount_directory);
        return;
    }
    // 2) connect device, get the device link
    command = "losetup -fP \"" + decrypted_file + "\"";
    result = system(command.c_str());
    if (result > 0) {
        std::cerr << "An error occurred while openning loop device"
                  << std::endl;
        fs::remove(decrypted_file);
        fs::remove(mount_directory);
        return;
    }

    command = "losetup -a | grep \"" + decrypted_file + "\" | cut -d: -f1";
    pipe = popen(command.c_str(), "r");

    if (!pipe) {
        std::cerr << "An error occurred while openning losetup query pipe"
                  << std::endl;
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
    }

    std::array<char, 64> buffer;
    std::string loop_device_path{};

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
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
    } else {
        std::cerr << "Failed to mount device" << std::endl;
        command = "losetup -d \"" + loop_device_path + "\"";
        system(command.c_str());
        fs::remove(mount_directory);
        fs::remove(decrypted_file);
    }
}

} // namespace crypto_decrypt
