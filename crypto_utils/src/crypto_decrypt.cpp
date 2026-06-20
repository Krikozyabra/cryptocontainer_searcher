#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace crypto_decrypt{

void encfs(const fs::path& file, const std::string& password){
    // 1) get the directory
    const fs::path enc_directory = file.parent_path();
    // 2) create mount directory and file with password
    const fs::path mount_directory{enc_directory.string() + "_mount"};
    fs::create_directory(mount_directory);
    // 3) mount
    const std::string command = "encfs --stdinpass " + enc_directory.string() + " " + mount_directory.string();
    FILE* pipe = popen(command.c_str(), "w");
    if (!pipe) {
        std::cerr << "An error occured while attempting to open pipe" << std::endl;
        return;
    }

    std::fputs(password.c_str(), pipe);
    std::fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0){
        std::cerr << "An error occurred while attempting to mount" << std::endl;
        fs::remove(mount_directory);
        return;
    }
    // 4) print the mount link
    std::cout << "\nThe decrypted encfs folder was mounted at:" << std::endl;
    std::cout << mount_directory << std::endl;
}

}
