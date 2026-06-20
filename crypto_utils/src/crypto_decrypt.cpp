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

void luks(const fs::path& file, const std::string& password){
    // 1) create mount point
    const fs::path mount_directory{"/mnt/"+file.filename().string()+"_mount"}; 
    // 2) decrypt and create device
    const std::string device_name{file.filename().string()+"_device"};
    std::string command{"cryptsetup open "+file.string()+" "+device_name+" -"};

    FILE* pipe = popen(command.c_str(), "w");
    if (!pipe) {
        std::cerr << "An error occurred while pipe openning" << std::endl;
        return;
    }

    fputs(password.c_str(), pipe);
    fputs("\n", pipe);

    int result = pclose(pipe);

    if (result != 0){
        std::cerr << "An error occurred while attempting to decrypt" << std::endl;
        return;
    }
    // 3) mount device to mount point

    command="mount /dev/mapper/"+device_name+" "+mount_directory.string();
    result = system(command.c_str());

    if (!result){
        std::cout << "The decrypted LUKS container mounted at:" << std::endl;
        std::cout << mount_directory << std::endl;
    }else {
        std::cerr << "Failed to mount device" << std::endl;
    }
    // 4) print mount point
}

}
