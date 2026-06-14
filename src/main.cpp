#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <entropy/shannon_entropy.h>

namespace fs = std::filesystem;

void usage_exit(){
    std::cout<<"Crypto search work only with TrueCrypt/VeraCrypt, EncFS, LUKS, PGP containers.\n\
                Usage:\n\
                \tcrypto_search --folder 'Folder'\n\n\
                You can use next commands:\n\
                \t--help - to see this message\n\
                \t--version - to see version of the program\n\
                \t--folder - to set folder to search in\n\
                \t--recursive - to check nested folders\n";
    exit(EXIT_SUCCESS);
}

void version_exit(){
    std::cout<<"0.0.1\n";
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    setlocale(LC_ALL, 0);
    fs::path searching_folder{"/"}; 
    bool is_recursive = false;

    entropy::ShannonEncryptionChecker checker;
    
    if(argc<3) usage_exit();
    if(strcmp(argv[1], "--version") == 0) version_exit();
    if(strcmp(argv[1], "--help") == 0) usage_exit();
    if(strcmp(argv[1], "--folder") == 0){
        fs::path pathname{argv[2]};
        if(!fs::exists(pathname)){
            std::cout<<"Folder: "<<pathname<<" doesn't exists"<<std::endl;
            exit(EXIT_SUCCESS);
        }
        searching_folder = pathname;
    }
    if(argc == 4 && strcmp(argv[3], "--recursive") == 0)
        is_recursive = true;

    try {
        for(const auto& entry : fs::directory_iterator(searching_folder))
        {
            std::cout<<entry<<std::endl;
            if(entry.is_directory() == false){
                // check for LUKSs header
                std::ifstream byte_stream(entry.path(), std::ios::binary);
                char some_bytes[5]{};
                byte_stream.read(reinterpret_cast<char*>(&some_bytes), sizeof some_bytes);
                some_bytes[4] = '\0';
                if(strcmp(some_bytes, "LUKS") == 0){
                    std::cout << "File is encrypted with LUKS" << std::endl;
                    continue;
                }
                
                // check for TrueCrypt/VeraCrypt
                double entropy_value = checker.get_file_entropy(entry.path());
                if(entropy_value > 7.9 && entry.file_size()%512 == 0){
                    std::cout << "File is encrypted with TrueCrypt\\VeraCrypt" << std::endl;
                    continue;
                }
            }
            else{
                for(const auto& nested_entry : fs::directory_iterator(entry)){
                    std::string filename{nested_entry.path().stem().string()};
                    if(filename.compare(".encfs6") == 0){
                        std::cout << "This folder encrypted with EncFS" << std::endl;
                        break;
                    }
                }
            }
        }
    } 
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
