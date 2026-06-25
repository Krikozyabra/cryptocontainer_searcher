#include <catch2/catch_test_macros.hpp>
#include "crypto_utils/crypto_search.h"
#include <filesystem>
#include <cstdlib>
#include <string>

namespace fs = std::filesystem;

void create_file(){
    fs::create_directory("test_search");
    const std::string create_file_command = "dd if=/dev/zero of=./test_search/test_file bs=1M count=30";
    const std::string create_keyfile_command = "echo \"test_password\" > \"./test_search/test_keyfile\"";
    const std::string crypt_file_command = "cryptsetup luksFormat ./test_search/test_file --key-file ./test_search/test_keyfile --keyfile-size 13 --batch-mode";

    system(create_file_command.c_str());
    system(create_keyfile_command.c_str());
    system(crypt_file_command.c_str());
}

void delete_file(){
    const std::string delete_test_files_command = "rm -rfd \"./test_search\"";

    system(delete_test_files_command.c_str());
}

TEST_CASE( "create file and try to find", "[luks][search]" ) {
    create_file();

    REQUIRE( crypto_search::luks_file(fs::path{"./test_search/test_file"}) == true );
    
    delete_file();
}
