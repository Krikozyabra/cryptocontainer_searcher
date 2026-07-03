#include <catch2/catch_test_macros.hpp>
#include "crypto_utils/crypto_search.h"
#include <filesystem>
#include <cstdlib>
#include <string>

namespace fs = std::filesystem;

struct TestDirectoryGuard {
    const fs::path test_dir = "./test_search";

    TestDirectoryGuard() {
        // Создаем директорию (игнорирует, если она уже есть)
        fs::create_directories(test_dir);
    }

    ~TestDirectoryGuard() {
        // Деструктор гарантированно вызовется при выходе из области видимости TEST_CASE,
        // даже если REQUIRE внутри теста завершился неудачей.
        std::error_code ec;
        fs::remove_all(test_dir, ec);
    }
};

struct EncfsMountGuard {
    fs::path mount_point;

    EncfsMountGuard(fs::path mp) : mount_point(std::move(mp)) {}

    ~EncfsMountGuard() {
        std::string cmd = "fusermount3 -u " + mount_point.string() + " 2>/dev/null || "
                          "fusermount -u " + mount_point.string() + " 2>/dev/null";
        std::system(cmd.c_str());
    }
};

auto run_system_command = [](const std::string& command) {
    int result = std::system(command.c_str());
    if (result != 0) {
        FAIL("System command failed: " << command << " (exit code: " << result << ")");
    }
};

TEST_CASE( "create luks container and try to find", "[luks][search]" ) {
    TestDirectoryGuard guard;
    const std::string create_file_command = "dd if=/dev/zero of=./test_search/test_file bs=1M count=30";
    const std::string create_keyfile_command = "echo \"test_password\" > \"./test_search/test_keyfile\"";
    const std::string crypt_file_command = "cryptsetup luksFormat ./test_search/test_file --key-file ./test_search/test_keyfile --keyfile-size 13 --batch-mode";

    run_system_command(create_file_command);
    run_system_command(create_keyfile_command);
    run_system_command(crypt_file_command);

    REQUIRE( crypto_search::luks_file(fs::path{"./test_search/test_file"}) == true );
}

TEST_CASE( "create veracrypt container and try to find", "[veracrypt][search]" ) {
    TestDirectoryGuard guard;

    const std::string crypt_container_command = "veracrypt -t -c ./test_search/test_file --volume-type=normal --encryption=AES --hash=SHA512 --filesystem=FAT --size=32M --password=\"MyTestPassword123\" --pim=0 --random-source=/dev/urandom --non-interactive --force";

    run_system_command(crypt_container_command);

    REQUIRE( crypto_search::veracrypt_truecrypt_file(fs::path{"./test_search/test_file"}) == true );
}

TEST_CASE( "create truecrypt container and try to find", "[truecrypt][search]" ) {
    TestDirectoryGuard guard;

    const std::string crypt_container_command = "truecrypt -t -c ./test_search/test_file "
        "--volume-type=normal --encryption=AES --hash=sha-512 "
        "--filesystem=ext4 --size=33554432 --password=\"MyTestPassword123\" "
        "--random-source=/dev/urandom --non-interactive --force";

    run_system_command(crypt_container_command);

    REQUIRE( crypto_search::veracrypt_truecrypt_file(fs::path{"./test_search/test_file"}) == true );
}

TEST_CASE( "create encfs container and try to find", "[encfs][search]" ) {
    TestDirectoryGuard directory_guard;

    const fs::path encrypted_dir = fs::absolute("./test_search/encrypted");
    const fs::path decrypted_dir = fs::absolute("./test_search/decrypted");

    fs::create_directories(encrypted_dir);
    fs::create_directories(decrypted_dir);

    EncfsMountGuard mount_guard(decrypted_dir);

    const std::string crypt_container_command = 
        "echo \"MyTestPassword123\" | encfs --standard --stdinpass " + 
        encrypted_dir.string() + " " + decrypted_dir.string();

    run_system_command(crypt_container_command);

    REQUIRE( crypto_search::encfs_file(encrypted_dir/fs::path(".encfs6.xml")) == true );
}

TEST_CASE( "create pgp symmetric container and try to find", "[pgp][search]" ) {
    TestDirectoryGuard guard;

    const std::string plain_text_file = "./test_search/test_plain.txt";
    const std::string encrypted_file = "./test_search/test_encrypted.gpg";

    const std::string create_file_command = "echo \"Secret content for testing\" > " + plain_text_file;
    run_system_command(create_file_command);

    const fs::path gpg_home = fs::absolute("./test_search/gnupg_home");
    fs::create_directories(gpg_home);

    const std::string crypt_container_command = 
        "gpg --homedir " + gpg_home.string() + " --symmetric --batch --yes --pinentry-mode loopback "
        "--passphrase \"MyTestPassword123\" --output " + encrypted_file + " " + plain_text_file;

    run_system_command(crypt_container_command);

    REQUIRE( crypto_search::pgp_file(fs::path{encrypted_file}) == true );
}
