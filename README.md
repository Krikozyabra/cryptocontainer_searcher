### what i used to analyze:
1) bless - hex-editor for Linux
2) binwalk - create graph with entropy on every byte
3) ls -la - to see hidden files and size of files

## Containers
### TrueCrypt/VeraCrypt
- high entropy (> 7.9 of 8.0)
- file size multiple of 512
- between TrueCrypt and VeraCrypt no diffs in files

### EncFS
- the encrypted folder has the hidden config file like ".encfs6" or ".encfs6.xml"

### LUKS
- first 4 bytes is "LUKS"
- next some bytes has config 

### PGPFile
- first 6 bytes is [0x8c, 0x0d, 0x04, 0x09, 0x03, 0x0A]

## Build
### Windows

    cmake --toolchain mingw-toolchain.cmake -B build
    cmake --build build

### Linux

    cmake -B build
    cmake --build build

## Usage

    ./build/crypto_search --help
    ./build/crypto_search --version
    ./build/crypto_search --folder ~ --recursive
