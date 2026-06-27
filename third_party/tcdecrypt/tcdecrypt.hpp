/*
 tcdecrypt — public module API.

 A small, dependency-free (for the consumer) C++ interface for reading
 TrueCrypt volumes. Include this one header and link the `tcdecrypt_core`
 static library; none of the TrueCrypt internal headers leak into your project.

 Cross-platform: Linux and Windows (MSVC or MinGW), C++11.

 Example
 -------
   #include "tcdecrypt.hpp"

   tcdecrypt::OpenOptions opt;
   opt.path     = "secret.tc";
   opt.password = "my password";
   opt.keyfiles = { "key.bin" };   // optional
   opt.hidden   = true;            // open the hidden volume

   try {
       tcdecrypt::Volume vol(opt);
       std::cout << "cipher: " << vol.cipherName()
                 << " size: " << vol.size() << "\n";

       std::vector<unsigned char> buf(vol.sectorSize() * 8);
       vol.read(buf.data(), buf.size(), 0);   // decrypt first 8 sectors
   }
   catch (const tcdecrypt::IncorrectPassword&) { ... }
   catch (const tcdecrypt::Error& e)           { std::cerr << e.what(); }
*/

#ifndef TCDECRYPT_PUBLIC_HPP
#define TCDECRYPT_PUBLIC_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace tcdecrypt {

// Base error for any failure opening or reading a volume.
struct Error : public std::runtime_error {
    explicit Error(const std::string& what) : std::runtime_error(what) {}
};

// Thrown when the password/keyfiles don't unlock the requested volume
// (including: no hidden volume exists for the given credentials).
struct IncorrectPassword : public Error {
    explicit IncorrectPassword(const std::string& what) : Error(what) {}
};

struct OpenOptions {
    std::string path;                      // path to the container/volume file
    std::string password;                  // volume password (may be empty)
    std::vector<std::string> keyfiles;     // optional keyfiles (files or dirs)
    bool hidden = false;                   // open the hidden volume, not the outer one
    bool useBackupHeader = false;          // use the embedded backup header
};

// An opened, decryptable TrueCrypt volume. Read-only. Move-only.
class Volume {
public:
    explicit Volume(const OpenOptions& options);
    ~Volume();

    Volume(Volume&&) noexcept;
    Volume& operator=(Volume&&) noexcept;
    Volume(const Volume&) = delete;
    Volume& operator=(const Volume&) = delete;

    // Decrypted size of the volume's data area, in bytes.
    std::uint64_t size() const;

    // Sector size (bytes). read() offset and length must be multiples of this.
    std::size_t sectorSize() const;

    // True if the opened volume is the hidden volume.
    bool isHidden() const;

    // Human-readable cipher/algorithm name, e.g. "AES" or "AES-Twofish-Serpent".
    std::string cipherName() const;

    // Decrypt `length` bytes starting at `byteOffset` within the volume's data
    // area into `dst`. Both `byteOffset` and `length` must be multiples of
    // sectorSize(). Throws tcdecrypt::Error on failure.
    void read(void* dst, std::size_t length, std::uint64_t byteOffset) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Convenience: decrypt the whole volume (or the first `maxBytes`) to a file.
// Returns the number of bytes written. Throws on error.
std::uint64_t decryptToFile(const OpenOptions& options,
                            const std::string& outputPath,
                            std::uint64_t maxBytes = 0 /* 0 = whole volume */);

} // namespace tcdecrypt

#endif // TCDECRYPT_PUBLIC_HPP
