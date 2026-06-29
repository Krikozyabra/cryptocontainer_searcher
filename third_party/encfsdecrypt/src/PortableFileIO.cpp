#include "PortableFileIO.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstring>

// Portable 64-bit file seek/tell.
#if defined(_WIN32)
#define enc_fseeko _fseeki64
#define enc_ftello _ftelli64
#elif defined(__APPLE__)
#define enc_fseeko fseeko
#define enc_ftello ftello
#else
#define enc_fseeko fseeko
#define enc_ftello ftello
#endif

using encfs::Interface;
using encfs::IORequest;

namespace encfs_decrypt {

PortableFileIO::PortableFileIO(std::string fileName)
    : name_(std::move(fileName)),
      fp_(nullptr),
      knownSize_(false),
      fileSize_(0) {}

PortableFileIO::~PortableFileIO() {
  if (fp_ != nullptr) {
    std::fclose(fp_);
    fp_ = nullptr;
  }
}

// Matches RawFileIO's reported interface so CipherFileIO is happy.
Interface PortableFileIO::interface() const {
  return Interface("FileIO/Portable", 1, 0, 0);
}

void PortableFileIO::setFileName(const char *fileName) { name_ = fileName; }

const char *PortableFileIO::getFileName() const { return name_.c_str(); }

int PortableFileIO::open(int /*flags*/) {
  if (fp_ != nullptr) {
    return 0;  // already open
  }
  // Read-only, binary. "rb" is portable (Windows needs the 'b').
  fp_ = std::fopen(name_.c_str(), "rb");
  if (fp_ == nullptr) {
    return -errno;
  }
  return 0;
}

off_t PortableFileIO::getSize() const {
  if (knownSize_) {
    return fileSize_;
  }
  struct stat st;
  std::memset(&st, 0, sizeof(st));
  if (::stat(name_.c_str(), &st) != 0) {
    return -errno;
  }
  fileSize_ = static_cast<off_t>(st.st_size);
  knownSize_ = true;
  return fileSize_;
}

int PortableFileIO::getAttr(struct stat *stbuf) const {
  if (::stat(name_.c_str(), stbuf) != 0) {
    return -errno;
  }
  return 0;
}

ssize_t PortableFileIO::read(const IORequest &req) const {
  if (fp_ == nullptr) {
    return -EBADF;
  }
  if (enc_fseeko(fp_, static_cast<long long>(req.offset), SEEK_SET) != 0) {
    return -errno;
  }
  size_t got = std::fread(req.data, 1, req.dataLen, fp_);
  if (got < req.dataLen && std::ferror(fp_)) {
    return -EIO;
  }
  return static_cast<ssize_t>(got);
}

ssize_t PortableFileIO::write(const IORequest & /*req*/) {
  // Decrypt-only: never written.
  return -EROFS;
}

int PortableFileIO::truncate(off_t /*size*/) { return -EROFS; }

bool PortableFileIO::isWritable() const { return false; }

}  // namespace encfs_decrypt
