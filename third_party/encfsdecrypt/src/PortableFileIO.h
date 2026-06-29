/*****************************************************************************
 * PortableFileIO.h
 *
 * A minimal, read-only, cross-platform implementation of encfs::FileIO.
 *
 * libencfs normally reads ciphertext through RawFileIO, which uses POSIX
 * open()/pread()/lstat(). Those are not portable to Windows. This class
 * provides the same FileIO contract for the *read* path using C stdio
 * (fopen/fseeko/fread), which works identically on Linux and Windows.
 *
 * Only the operations the decrypt path exercises are implemented; write,
 * truncate and setIV-less paths return errors / sane defaults.
 *****************************************************************************/

#ifndef ENCFS_DECRYPT_PORTABLE_FILE_IO_H_
#define ENCFS_DECRYPT_PORTABLE_FILE_IO_H_

#include <cstdio>
#include <string>

#include "FileIO.h"
#include "Interface.h"

namespace encfs_decrypt {

class PortableFileIO : public encfs::FileIO {
 public:
  explicit PortableFileIO(std::string fileName);
  ~PortableFileIO() override;

  encfs::Interface interface() const override;

  void setFileName(const char *fileName) override;
  const char *getFileName() const override;

  int open(int flags) override;

  int getAttr(struct stat *stbuf) const override;
  off_t getSize() const override;

  ssize_t read(const encfs::IORequest &req) const override;
  ssize_t write(const encfs::IORequest &req) override;

  int truncate(off_t size) override;

  bool isWritable() const override;

 private:
  std::string name_;
  std::FILE *fp_;
  mutable bool knownSize_;
  mutable off_t fileSize_;
};

}  // namespace encfs_decrypt

#endif  // ENCFS_DECRYPT_PORTABLE_FILE_IO_H_
