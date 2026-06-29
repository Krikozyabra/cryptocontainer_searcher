/*****************************************************************************
 * encfs_decrypt.h
 *
 * Minimal C++ module: decrypt an entire EncFS folder.
 *
 * The single feature provided here is decrypting a whole encrypted EncFS
 * directory (the "root dir", which contains the .encfs6.xml config) into a
 * plaintext output directory, given the volume password.
 *
 * This is the CROSS-PLATFORM build of the module: it depends on neither FUSE
 * nor POSIX-only filesystem APIs, so it compiles into a single library on both
 * Linux and Windows. It reuses only the portable libencfs crypto/config/name/
 * block-IO primitives, walks the tree with std::filesystem, and reads files
 * with portable C stdio.
 *
 * Scope notes:
 *   - Supports the V6 config format (.encfs6.xml), which encfs 1.9.x creates.
 *     The legacy binary V4/V5 readers are POSIX-bound and not included here.
 *   - The password must be supplied in-process (see DecryptOptions::password);
 *     there is no fork()-based external password program in this build.
 *****************************************************************************/

#ifndef ENCFS_DECRYPT_MODULE_H_
#define ENCFS_DECRYPT_MODULE_H_

#include <string>

namespace encfs_decrypt {

/// Options controlling a whole-folder decrypt.
struct DecryptOptions {
  /// Encrypted EncFS root directory (the one that holds the config file,
  /// e.g. `.encfs6.xml`). Required.
  std::string rootDir;

  /// Destination directory for the decrypted (plaintext) tree. Created if it
  /// does not exist. Required.
  std::string destDir;

  /// Volume password. Required (supplied in-process).
  std::string password;

  /// Explicit path to the config file. Empty = use `<rootDir>/.encfs6.xml`.
  std::string configFile;

  /// Continue decoding blocks even if a MAC check fails (encfs --public style).
  bool forceDecode = false;
};

/// Result of a whole-folder decrypt.
struct DecryptResult {
  bool ok = false;          ///< true when the whole tree decrypted cleanly.
  unsigned long files = 0;  ///< regular files written.
  unsigned long dirs = 0;   ///< directories created.
  unsigned long links = 0;  ///< symlinks recreated.
  std::string error;        ///< human-readable error when !ok.
};

/// Decrypt an entire EncFS folder into `opts.destDir`.
///
/// Loads the EncFS config from `opts.rootDir`, derives the volume key from the
/// password, then walks the encrypted tree and writes the plaintext files,
/// directories and symlinks under `opts.destDir`, preserving the layout.
DecryptResult decryptFolder(const DecryptOptions &opts);

}  // namespace encfs_decrypt

#endif  // ENCFS_DECRYPT_MODULE_H_
