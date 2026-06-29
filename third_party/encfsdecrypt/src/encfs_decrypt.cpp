/*****************************************************************************
 * encfs_decrypt.cpp  (cross-platform)
 *
 * Decrypt an entire EncFS folder, with NO dependency on FUSE or POSIX-only
 * filesystem APIs, so the same module compiles into one library on both Linux
 * and Windows.
 *
 * It reuses only the portable libencfs primitives:
 *   - XmlReader / EncFSConfig : parse the V6 config (.encfs6.xml).
 *   - Cipher (SSL_Cipher)      : derive the user key (PBKDF2) and the volume key.
 *   - NameIO (BlockNameIO/...) : encode/decode file names (+ IV chaining).
 *   - CipherFileIO / MACFileIO : decrypt file blocks (over PortableFileIO).
 *
 * The directory walk uses std::filesystem; file reads use PortableFileIO
 * (C stdio). The plaintext-driven traversal + per-entry IV handling mirror
 * encfs's own DirNode logic, so all standard/paranoia modes decrypt correctly.
 *
 * Note: only the V6 (XML, ".encfs6.xml") config format is supported in the
 * portable path -- it is the format encfs 1.9.x creates and the only one
 * relevant for new cross-platform volumes. The legacy binary V4/V5 readers are
 * POSIX-bound and intentionally not pulled into this library.
 *****************************************************************************/

#include "encfs_decrypt.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "BlockNameIO.h"
#include "Cipher.h"
#include "CipherFileIO.h"
#include "CipherKey.h"
#include "Error.h"
#include "FSConfig.h"
#include "FileIO.h"
#include "FileUtils.h"  // EncFS_Opts (plain struct; FUSE bits guarded out)
#include "Interface.h"
#include "MACFileIO.h"
#include "NameIO.h"
#include "XmlReader.h"

#include "PortableFileIO.h"

namespace fs = std::filesystem;

using encfs::Cipher;
using encfs::CipherFileIO;
using encfs::CipherKey;
using encfs::EncFSConfig;
using encfs::FileIO;
using encfs::FSConfig;
using encfs::FSConfigPtr;
using encfs::Interface;
using encfs::IORequest;
using encfs::MACFileIO;
using encfs::NameIO;
using encfs::XmlReader;
using encfs::XmlValuePtr;

namespace encfs_decrypt {

namespace {

constexpr int kV5SubVersion = 20040813;

// Parse a V6 (.encfs6.xml) config into an EncFSConfig. Mirrors libencfs'
// readV6Config(), but lives here so the portable library need not compile the
// POSIX/FUSE-bound FileUtils.cpp.
bool loadV6Config(const std::string &configFile, EncFSConfig *cfg,
                  std::string *err) {
  XmlReader rdr;
  if (!rdr.load(configFile.c_str())) {
    *err = "failed to load config file: " + configFile;
    return false;
  }

  XmlValuePtr serialization = rdr["boost_serialization"];
  if (!serialization) {
    *err = "config missing boost_serialization root: " + configFile;
    return false;
  }
  XmlValuePtr config = (*serialization)["cfg"];
  if (!config) config = (*serialization)["config"];
  if (!config) {
    *err = "unable to find XML configuration in: " + configFile;
    return false;
  }

  int version = 0;
  if (!config->read("version", &version) &&
      !config->read("@version", &version)) {
    *err = "unable to find version in config file";
    return false;
  }

  if (version == 20 || version >= 20100713) {
    cfg->subVersion = version;
  } else if (version == 26800) {
    cfg->subVersion = 20080816;
  } else if (version == 26797) {
    cfg->subVersion = 20080813;
  } else {
    cfg->subVersion = version;
  }

  config->read("creator", &cfg->creator);
  config->read("cipherAlg", &cfg->cipherIface);
  config->read("nameAlg", &cfg->nameIface);
  config->read("keySize", &cfg->keySize);
  config->read("blockSize", &cfg->blockSize);
  config->read("plainData", &cfg->plainData);
  config->read("uniqueIV", &cfg->uniqueIV);
  config->read("chainedNameIV", &cfg->chainedNameIV);
  config->read("externalIVChaining", &cfg->externalIVChaining);
  config->read("blockMACBytes", &cfg->blockMACBytes);
  config->read("blockMACRandBytes", &cfg->blockMACRandBytes);
  config->read("allowHoles", &cfg->allowHoles);

  int encodedSize = 0;
  config->read("encodedKeySize", &encodedSize);
  if (encodedSize <= 0) {
    *err = "invalid encoded key size in config";
    return false;
  }
  std::vector<unsigned char> key(encodedSize);
  config->readB64("encodedKeyData", key.data(), encodedSize);
  cfg->keyData.assign(key.begin(), key.end());

  if (cfg->subVersion >= 20080816) {
    int saltLen = 0;
    config->read("saltLen", &saltLen);
    if (saltLen > 0) {
      std::vector<unsigned char> salt(saltLen);
      config->readB64("saltData", salt.data(), saltLen);
      cfg->salt.assign(salt.begin(), salt.end());
    }
    config->read("kdfIterations", &cfg->kdfIterations);
    config->read("desiredKDFDuration", &cfg->desiredKDFDuration);
  } else {
    cfg->kdfIterations = 16;
    cfg->desiredKDFDuration = 500;
  }

  cfg->cfgType = encfs::Config_V6;
  return true;
}

// Derive the user key from a password, reproducing EncFSConfig::makeKey()
// without its interactive/exit-on-error behaviour.
CipherKey deriveUserKey(const std::shared_ptr<Cipher> &cipher,
                        EncFSConfig *cfg, const std::string &password) {
  if (!cfg->salt.empty()) {
    return cipher->newKey(password.c_str(), static_cast<int>(password.size()),
                          cfg->kdfIterations, cfg->desiredKDFDuration,
                          cfg->salt.data(),
                          static_cast<int>(cfg->salt.size()));
  }
  return cipher->newKey(password.c_str(), static_cast<int>(password.size()));
}

// Build the read-only decrypting IO chain for a single ciphertext file:
//   PortableFileIO -> CipherFileIO -> (MACFileIO).
// externalIV is the per-file IV used in paranoia (externalIVChaining) mode.
std::shared_ptr<FileIO> openCipherFile(const std::string &cipherFullPath,
                                       const FSConfigPtr &fsCfg,
                                       uint64_t externalIV) {
  std::shared_ptr<FileIO> raw(new PortableFileIO(cipherFullPath));
  std::shared_ptr<FileIO> io(new CipherFileIO(raw, fsCfg));

  if (fsCfg->config->externalIVChaining) {
    io->setIV(externalIV);
  }

  if (fsCfg->config->blockMACBytes != 0 ||
      fsCfg->config->blockMACRandBytes != 0) {
    io = std::shared_ptr<FileIO>(new MACFileIO(io, fsCfg));
  }

  if (io->open(0 /* O_RDONLY */) < 0) {
    return nullptr;
  }
  return io;
}

struct Walker {
  std::shared_ptr<NameIO> naming;
  FSConfigPtr fsCfg;
  std::string rootDir;  // ciphertext root, with trailing separator
  DecryptResult *res;

  // Decrypt one regular file (plaintextPath like "/a/b.txt") to destFsPath.
  bool decryptFile(const std::string &plaintextPath,
                   const fs::path &destFsPath) {
    uint64_t iv = 0;
    std::string cipherRel = naming->encodePath(plaintextPath.c_str(), &iv);
    std::string cipherFull = rootDir + cipherRel;

    std::shared_ptr<FileIO> io = openCipherFile(cipherFull, fsCfg, iv);
    if (!io) {
      res->error = "unable to open encrypted file: " + plaintextPath;
      return false;
    }

    off_t size = io->getSize();
    if (size < 0) {
      res->error = "unable to size encrypted file: " + plaintextPath;
      return false;
    }

    std::error_code ec;
    fs::create_directories(destFsPath.parent_path(), ec);
    FILE *out = std::fopen(destFsPath.string().c_str(), "wb");
    if (out == nullptr) {
      res->error = "unable to create output file: " + destFsPath.string();
      return false;
    }

    const size_t kBuf = 4096;
    std::vector<unsigned char> buf(kBuf);
    off_t offset = 0;
    bool ok = true;
    while (offset < size) {
      size_t want = static_cast<size_t>(
          std::min<off_t>(static_cast<off_t>(kBuf), size - offset));
      IORequest req;
      req.offset = offset;
      req.dataLen = want;
      req.data = buf.data();
      ssize_t got = io->read(req);
      if (got < 0) {
        res->error = "decryption read error in: " + plaintextPath;
        ok = false;
        break;
      }
      if (got == 0) break;
      if (std::fwrite(buf.data(), 1, static_cast<size_t>(got), out) !=
          static_cast<size_t>(got)) {
        res->error = "write error to: " + destFsPath.string();
        ok = false;
        break;
      }
      offset += got;
    }
    std::fclose(out);
    if (ok) res->files++;
    return ok;
  }

  // Recursively decrypt the plaintext directory `plainDir` (e.g. "/" or "/sub")
  // into `destDir`.
  bool walk(const std::string &plainDir, const fs::path &destDir) {
    std::error_code ec;
    fs::create_directories(destDir, ec);
    if (plainDir != "/") res->dirs++;

    // Cipher path of this directory + its chained IV.
    uint64_t dirIV = 0;
    std::string cipherDirRel;
    if (plainDir == "/") {
      cipherDirRel.clear();
      if (naming->getChainedNameIV()) {
        naming->encodePath("/", &dirIV);
      }
    } else {
      std::string tmp = plainDir;
      uint64_t iv = 0;
      cipherDirRel = naming->encodePath(plainDir.c_str(), &iv);
      if (naming->getChainedNameIV()) dirIV = iv;
    }
    std::string cipherDirFull = rootDir + cipherDirRel;

    std::error_code itEc;
    fs::directory_iterator it(cipherDirFull, itEc), end;
    if (itEc) {
      res->error = "unable to open encrypted directory: " + cipherDirFull;
      return false;
    }

    for (; it != end; it.increment(itEc)) {
      if (itEc) {
        res->error = "error iterating: " + cipherDirFull;
        return false;
      }
      std::string cipherName = it->path().filename().string();

      // Skip the config and dotfiles that aren't encrypted entries.
      if (cipherName == ".encfs6.xml" || cipherName == "." ||
          cipherName == "..") {
        continue;
      }

      // Decode this entry's plaintext name using the parent dir IV.
      std::string plainName;
      try {
        uint64_t localIV = dirIV;
        plainName = naming->decodePath(cipherName.c_str(), &localIV);
      } catch (encfs::Error &) {
        // Not a decodable encfs name (stray file) -- skip it.
        continue;
      }
      if (plainName.empty()) continue;

      std::string childPlain =
          (plainDir == "/") ? ("/" + plainName) : (plainDir + "/" + plainName);
      fs::path childDest = destDir / plainName;

      std::error_code sEc;
      fs::file_status st = fs::symlink_status(it->path(), sEc);
      if (sEc) {
        res->error = "unable to stat: " + it->path().string();
        return false;
      }

      if (fs::is_directory(st)) {
        if (!walk(childPlain, childDest)) return false;
      } else if (fs::is_symlink(st)) {
        // Recreate the symlink with a decoded target.
        std::error_code rEc;
        fs::path target = fs::read_symlink(it->path(), rEc);
        if (rEc) {
          res->error = "unable to read symlink: " + it->path().string();
          return false;
        }
        std::string decodedTarget;
        try {
          decodedTarget = naming->decodePath(target.string().c_str());
        } catch (encfs::Error &) {
          decodedTarget = target.string();
        }
        std::error_code lEc;
        fs::create_symlink(decodedTarget, childDest, lEc);
        if (!lEc) res->links++;
      } else if (fs::is_regular_file(st)) {
        if (!decryptFile(childPlain, childDest)) return false;
      }
      // other types (fifo/socket/...) are skipped.
    }
    return true;
  }
};

}  // namespace

DecryptResult decryptFolder(const DecryptOptions &opts) {
  DecryptResult result;

  if (opts.rootDir.empty()) {
    result.error = "rootDir is required";
    return result;
  }
  if (opts.destDir.empty()) {
    result.error = "destDir is required";
    return result;
  }
  if (opts.password.empty()) {
    result.error =
        "password is required (in-process password only on this platform)";
    return result;
  }

  // Resolve the config file.
  fs::path root(opts.rootDir);
  fs::path cfgPath =
      opts.configFile.empty() ? (root / ".encfs6.xml") : fs::path(opts.configFile);
  if (!fs::exists(cfgPath)) {
    result.error = "config file not found: " + cfgPath.string();
    return result;
  }

  auto cfg = std::make_shared<EncFSConfig>();
  if (!loadV6Config(cfgPath.string(), cfg.get(), &result.error)) {
    return result;  // result.error already set
  }

  if (cfg->plainData) {
    result.error = "plainData volumes are not supported";
    return result;
  }

  std::shared_ptr<Cipher> cipher = Cipher::New(cfg->cipherIface, cfg->keySize);
  if (!cipher) {
    result.error = "unsupported cipher in config";
    return result;
  }

  CipherKey userKey = deriveUserKey(cipher, cfg.get(), opts.password);
  if (!userKey) {
    result.error = "failed to derive user key from password";
    return result;
  }

  if (cfg->keyData.empty()) {
    result.error = "config has no key data";
    return result;
  }
  CipherKey volumeKey =
      cipher->readKey(cfg->keyData.data(), userKey, /*checkKey=*/true);
  userKey.reset();
  if (!volumeKey) {
    result.error = "incorrect password (volume key did not decode)";
    return result;
  }

  std::shared_ptr<NameIO> naming =
      NameIO::New(cfg->nameIface, cipher, volumeKey);
  if (!naming) {
    result.error = "unsupported filename encoding in config";
    return result;
  }
  naming->setChainedNameIV(cfg->chainedNameIV);

  auto fsCfg = std::make_shared<FSConfig>();
  fsCfg->cipher = cipher;
  fsCfg->key = volumeKey;
  fsCfg->nameCoding = naming;
  fsCfg->config = cfg;
  fsCfg->forceDecode = opts.forceDecode;
  fsCfg->reverseEncryption = false;
  // The block-IO classes read a few fields off opts (e.g. noCache); provide a
  // default so they are never dereferenced as null.
  fsCfg->opts = std::make_shared<encfs::EncFS_Opts>();
  fsCfg->opts->readOnly = true;

  std::string rootDir = opts.rootDir;
  if (rootDir.back() != '/' && rootDir.back() != '\\') rootDir.push_back('/');

  Walker w;
  w.naming = naming;
  w.fsCfg = fsCfg;
  w.rootDir = rootDir;
  w.res = &result;

  std::error_code ec;
  fs::create_directories(opts.destDir, ec);

  result.ok = w.walk("/", fs::path(opts.destDir));
  return result;
}

}  // namespace encfs_decrypt
