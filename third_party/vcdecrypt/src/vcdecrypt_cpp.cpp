/*
 vcdecrypt — public C++ module API implementation.

 Wraps VeraCrypt's Volume crypto behind the clean interface declared in
 vcdecrypt.hpp, so consumers never see VeraCrypt's internal headers.

 Implementation note
 -------------------
 Rather than VeraCrypt's high-level Volume::Open() (which depends on its
 Unix-only Platform::File layer and the PCSC/EMV token stack), this wrapper
 drives VeraCrypt's portable, OS-independent crypto core directly:
   - it does its own std::ifstream file I/O,
   - replicates the layout-iteration + VolumeHeader::Decrypt() logic of
     Volume::Open() (mirrors src/Volume/Volume.cpp), and
   - decrypts the data area with EncryptionAlgorithm::DecryptSectors() exactly
     as Volume::ReadSectors() does.
 The result builds identically on Linux and Windows with no extra platform code.

 Governed by the Apache License 2.0 (see License.txt).
*/

#include "vcdecrypt.hpp"

#include <fstream>
#include <algorithm>
#include <cstring>

// VeraCrypt internals (kept private to this translation unit / the static lib).
#include "Platform/Platform.h"
#include "Platform/StringConverter.h"
#include "Volume/VolumeHeader.h"
#include "Volume/VolumeLayout.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/VolumePassword.h"
#include "Volume/Crc32.h"

namespace vcdecrypt {

// NOTE: `shared_ptr` / `make_shared` / `foreach` are macros (Platform/*.h) that
// already expand into the VeraCrypt namespace, so they are used *unqualified*.
// VeraCrypt class types are qualified explicitly, because Common/Crypto.h
// defines a clashing C `EncryptionAlgorithm` typedef at global scope.
using VeraCrypt::VolumeHeader;
using VeraCrypt::VolumeLayout;
using VeraCrypt::VolumeLayoutV1Normal;
using VeraCrypt::VolumeLayoutV2Normal;
using VeraCrypt::VolumeType;
using VeraCrypt::VolumePassword;
using VeraCrypt::Pkcs5Kdf;
using VeraCrypt::SecureBuffer;
using VeraCrypt::Crc32;
using VeraCrypt::StringConverter;

namespace {

// Replicates Keyfile::Apply() (src/Volume/Keyfile.cpp): stream each keyfile
// through CRC32, adding the running CRC bytes into a rotating pool, then mix
// that pool into the password — without VeraCrypt's File/Directory/token deps.
// Returns the keyfile-mixed password, or the plain password if none given.
shared_ptr<VolumePassword> applyKeyfiles(const std::string& password,
                                         const std::vector<std::string>& keyfiles)
{
    if (keyfiles.empty())
        return shared_ptr<VolumePassword>(new VolumePassword(
            reinterpret_cast<const uint8*>(password.data()), password.size()));

    const size_t poolSize = (password.size() <= VolumePassword::MaxLegacySize)
                          ? VolumePassword::MaxLegacySize
                          : VolumePassword::MaxSize;
    SecureBuffer pool(poolSize);
    pool.Zero();
    pool.CopyFrom(VeraCrypt::ConstBufferPtr(
        reinterpret_cast<const uint8*>(password.data()), password.size()));

    const uint64 MaxProcessedLength = 1024 * 1024;
    const uint64 MinProcessedLength = 1;

    for (const std::string& kfPath : keyfiles) {
        std::ifstream kf(kfPath.c_str(), std::ios::binary);
        if (!kf)
            throw Error("cannot open keyfile: " + kfPath);

        Crc32 crc32;
        size_t poolPos = 0;
        uint64 totalLength = 0;
        char buf[64 * 1024];

        while (kf.read(buf, sizeof buf), kf.gcount() > 0) {
            std::streamsize n = kf.gcount();
            for (std::streamsize i = 0; i < n; ++i) {
                uint32 crc = crc32.Process((uint8) buf[i]);
                pool.Ptr()[poolPos++] += (uint8)(crc >> 24);
                pool.Ptr()[poolPos++] += (uint8)(crc >> 16);
                pool.Ptr()[poolPos++] += (uint8)(crc >> 8);
                pool.Ptr()[poolPos++] += (uint8) crc;
                if (poolPos >= pool.Size())
                    poolPos = 0;
                if (++totalLength >= MaxProcessedLength)
                    break;
            }
            if (totalLength >= MaxProcessedLength)
                break;
        }
        if (totalLength < MinProcessedLength)
            throw Error("keyfile contains no data: " + kfPath);
    }

    shared_ptr<VolumePassword> newPassword(new VolumePassword);
    newPassword->Set(pool);
    return newPassword;
}

bool readAt(std::ifstream& f, uint64_t pos, uint8* out, std::size_t len)
{
    f.clear();
    f.seekg(static_cast<std::streamoff>(pos), std::ios::beg);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(len));
    return static_cast<std::size_t>(f.gcount()) == len;
}

} // namespace

struct Volume::Impl {
    std::ifstream                              file;
    shared_ptr<VolumeHeader>                   header;
    shared_ptr<VeraCrypt::EncryptionAlgorithm> ea;          // configured w/ master key
    uint64_t    dataOffset = 0;   // byte offset of data area in host
    uint64_t    dataSize   = 0;   // plaintext size
    uint32_t    sector     = 0;
    bool        hidden     = false;
};

Volume::Volume(const OpenOptions& options) : impl_(new Impl) {
    try {
        impl_->file.open(options.path.c_str(), std::ios::binary | std::ios::in);
        if (!impl_->file.is_open())
            throw Error("cannot open volume file: " + options.path);

        impl_->file.seekg(0, std::ios::end);
        const std::streamoff end = impl_->file.tellg();
        if (end <= 0)
            throw Error("cannot determine volume size: " + options.path);
        const uint64_t hostSize = static_cast<uint64_t>(end);

        shared_ptr<VolumePassword> passwordKey =
            applyKeyfiles(options.password, options.keyfiles);

        const VolumeType::Enum wantType =
            options.hidden ? VolumeType::Hidden : VolumeType::Normal;

        // Mirror Volume::Open(): try each on-disk layout for the requested type.
        bool skipLayoutV1Normal = false;
        VeraCrypt::VolumeLayoutList layouts =
            VolumeLayout::GetAvailableLayouts(wantType);

        for (shared_ptr<VolumeLayout> layout : layouts) {
            if (skipLayoutV1Normal && typeid(*layout) == typeid(VolumeLayoutV1Normal))
                continue;
            if (options.useBackupHeader && !layout->HasBackupHeader())
                continue;
            if (layout->HasDriveHeader())   // system/boot encryption — out of scope
                continue;

            SecureBuffer headerBuffer(layout->GetHeaderSize());

            const int headerOffset = options.useBackupHeader
                ? layout->GetBackupHeaderOffset() : layout->GetHeaderOffset();
            const uint64_t hostOffset = (headerOffset >= 0)
                ? static_cast<uint64_t>(headerOffset)
                : (hostSize - static_cast<uint64_t>(-headerOffset));

            if (hostOffset + layout->GetHeaderSize() > hostSize)
                continue;
            if (!readAt(impl_->file, hostOffset, headerBuffer.Ptr(), layout->GetHeaderSize()))
                continue;

            VeraCrypt::EncryptionAlgorithmList algs =
                layout->GetSupportedEncryptionAlgorithms();
            VeraCrypt::EncryptionModeList modes =
                layout->GetSupportedEncryptionModes();
            if (typeid(*layout) == typeid(VolumeLayoutV2Normal)) {
                skipLayoutV1Normal = true;
                algs  = VeraCrypt::EncryptionAlgorithm::GetAvailableAlgorithms();
                modes = VeraCrypt::EncryptionMode::GetAvailableModes();
            }

            shared_ptr<VolumeHeader> header = layout->GetHeader();
            if (header->Decrypt(headerBuffer, *passwordKey, options.pim,
                                shared_ptr<Pkcs5Kdf>(),
                                layout->GetSupportedKeyDerivationFunctions(),
                                algs, modes))
            {
                if (typeid(*layout) == typeid(VolumeLayoutV2Normal)
                    && header->GetRequiredMinProgramVersion() < 0x10b) {
                    layout.reset(new VolumeLayoutV1Normal);
                    header->SetSize(layout->GetHeaderSize());
                    layout->SetHeader(header);
                }
                impl_->header     = header;
                impl_->ea         = header->GetEncryptionAlgorithm();
                impl_->sector     = static_cast<uint32_t>(header->GetSectorSize());
                impl_->dataOffset = layout->GetDataOffset(hostSize);
                impl_->dataSize   = layout->GetDataSize(hostSize);
                impl_->hidden     = (layout->GetType() == VolumeType::Hidden);
                return;
            }
        }

        throw IncorrectPassword(
            options.hidden
                ? "incorrect password/keyfile, or no hidden volume for these credentials"
                : "incorrect password or keyfile(s)");
    }
    catch (IncorrectPassword&) {
        throw;
    }
    catch (Error&) {
        throw;
    }
    catch (VeraCrypt::PasswordException&) {
        throw IncorrectPassword("incorrect password or keyfile(s)");
    }
    catch (VeraCrypt::Exception&) {
        throw Error("VeraCrypt error while opening volume");
    }
}

Volume::~Volume() = default;
Volume::Volume(Volume&&) noexcept = default;
Volume& Volume::operator=(Volume&&) noexcept = default;

std::uint64_t Volume::size() const {
    return impl_->dataSize;
}

std::size_t Volume::sectorSize() const {
    return impl_->sector;
}

bool Volume::isHidden() const {
    return impl_->hidden;
}

std::string Volume::cipherName() const {
    return StringConverter::ToSingle(impl_->ea->GetName(false));
}

void Volume::read(void* dst, std::size_t length, std::uint64_t byteOffset) const {
    if (length == 0)
        return;
    const uint32_t ss = impl_->sector;
    if (ss == 0 || (byteOffset % ss) != 0 || (length % ss) != 0)
        throw Error("read offset and length must be sector-aligned");
    if (byteOffset + length > impl_->dataSize)
        throw Error("read range exceeds volume data size");

    try {
        const uint64_t hostOffset = impl_->dataOffset + byteOffset;
        if (!readAt(impl_->file, hostOffset, reinterpret_cast<uint8*>(dst), length))
            throw Error("short read from volume");
        impl_->ea->DecryptSectors(reinterpret_cast<uint8*>(dst),
                                  hostOffset / ss, length / ss, ss);
    }
    catch (Error&) {
        throw;
    }
    catch (VeraCrypt::Exception&) {
        throw Error("VeraCrypt read error");
    }
}

std::uint64_t decryptToFile(const OpenOptions& options,
                            const std::string& outputPath,
                            std::uint64_t maxBytes) {
    Volume vol(options);

    const std::uint64_t dataSize = vol.size();
    const std::size_t sectorSize = vol.sectorSize();

    std::uint64_t want = (maxBytes && maxBytes < dataSize) ? maxBytes : dataSize;
    std::uint64_t aligned = (want / sectorSize) * sectorSize;
    if (aligned == 0 && dataSize >= sectorSize)
        aligned = sectorSize;

    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out)
        throw Error("cannot open output file: " + outputPath);

    std::vector<unsigned char> buffer(static_cast<std::size_t>(
        std::min<std::uint64_t>(256u * sectorSize, aligned ? aligned : sectorSize)));

    std::uint64_t offset = 0;
    while (offset < aligned) {
        std::uint64_t remaining = aligned - offset;
        std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), remaining));
        vol.read(buffer.data(), chunk, offset);
        out.write(reinterpret_cast<const char*>(buffer.data()),
                  static_cast<std::streamsize>(chunk));
        offset += chunk;
    }
    out.flush();
    return aligned;
}

} // namespace vcdecrypt
