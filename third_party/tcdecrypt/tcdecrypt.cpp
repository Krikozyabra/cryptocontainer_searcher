/*
 tcdecrypt — public module API implementation.

 Wraps the TrueCrypt 7.1a Volume library behind the clean interface declared in
 tcdecrypt.hpp, so consumers never see TrueCrypt's internal headers.
*/

#include "tcdecrypt.hpp"

#include <fstream>
#include <algorithm>

// TrueCrypt internals (kept private to this translation unit / the static lib).
#include "Platform/Platform.h"
#include "Platform/StringConverter.h"
#include "Volume/Volume.h"
#include "Volume/VolumePassword.h"
#include "Volume/Keyfile.h"
#include "Volume/EncryptionTest.h"

namespace tcdecrypt {

// NOTE: `shared_ptr` and `make_shared` are macros (Platform/SharedPtr.h) that
// already expand into the TrueCrypt namespace, so they must be used *unqualified*
// — writing `TrueCrypt::shared_ptr` would expand to `TrueCrypt::TrueCrypt::...`.
using TrueCrypt::VolumePassword;
using TrueCrypt::KeyfileList;
using TrueCrypt::Keyfile;
using TrueCrypt::FilesystemPath;
using TrueCrypt::StringConverter;
using TrueCrypt::byte;

namespace {

shared_ptr<VolumePassword> makePassword(const std::string& p) {
    return shared_ptr<VolumePassword>(
        new VolumePassword(reinterpret_cast<const byte*>(p.data()), p.size()));
}

shared_ptr<KeyfileList> makeKeyfiles(const std::vector<std::string>& paths) {
    shared_ptr<KeyfileList> kfl(new KeyfileList);
    for (const auto& k : paths)
        kfl->push_back(make_shared<Keyfile>(
            FilesystemPath(StringConverter::ToWide(k))));
    return kfl->empty() ? shared_ptr<KeyfileList>() : kfl;
}

// Run the cipher/hash known-answer self-tests exactly once per process.
void ensureSelfTest() {
    static bool done = false;
    if (!done) {
        TrueCrypt::EncryptionTest::TestAll();
        done = true;
    }
}

} // namespace

struct Volume::Impl {
    TrueCrypt::Volume volume;
};

Volume::Volume(const OpenOptions& options) : impl_(new Impl) {
    try {
        ensureSelfTest();

        TrueCrypt::VolumeType::Enum type =
            options.hidden ? TrueCrypt::VolumeType::Hidden
                           : TrueCrypt::VolumeType::Normal;

        impl_->volume.Open(
            TrueCrypt::VolumePath(TrueCrypt::StringConverter::ToWide(options.path)),
            /* preserveTimestamps */ true,
            makePassword(options.password),
            makeKeyfiles(options.keyfiles),
            TrueCrypt::VolumeProtection::ReadOnly,
            shared_ptr<VolumePassword>(),
            shared_ptr<KeyfileList>(),
            /* sharedAccessAllowed */ true,
            type,
            /* useBackupHeaders */ options.useBackupHeader);
    }
    catch (TrueCrypt::PasswordIncorrect&) {
        throw IncorrectPassword(
            options.hidden
                ? "incorrect password/keyfile, or no hidden volume for these credentials"
                : "incorrect password or keyfile(s)");
    }
    catch (TrueCrypt::Exception& e) {
        throw Error(e.what() ? e.what() : "TrueCrypt error");
    }
}

Volume::~Volume() = default;
Volume::Volume(Volume&&) noexcept = default;
Volume& Volume::operator=(Volume&&) noexcept = default;

std::uint64_t Volume::size() const {
    return impl_->volume.GetSize();
}

std::size_t Volume::sectorSize() const {
    return impl_->volume.GetSectorSize();
}

bool Volume::isHidden() const {
    return impl_->volume.GetType() == TrueCrypt::VolumeType::Hidden;
}

std::string Volume::cipherName() const {
    return TrueCrypt::StringConverter::ToSingle(
        impl_->volume.GetEncryptionAlgorithm()->GetName());
}

void Volume::read(void* dst, std::size_t length, std::uint64_t byteOffset) const {
    try {
        TrueCrypt::BufferPtr buf(reinterpret_cast<TrueCrypt::byte*>(dst), length);
        impl_->volume.ReadSectors(buf, byteOffset);
    }
    catch (TrueCrypt::Exception& e) {
        throw Error(e.what() ? e.what() : "TrueCrypt read error");
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

} // namespace tcdecrypt
