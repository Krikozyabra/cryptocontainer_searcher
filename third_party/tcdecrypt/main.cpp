/*
 tcdecrypt — minimal standalone TrueCrypt volume decryptor.

 Opens a TrueCrypt volume with a password and optional keyfile(s), then writes
 the decrypted plaintext of the volume to a file (or stdout). Supports hidden
 volumes via --hidden (the Volume library natively probes hidden layouts when
 asked for VolumeType::Hidden).

 Usage:
   tcdecrypt --volume FILE --password PASS [--keyfile FILE]... \
             [--hidden] [--out FILE] [--size N] [--backup-header]

 Notes:
 - This is a read-only decryptor: it never modifies the volume.
 - Password is read from --password, or from $TC_PASSWORD, or (if neither)
   from stdin's first line.
 - C++17, builds with CMake. See CMakeLists.txt for the file set reused from
   the TrueCrypt 7.1a source tree.
*/

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "Platform/Platform.h"
#include "Volume/Volume.h"
#include "Volume/VolumePassword.h"
#include "Volume/Keyfile.h"
#include "Volume/EncryptionTest.h"
#include "Volume/VolumeHeader.h"
#include "Volume/VolumeLayout.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/EncryptionModeXTS.h"
#include "Platform/StringConverter.h"
#include "Platform/File.h"

using namespace TrueCrypt;

namespace {

void PrintUsage(const char *prog)
{
	std::cerr <<
		"tcdecrypt — minimal TrueCrypt volume decryptor\n\n"
		"Usage:\n  " << prog << " --volume FILE --password PASS [options]\n\n"
		"Options:\n"
		"  --volume FILE        Path to the TrueCrypt container/volume (required)\n"
		"  --password PASS      Volume password (or $TC_PASSWORD, or stdin)\n"
		"  --keyfile FILE       Keyfile to combine with the password (repeatable)\n"
		"  --hidden             Open the hidden volume instead of the outer one\n"
		"  --backup-header      Use the volume's embedded backup header\n"
		"  --out FILE           Write decrypted data here (default: stdout)\n"
		"  --size N             Decrypt only the first N bytes (default: whole volume)\n"
		"  --info               Print volume info and exit (no data written)\n"
		"  -h, --help           Show this help\n"
		"\nTest-fixture creation (round-trip self-test):\n"
		"  --create --host-size N            Create a normal AES-256-XTS/RIPEMD-160 volume\n"
		"  [--make-hidden --hidden-size N    ...with an embedded hidden volume,\n"
		"   --hidden-password P              its password,\n"
		"   --hidden-keyfile FILE]           and keyfile(s)\n";
}

std::string ReadFirstStdinLine()
{
	std::string line;
	std::getline(std::cin, line);
	// strip a trailing CR if present (e.g. from Windows-formatted input)
	if (!line.empty() && line.back() == '\r')
		line.pop_back();
	return line;
}

void FillRandom(const BufferPtr &buf)
{
	// Test-grade randomness for keys/salt: this is only used by --create to
	// produce fixtures for verifying the decryptor, not for real volumes.
	std::ifstream urandom("/dev/urandom", std::ios::binary);
	if (urandom)
		urandom.read(reinterpret_cast<char *>(buf.Get()), (std::streamsize) buf.Size());
	else
		for (size_t i = 0; i < buf.Size(); ++i) buf[i] = (byte)(std::rand() & 0xff);
}

shared_ptr<VolumePassword> MakePassword(const std::string &p)
{
	return shared_ptr<VolumePassword>(
		new VolumePassword(reinterpret_cast<const byte *>(p.data()), p.size()));
}

shared_ptr<KeyfileList> MakeKeyfiles(const std::vector<std::string> &paths)
{
	shared_ptr<KeyfileList> kfl(new KeyfileList);
	for (const auto &k : paths)
		kfl->push_back(make_shared<Keyfile>(FilesystemPath(StringConverter::ToWide(k))));
	return kfl->empty() ? shared_ptr<KeyfileList>() : kfl;
}

// Write a single TrueCrypt V2 header (normal or hidden) for `layout` into the
// host file at the layout's header offset, mirroring Core/VolumeCreator.cpp.
// Returns the master key so the caller can seed the data area if desired.
void WriteHeader(File &hostFile, uint64 hostSize, shared_ptr<VolumeLayout> layout,
                 VolumeType::Enum type, uint64 volumeSize,
                 shared_ptr<VolumePassword> password, shared_ptr<KeyfileList> keyfiles)
{
	// NB: fully-qualify TrueCrypt::EncryptionAlgorithm — Common/Crypto.h defines
	// a C-level global `EncryptionAlgorithm` typedef that otherwise makes the
	// bare name ambiguous in this `using namespace TrueCrypt` translation unit.
	// Pick the AES algorithm from the registry (its first entry) rather than
	// `new AES`, which is fragile to parse near the Crypto/ C headers.
	shared_ptr<TrueCrypt::EncryptionAlgorithm> ea;
	foreach (shared_ptr<TrueCrypt::EncryptionAlgorithm> a, TrueCrypt::EncryptionAlgorithm::GetAvailableAlgorithms())
		if (a->GetName() == L"AES") { ea = a; break; }
	if (!ea) ea = TrueCrypt::EncryptionAlgorithm::GetAvailableAlgorithms().front();

	shared_ptr<Pkcs5Kdf> kdf;
	foreach (shared_ptr<Pkcs5Kdf> k, layout->GetSupportedKeyDerivationFunctions())
		if (k->GetName() == L"HMAC-RIPEMD-160") { kdf = k; break; }
	if (!kdf) kdf = layout->GetSupportedKeyDerivationFunctions().front();

	shared_ptr<VolumeHeader> header = layout->GetHeader();
	SecureBuffer headerBuffer(layout->GetHeaderSize());

	VolumeHeaderCreationOptions opt;
	opt.EA = ea;
	opt.Kdf = kdf;
	opt.Type = type;
	opt.SectorSize = TC_SECTOR_SIZE_LEGACY;

	if (type == VolumeType::Hidden)
		opt.VolumeDataStart = hostSize - layout->GetHeaderSize() * 2 - volumeSize;
	else
		opt.VolumeDataStart = layout->GetHeaderSize() * 2;
	opt.VolumeDataSize = layout->GetMaxDataSize(volumeSize);

	SecureBuffer masterKey(ea->GetKeySize() * 2);
	FillRandom(masterKey);
	opt.DataKey = masterKey;

	SecureBuffer salt(VolumeHeader::GetSaltSize());
	FillRandom(salt);
	opt.Salt = salt;

	SecureBuffer headerKey(VolumeHeader::GetLargestSerializedKeySize());
	shared_ptr<VolumePassword> passwordKey = Keyfile::ApplyListToPassword(keyfiles, password);
	kdf->DeriveKey(headerKey, *passwordKey, salt);
	opt.HeaderKey = headerKey;

	header->Create(headerBuffer, opt);

	int off = layout->GetHeaderOffset();
	if (off >= 0) hostFile.SeekAt(off); else hostFile.SeekEnd(off);
	hostFile.Write(headerBuffer);
}

// Create a TrueCrypt container with a normal volume, optionally embedding a
// hidden volume (with its own password/keyfiles). Mirrors the layout that
// Volume::Open expects to read back.
int CreateVolume(const std::string &path, uint64 hostSize,
                 shared_ptr<VolumePassword> outerPw, shared_ptr<KeyfileList> outerKf,
                 bool withHidden, uint64 hiddenSize,
                 shared_ptr<VolumePassword> hiddenPw, shared_ptr<KeyfileList> hiddenKf)
{
	// Pre-size the host file with random bytes (so the unused space looks
	// encrypted and the hidden header sits inside real data).
	{
		std::ofstream f(path, std::ios::binary | std::ios::trunc);
		std::vector<char> zeros(64 * 1024);
		FillRandom(BufferPtr(reinterpret_cast<byte *>(zeros.data()), zeros.size()));
		uint64 written = 0;
		while (written < hostSize) {
			uint64 n = std::min<uint64>(zeros.size(), hostSize - written);
			f.write(zeros.data(), (std::streamsize) n);
			written += n;
		}
	}

	make_shared_auto(File, host);
	host->Open(VolumePath(StringConverter::ToWide(path)), File::OpenReadWrite, File::ShareNone);

	WriteHeader(*host, hostSize, shared_ptr<VolumeLayout>(new VolumeLayoutV2Normal),
	            VolumeType::Normal, hostSize, outerPw, outerKf);

	if (withHidden)
		WriteHeader(*host, hostSize, shared_ptr<VolumeLayout>(new VolumeLayoutV2Hidden),
		            VolumeType::Hidden, hiddenSize, hiddenPw, hiddenKf);

	host->Flush();
	host.reset();
	return 0;
}

} // namespace

int main(int argc, char **argv)
{
	std::string volumePath;
	std::string password;
	bool passwordGiven = false;
	std::vector<std::string> keyfilePaths;
	bool hidden = false;
	bool backupHeader = false;
	bool infoOnly = false;
	std::string outPath;
	uint64 sizeLimit = 0; // 0 == whole volume

	// --create mode (test-fixture generation)
	bool createMode = false;
	uint64 hostSize = 0;
	uint64 hiddenSize = 0;
	std::string hiddenPassword;
	std::vector<std::string> hiddenKeyfilePaths;

	for (int i = 1; i < argc; ++i)
	{
		std::string a = argv[i];
		auto next = [&](const char *name) -> std::string {
			if (i + 1 >= argc) {
				std::cerr << "error: " << name << " requires an argument\n";
				std::exit(2);
			}
			return argv[++i];
		};

		if (a == "--volume") volumePath = next("--volume");
		else if (a == "--password") { password = next("--password"); passwordGiven = true; }
		else if (a == "--keyfile") keyfilePaths.push_back(next("--keyfile"));
		else if (a == "--hidden") hidden = true;
		else if (a == "--backup-header") backupHeader = true;
		else if (a == "--info") infoOnly = true;
		else if (a == "--out") outPath = next("--out");
		else if (a == "--size") sizeLimit = std::strtoull(next("--size").c_str(), nullptr, 10);
		// create-mode flags
		else if (a == "--create") createMode = true;
		else if (a == "--host-size") hostSize = std::strtoull(next("--host-size").c_str(), nullptr, 10);
		else if (a == "--hidden-size") hiddenSize = std::strtoull(next("--hidden-size").c_str(), nullptr, 10);
		else if (a == "--make-hidden") hidden = true; // reuse `hidden` to request a hidden inner volume in create mode
		else if (a == "--hidden-password") hiddenPassword = next("--hidden-password");
		else if (a == "--hidden-keyfile") hiddenKeyfilePaths.push_back(next("--hidden-keyfile"));
		else if (a == "-h" || a == "--help") { PrintUsage(argv[0]); return 0; }
		else { std::cerr << "error: unknown argument '" << a << "'\n"; PrintUsage(argv[0]); return 2; }
	}

	if (volumePath.empty()) {
		std::cerr << "error: --volume is required\n";
		PrintUsage(argv[0]);
		return 2;
	}

	// Resolve the password: --password, then $TC_PASSWORD, then stdin.
	if (!passwordGiven) {
		if (const char *env = std::getenv("TC_PASSWORD")) {
			password = env;
		} else {
			std::cerr << "Enter volume password: ";
			password = ReadFirstStdinLine();
		}
	}

	try {
		// Run the cipher/hash self-tests once — this validates the extracted
		// crypto primitives against TrueCrypt's known-answer test vectors.
		EncryptionTest::TestAll();

		// --create: generate a TrueCrypt container to use as a test fixture.
		if (createMode) {
			if (hostSize == 0) { std::cerr << "error: --create requires --host-size\n"; return 2; }
			if (hidden && hiddenSize == 0) { std::cerr << "error: --make-hidden requires --hidden-size\n"; return 2; }
			std::cerr << "Creating " << (hidden ? "normal+hidden" : "normal")
			          << " AES-256-XTS / RIPEMD-160 volume at '" << volumePath << "' ("
			          << hostSize << " bytes)\n";
			CreateVolume(volumePath, hostSize,
			             MakePassword(password), MakeKeyfiles(keyfilePaths),
			             hidden, hiddenSize,
			             MakePassword(hiddenPassword), MakeKeyfiles(hiddenKeyfilePaths));
			std::cerr << "Created.\n";
			return 0;
		}

		// Build the password and keyfile list.
		shared_ptr<VolumePassword> pw = MakePassword(password);

		shared_ptr<KeyfileList> keyfiles(new KeyfileList);
		for (const auto &kf : keyfilePaths)
			keyfiles->push_back(make_shared<Keyfile>(FilesystemPath(StringConverter::ToWide(kf))));

		VolumeType::Enum volumeType = hidden ? VolumeType::Hidden : VolumeType::Normal;

		Volume volume;
		volume.Open(
			VolumePath(StringConverter::ToWide(volumePath)),
			/* preserveTimestamps */ true,
			pw,
			keyfiles->empty() ? shared_ptr<KeyfileList>() : keyfiles,
			VolumeProtection::ReadOnly,
			shared_ptr<VolumePassword>(),
			shared_ptr<KeyfileList>(),
			/* sharedAccessAllowed */ true,
			volumeType,
			/* useBackupHeaders */ backupHeader);

		const uint64 dataSize = volume.GetSize();
		const size_t sectorSize = volume.GetSectorSize();

		std::cerr << "Volume opened successfully.\n"
		          << "  Type:         " << (volume.GetType() == VolumeType::Hidden ? "Hidden" : "Normal") << "\n"
		          << "  Cipher:       " << StringConverter::ToSingle(volume.GetEncryptionAlgorithm()->GetName()) << "\n"
		          << "  Sector size:  " << sectorSize << " bytes\n"
		          << "  Data size:    " << dataSize << " bytes\n";

		if (infoOnly)
			return 0;

		uint64 toDecrypt = (sizeLimit && sizeLimit < dataSize) ? sizeLimit : dataSize;
		// ReadSectors requires sector-aligned lengths/offsets.
		uint64 alignedToDecrypt = (toDecrypt / sectorSize) * sectorSize;
		if (alignedToDecrypt == 0 && dataSize >= sectorSize)
			alignedToDecrypt = sectorSize;

		std::ostream *out = &std::cout;
		std::ofstream file;
		if (!outPath.empty()) {
			file.open(outPath, std::ios::binary | std::ios::trunc);
			if (!file) {
				std::cerr << "error: cannot open output file '" << outPath << "'\n";
				return 1;
			}
			out = &file;
		}

		// Decrypt sector by sector in a modest buffer.
		const uint64 chunkSectors = 256; // 256 * sectorSize per read
		SecureBuffer buffer(chunkSectors * sectorSize);

		uint64 offset = 0;
		while (offset < alignedToDecrypt) {
			uint64 remaining = alignedToDecrypt - offset;
			uint64 thisLen = remaining < buffer.Size() ? remaining : buffer.Size();
			BufferPtr slice(buffer.Ptr(), (size_t) thisLen);

			volume.ReadSectors(slice, offset);
			out->write(reinterpret_cast<const char *>(buffer.Ptr()), (std::streamsize) thisLen);

			offset += thisLen;
		}

		out->flush();
		std::cerr << "Decrypted " << alignedToDecrypt << " bytes";
		if (!outPath.empty())
			std::cerr << " to '" << outPath << "'";
		std::cerr << ".\n";

		volume.Close();
		return 0;
	}
	catch (PasswordIncorrect &) {
		std::cerr << "error: incorrect password or keyfile(s)"
		          << (hidden ? " (no hidden volume found with these credentials)" : "") << ".\n";
		return 1;
	}
	catch (Exception &e) {
		// TrueCrypt's Exception derives from std::exception; what() is const char*.
		std::cerr << "error: " << (e.what() ? e.what() : "TrueCrypt exception") << "\n";
		return 1;
	}
	catch (std::exception &e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
