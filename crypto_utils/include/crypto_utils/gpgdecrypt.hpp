#ifndef GPG_DECRYPTOR_H
#define GPG_DECRYPTOR_H

#include <string>

class pgputil {
public:
    enum class PgpContainerType {
        NotPgpOrInvalid,
        Symmetric,
        Asymmetric,
        UnknownError
    };

    // Initializes GPGME subsystems. Must be called once before using.
    static bool initialize();

    // Decrypts a symmetrically encrypted .gpg file to the output path using a passphrase.
    static bool decryptSymmetric(const std::string& inputPath, 
                                 const std::string& outputPath, 
                                 const std::string& passphrase);

    static PgpContainerType analyzePgpEncryption(const std::string& filePath);
};

#endif // GPG_DECRYPTOR_H
