#ifndef GPG_DECRYPTOR_H
#define GPG_DECRYPTOR_H

#include <string>

class pgpdecrypt {
public:
    // Initializes GPGME subsystems. Must be called once before decryption.
    static bool initialize();

    // Decrypts a symmetrically encrypted .gpg file to the output path using a passphrase.
    static bool decryptSymmetric(const std::string& inputPath, 
                                 const std::string& outputPath, 
                                 const std::string& passphrase);
};

#endif // GPG_DECRYPTOR_H
