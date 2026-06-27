/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Crypto_Aes_Hw_Cpu
#define TC_HEADER_Crypto_Aes_Hw_Cpu

#include "Common/Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/* Use unsigned char rather than the `byte` typedef here: in C++17 a
   translation unit that pulled in `using namespace std;` (Platform/PlatformBase.h)
   sees both the global TrueCrypt `byte` and `std::byte`, making the bare name
   ambiguous. `byte` is an unsigned char on every supported platform, so this is
   an equivalent, ambiguity-free declaration. */
unsigned char is_aes_hw_cpu_supported ();
void aes_hw_cpu_enable_sse ();
void aes_hw_cpu_decrypt (const unsigned char *ks, unsigned char *data);
void aes_hw_cpu_decrypt_32_blocks (const unsigned char *ks, unsigned char *data);
void aes_hw_cpu_encrypt (const unsigned char *ks, unsigned char *data);
void aes_hw_cpu_encrypt_32_blocks (const unsigned char *ks, unsigned char *data);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_Aes_Hw_Cpu
