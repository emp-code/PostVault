#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

#define AEM_KDF_SMK_KEYLEN 46 // 32 Key + 12 Nonce + 2 Counter (368 bits)
#define AEM_KDF_UMK_KEYLEN 45 // 32 Key + 12 Nonce + 1 Counter (360 bits)
#define AEM_KDF_SFK_KEYLEN 39 // 312 bits
#define AEM_KDF_UAK_KEYLEN 43 // 338 bits
#define AEM_KDF_MFK_KEYLEN 40 // 320 bits

#define AEM_UAK_POST 64
#define AEM_KDF_PV 128 // Ensure different keys between AEM & PV

// Server
#define AEM_KDF_KEYID_SMK_UMK 1 // Master Admin's UMK

#define AEM_KDF_KEYID_PV_FILE (AEM_KDF_PV | 2)
#define AEM_KDF_KEYID_PV_PATH (AEM_KDF_PV | 3)
#define AEM_KDF_KEYID_PV_SFK  (AEM_KDF_PV | 4)
#define AEM_KDF_KEYID_PV_TIME (AEM_KDF_PV | 5)

// User
#define AEM_KDF_KEYID_UMK_UAK 1 // UMK -> User API Key

// UAK
#define AEM_KDF_UAK_URL 0

void aem_kdf_smk(unsigned char * const out, const size_t lenOut, const uint8_t n, const unsigned char smk[AEM_KDF_SMK_KEYLEN]);
void aem_kdf_sfk       (unsigned char * const out, const size_t lenOut, const uint64_t binTs, const uint16_t uid, const uint32_t chunk, const unsigned char sfk[AEM_KDF_SFK_KEYLEN]);
void aem_kdf_sfk_direct(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const uint16_t uid, const uint32_t chunk, const unsigned char sfk[AEM_KDF_SFK_KEYLEN]);
void aem_kdf_uak(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const bool post, const uint8_t type, const unsigned char uak[AEM_KDF_UAK_KEYLEN]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_UAK_KEYLEN]);

#ifdef AEM_KDF_UMK
void aem_kdf_umk(unsigned char * const out, const size_t lenOut, const uint16_t n, const unsigned char umk[AEM_KDF_UMK_KEYLEN]);
#endif

#endif
