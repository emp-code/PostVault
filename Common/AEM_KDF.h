#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

// UMK: last keybyte always zero
#define AEM_KDF_MASTER_KEYLEN 46 // 32 Key + 12 Nonce + 2 Counter (368 bits)
#define AEM_KDF_SUB_KEYLEN 37 // 32 Key + 4 Nonce + 1 Counter (296 bits)

enum {
	// Server: Server Master Key
	AEM_KDF_KEYID_SMK_UMK = 0x01, // Master Admin's UMK

	// 128 for PostVault
	AEM_KDF_KEYID_PV_FILE = (128 | 0x02),
	AEM_KDF_KEYID_PV_PATH = (128 | 0x03),

	// User
	AEM_KDF_KEYID_UMK_UAK = 0x01, // UMK -> User Access Key
	AEM_KDF_KEYID_UAK_UID = 0x01  // UAK -> UserID key
};

void aem_kdf_master(unsigned char * const out, const size_t lenOut, const uint8_t id, const unsigned char key[AEM_KDF_MASTER_KEYLEN]);
void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_SUB_KEYLEN]);

#endif
