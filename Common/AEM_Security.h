#ifndef AEM_SECURITY_H
#define AEM_SECURITY_H

#define AEM_SECURITY_MASTERKEY_LEN 48 // 384-bit, 64 Base64 characters
#define AEM_SECURITY_UAK_LEN 35 // 280-bit

typedef enum : uint8_t {
	// Server: Universal
	AEM_SECURITY_KEYID_SMK_MA_UMK = 0xF0,

	// Server: PostVault
	AEM_SECURITY_KEYID_SMK_PV_PATH = 0x80,
	AEM_SECURITY_KEYID_SMK_PV_FILE = 0x81,

	// User
	AEM_SECURITY_KEYID_UMK_UAK = 0xE0
} aem_security_keyId;

void aem_security_kdf(unsigned char * const target, const size_t lenTarget, const unsigned char masterKey[AEM_SECURITY_MASTERKEY_LEN], const aem_security_keyId keyId);
int aem_security_uid(const unsigned char uak[AEM_SECURITY_UAK_LEN]);

#endif
