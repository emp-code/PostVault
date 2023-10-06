#ifndef AEM_SECURITY_H
#define AEM_SECURITY_H

#define AEM_SECURITY_MASTERKEY_LEN 48 // 384-bit, 64 Base64 characters
#define AEM_SECURITY_UAK_LEN 32

typedef enum : uint8_t {
	AEM_SECURITY_KEYID_SERVER_MA_UMK,
	AEM_SECURITY_KEYID_SERVER_FILE,
	AEM_SECURITY_KEYID_SERVER_PATH,
	AEM_SECURITY_KEYID_SERVER_API,

	AEM_SEUCRITY_KEYID_THRESHOLD_USER,
	AEM_SECURITY_KEYID_USER_UAK
} aem_security_keyId;

void aem_security_kdf(unsigned char * const target, const size_t lenTarget, const unsigned char masterKey[AEM_SECURITY_MASTERKEY_LEN], const aem_security_keyId keyId);
int aem_security_uid(const unsigned char uak[AEM_SECURITY_UAK_LEN]);

#endif
