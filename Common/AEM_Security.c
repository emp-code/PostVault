#include <sodium.h>

#include "AEM_Security.h"

void aem_security_kdf(unsigned char * const target, const size_t lenTarget, const unsigned char masterKey[AEM_SECURITY_MASTERKEY_LEN], const aem_security_keyId keyId) {
	crypto_generichash(target, lenTarget, (const unsigned char * const)&keyId, 1, masterKey, AEM_SECURITY_MASTERKEY_LEN);
}

int aem_security_uid(const unsigned char uak[AEM_SECURITY_UAK_LEN]) {
	uint16_t uid_base[8];
	crypto_generichash((unsigned char * const)uid_base, 16, (const unsigned char * const)"UserID", 6, uak, AEM_SECURITY_UAK_LEN);
	return uid_base[0] & 4095;
}
