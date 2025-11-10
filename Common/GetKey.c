#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const smk) {
	toggleEcho(false);
	fprintf(stderr, "Enter the Server Master Key (SMK) in hex - will not echo\n");

	char smkHex[AEM_KDF_SMK_KEYLEN * 2];
	for (unsigned int i = 0; i < AEM_KDF_SMK_KEYLEN * 2; i++) {
		const int gc = getchar_unlocked();
		if (!isxdigit(gc)) {toggleEcho(true); return -1;}
		smkHex[i] = gc;
	}

	sodium_hex2bin(smk, AEM_KDF_SMK_KEYLEN, smkHex, AEM_KDF_SMK_KEYLEN * 2, NULL, NULL, NULL);
	sodium_memzero(smkHex, AEM_KDF_SMK_KEYLEN * 2);

	toggleEcho(true);
	return 0;
}
