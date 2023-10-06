#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const target, const size_t len) {
	toggleEcho(false);
	fprintf(stderr, "Enter key (Base64) - will not echo\n");

	char b64[sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL) - 1];
	for (unsigned int i = 0; i < sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL) - 1; i++) {
		const int gc = getchar_unlocked();
		if (!isalnum(gc) && gc != '/' && gc != '+') {toggleEcho(true); return -1;}
		b64[i] = gc;
	}

	sodium_base642bin(target, len, b64, sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL) - 1, NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
	sodium_memzero(b64, sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL) - 1);

	toggleEcho(true);
	return 0;
}
