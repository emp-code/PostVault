#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const target, const size_t len) {
	toggleEcho(false);
	fprintf(stderr, "Enter key (hex) - will not echo\n");

	char hex[len * 2];
	for (unsigned int i = 0; i < len * 2; i++) {
		const int gc = getchar_unlocked();
		if (!isxdigit(gc)) {toggleEcho(true); return -1;}
		hex[i] = gc;
	}

	sodium_hex2bin(target, len, hex, len * 2, NULL, NULL, NULL);
	sodium_memzero(hex, len * 2);

	toggleEcho(true);
	return 0;
}
