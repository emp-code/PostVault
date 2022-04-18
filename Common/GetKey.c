#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/ToggleEcho.h"

int getKey(unsigned char * const pk, unsigned char * const sk) {
	toggleEcho(false);
	fprintf(stderr, "Enter PostVault Key (hex) - will not echo\n");

	char seedHex[crypto_box_SEEDBYTES * 2];
	for (unsigned int i = 0; i < crypto_box_SEEDBYTES * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		seedHex[i] = gc;
	}

	toggleEcho(true);

	unsigned char seed[crypto_box_SEEDBYTES];
	sodium_hex2bin(seed, crypto_box_SEEDBYTES, seedHex, crypto_box_SEEDBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(seedHex, crypto_box_SEEDBYTES * 2);

	crypto_box_seed_keypair(pk, sk, seed);
	sodium_memzero(seed, crypto_box_SEEDBYTES);
	return 0;
}
