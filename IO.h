#ifndef PV_IO_H
#define PV_IO_H

// Allow compiling on libsodium <1.0.19
#ifndef crypto_aead_aegis256_ABYTES
	#warning Missing AEGIS-256 support
	#define crypto_aead_aegis256_ABYTES    crypto_aead_chacha20poly1305_ABYTES
	#define crypto_aead_aegis256_KEYBYTES  crypto_aead_chacha20poly1305_KEYBYTES
	#define crypto_aead_aegis256_NPUBBYTES crypto_aead_chacha20poly1305_NPUBBYTES
	#define crypto_aead_aegis256_decrypt   crypto_aead_chacha20poly1305_decrypt
	#define crypto_aead_aegis256_encrypt   crypto_aead_chacha20poly1305_encrypt
#endif

#define PV_TS_BASE 946684800 // 2020-01-01 00:00:00
#define PV_TS_MAX  1099511627
#define PV_BLOCKSIZE 16
#define PV_CHUNKSIZE 16777216
#define PV_SENDSIZE 1024
#define PV_MFK_LEN 32 // AES-256

void ioSetup(const unsigned char pathKey[crypto_kdf_KEYBYTES]);

int checkUserDir(const uint16_t uid);

void respond_addFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t encSize, uint64_t ts_file, const unsigned char bodyKey[crypto_aead_aegis256_KEYBYTES], const unsigned char responseKey[1 + crypto_onetimeauth_KEYBYTES]);
void respond_getFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk, const unsigned char responseKey[crypto_aead_aegis256_KEYBYTES]);
void respond_delFile(const int sock, const uint16_t uid, const uint16_t slot, const unsigned char responseKey[1 + crypto_onetimeauth_KEYBYTES]);

#endif
