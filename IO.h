#ifndef PV_IO_H
#define PV_IO_H

void ioSetup(const unsigned char pathKey[crypto_kdf_KEYBYTES]);

int checkUserDir(const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES]);

void respond_addFile(const int sock, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, const int chunk, const unsigned char mfk[32], const bool replace, const size_t boxSize, const uint64_t ts, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]);
void respond_getFile(const int sock, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, const unsigned int chunk, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]);
void respond_delFile(const int sock, const int slot, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]);

#endif
