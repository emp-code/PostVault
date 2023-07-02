#ifndef PV_IO_H
#define PV_IO_H

void ioSetup(const unsigned char pathKey[crypto_kdf_KEYBYTES]);

int checkUserDir(const uint16_t uid);

void respond_addFile(const int sock, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES], const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t boxSize, uint64_t ts_file);
void respond_getFile(const int sock, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES], const uint16_t uid, const uint16_t slot, const uint16_t chunk);
void respond_delFile(const int sock, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES], const uint16_t uid, const uint16_t slot);

#endif
