#ifndef PV_IO_H
#define PV_IO_H

#define PV_SOCK_ACCEPT 4
#define PV_SOCK_CLIENT 5

#define PV_BLOCKSIZE 16LL
#define PV_CHUNKSIZE 4194304LL
#define PV_SENDSIZE 1024
#define PV_VERIFY_HASHSIZE 16 // 128-bit

void ioSetup(const unsigned char smk[AEM_KDF_SMK_KEYLEN]);

int checkUserDir(const uint16_t uid);

void respond_putFile(const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t rawSize, uint64_t ts_file);
void respond_getFile(const uint16_t uid, const uint16_t slot, const uint16_t chunk);
void respond_delFile(const uint16_t uid, const uint16_t slot);
void respond_vfyFile(const uint16_t uid, const uint16_t slot, const unsigned char * const verifyKey);

#endif
