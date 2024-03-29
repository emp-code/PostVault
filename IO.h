#ifndef PV_IO_H
#define PV_IO_H

#define PV_TS_BASE 946684800 // 2000-01-01 00:00:00
#define PV_TS_MAX  1099511627
#define PV_BLOCKSIZE 16LL
#define PV_CHUNKSIZE 16777216LL
#define PV_SENDSIZE 1024
#define PV_MFK_LEN 32 // AES-256
#define PV_PATHKEY_LEN 32

void ioSetup(const unsigned char pathKey[PV_PATHKEY_LEN]);

int checkUserDir(const uint16_t uid);

void respond_addFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t rawSize, uint64_t ts_file, unsigned char xmfk[32]);
void respond_getFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk);
void respond_delFile(const int sock, const uint16_t uid, const uint16_t slot);

#endif
