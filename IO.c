#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/aes.h"

#include "IO.h"

#define PV_USERDIR_PATH (char[]){'/', path_chars[uid & 63], path_chars[(uid >> 6) & 63], '\0'}
#define PV_USERFILE_PATH (char[]){'/', path_chars[uid & 63], path_chars[(uid >> 6) & 63], '/', path_chars[64 + (slot & 15)], path_chars[64 + ((slot >> 4) & 15)], path_chars[64 + ((slot >> 8) & 15)], path_chars[64 + ((slot >> 12) & 15)], '\0'}

#define PV_PATHCHARS_COUNT 80
static char path_chars[PV_PATHCHARS_COUNT] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+0123456789abcdef";

static int numberOfDigits(const size_t x) {
	return
		(x < 10 ? 1 :
		(x < 100 ? 2 :
		(x < 1000 ? 3 :
		(x < 10000 ? 4 :
		(x < 100000 ? 5 :
		(x < 1000000 ? 6 :
		(x < 10000000 ? 7 :
		(x < 100000000 ? 8 :
		(x < 1000000000 ? 9 :
		10)))))))));
}

// Shuffles the encoded character set based on the key
void ioSetup(const unsigned char pathKey[PV_PATHKEY_LEN]) {
	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	int total = 0;
	uint64_t done = 0;

	for (uint8_t i = 0; total < PV_PATHCHARS_COUNT; i++) {
		if (total == 64) done = 0;

		uint8_t val[32];
		crypto_generichash(val, 32, &i, 1, pathKey, PV_PATHKEY_LEN);

		for (int j = 0; j < 32; j++) {
			val[j] &= 63;

			if (((done >> val[j]) & 1) == 0) {
				path_chars[total] = b64_set[val[j]];
				done |= (uint64_t)1 << val[j];
				total++;
				if (total == 64 || total == PV_PATHCHARS_COUNT) break;
			}
		}
	}
}

int checkUserDir(const uint16_t uid) {
	struct statx s;
	if (statx(0, PV_USERDIR_PATH, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW, STATX_MTIME, &s) == 0) {
		// TODO Check things
	} else {
		if (errno == ENOENT) {
			if (mkdir(PV_USERDIR_PATH, S_IRWXU) != 0) return -1;
		} else {
			return -1;
		}
	}

	return 0;
}

static int getFd(const uint16_t uid, const int slot, uint32_t * const fileBlocks, uint64_t * const fileTime, const bool keep) {
	const bool write = (fileBlocks == NULL);
	const int fd = open(PV_USERFILE_PATH, (write? (O_WRONLY | O_CREAT | (keep? 0 : O_TRUNC)) : O_RDONLY) | O_NOATIME | O_NOCTTY | O_NOFOLLOW, write? (S_IRUSR | S_IWUSR) : 0);
	if (fd < 0) {perror("Failed opening file"); return -1;}

	struct statx s;
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MTIME | STATX_SIZE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID, &s) != 0) {
		close(fd);
		puts("statx() failed");
		return -1;
	}

	if (!write && (
	   s.stx_size < PV_BLOCKSIZE
	|| s.stx_size / PV_BLOCKSIZE > UINT32_MAX
	|| s.stx_size % PV_BLOCKSIZE != 0
	|| s.stx_mtime.tv_sec < PV_TS_BASE
	|| s.stx_mtime.tv_sec > PV_TS_BASE + PV_TS_MAX
	|| s.stx_mtime.tv_nsec > 999
	)) {
		close(fd);
		puts("Invalid file attributes");
		return -1;
	}

	if (fileBlocks != NULL) *fileBlocks = s.stx_size / PV_BLOCKSIZE;
	if (fileTime != NULL && s.stx_size != 0) *fileTime = ((s.stx_mtime.tv_sec - PV_TS_BASE) * 1000) + s.stx_mtime.tv_nsec;

	return fd;
}

static void respondStatus(const int sock, const bool ok) {
	send(sock,
		ok?
			"HTTP/1.1 204 PV\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Connection: close\r\n"
			"\r\n"
		:
			"HTTP/1.1 204 pv\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Connection: close\r\n"
			"\r\n"	
		, 70, 0);
}

static void mfk_encrypt(unsigned char * const src, const unsigned int blockCount, const unsigned char mfk[PV_MFK_LEN]) {
	unsigned char n[16];
	bzero(n, 16);

	struct AES_ctx aes;
	AES_init_ctx_iv(&aes, mfk, n);
	AES_CTR_xcrypt_buffer(&aes, src, 16);

	// Use first block as IV for the rest of the file
	AES_init_ctx_iv(&aes, mfk, src);
	AES_CTR_xcrypt_buffer(&aes, src + 16, (blockCount * PV_BLOCKSIZE) - 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));
}

void respond_addFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t rawSize, uint64_t ts_file, unsigned char xmfk[32]) {
	const int fd = getFd(uid, slot, NULL, keep? &ts_file : NULL, keep);
	if (fd < 0) {puts("Failed getFd"); return;}

	unsigned char * const raw = malloc(rawSize);
	if (raw == NULL) {
		puts("Failed malloc");
		close(fd);
		return;
	}
	bzero(raw, rawSize);

	size_t received = 0;
	while (received < rawSize) {
		const ssize_t ret = recv(sock, raw + received, rawSize - received, 0);
		if (ret < 0) {
			perror("Failed recv");
			free(raw);
			close(fd);
			return;
		}

		received += ret;
	}

	const size_t lenContent = rawSize - PV_MFK_LEN;
	unsigned char * const content = raw + PV_MFK_LEN;

	mfk_encrypt(content, lenContent / PV_BLOCKSIZE, (unsigned char[]) {
		raw[0]  ^ xmfk[0],  raw[1]  ^ xmfk[1],  raw[2]  ^ xmfk[2],  raw[3]  ^ xmfk[3],  raw[4]  ^ xmfk[4],  raw[5]  ^ xmfk[5],  raw[6]  ^ xmfk[6],  raw[7]  ^ xmfk[7],  raw[8]  ^ xmfk[8],  raw[9]  ^ xmfk[9],
		raw[10] ^ xmfk[10], raw[11] ^ xmfk[11], raw[12] ^ xmfk[12], raw[13] ^ xmfk[13], raw[14] ^ xmfk[14], raw[15] ^ xmfk[15], raw[16] ^ xmfk[16], raw[17] ^ xmfk[17], raw[18] ^ xmfk[18], raw[19] ^ xmfk[19],
		raw[20] ^ xmfk[20], raw[21] ^ xmfk[21], raw[22] ^ xmfk[22], raw[23] ^ xmfk[23], raw[24] ^ xmfk[24], raw[25] ^ xmfk[25], raw[26] ^ xmfk[26], raw[27] ^ xmfk[27], raw[28] ^ xmfk[28], raw[29] ^ xmfk[29],
		raw[30] ^ xmfk[30], raw[31] ^ xmfk[31]
	});

	if (pwrite(fd, content, lenContent, chunk * PV_CHUNKSIZE) != (off_t)lenContent) {
		perror("Failed writing file");
		free(raw);
		close(fd);
		respondStatus(sock, false);
		return;
	}

	free(raw);

	struct timespec t[2];
	t[0].tv_sec = 0;
	t[0].tv_nsec = UTIME_OMIT;

	t[1].tv_sec = PV_TS_BASE + ((ts_file - (ts_file % 1000)) / 1000);
	t[1].tv_nsec = ts_file % 1000;

	if (futimens(fd, t) != 0) {
		perror("Failed futimens");
		close(fd);
		respondStatus(sock, false);
		return;
	}

	close(fd);
	respondStatus(sock, true);
}

void respond_getFile(const int sock, const uint16_t uid, const uint16_t slot, const uint16_t chunk) {
	uint64_t fileTime;
	uint32_t fileBlocks;
	const int fd = getFd(uid, slot, &fileBlocks, &fileTime, false);
	if (fd < 0) return;

	const size_t startOffset = chunk * PV_CHUNKSIZE;
	if (startOffset > fileBlocks * PV_BLOCKSIZE) {
		puts("Invalid size");
		close(fd);
		return;
	}

	const off_t lenMax = (fileBlocks * PV_BLOCKSIZE) - startOffset;
	const off_t lenRead = (lenMax > PV_CHUNKSIZE) ? PV_CHUNKSIZE : lenMax;
	const size_t lenRaw = 9 + lenRead;
	unsigned char * const rawData = malloc(lenRaw);

	const off_t bytesRead = pread(fd, rawData + 9, lenRead, startOffset);
	close(fd);

	if (bytesRead != lenRead) {
		printf("Failed reading file: %ld != %ld\n", bytesRead, lenRead);
		free(rawData);
		return;
	}

	memcpy(rawData, (unsigned char*)&fileTime, 5);
	memcpy(rawData + 5, (unsigned char*)&fileBlocks, 4);

	const size_t lenHeaders = 88 + numberOfDigits(lenRaw);
	unsigned char * const response = malloc(lenHeaders + lenRaw);

	sprintf((char*)response,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, lenRaw);

	memcpy(response + lenHeaders, rawData, lenRaw);
	free(rawData);

	for (size_t sent = 0; sent < lenHeaders + lenRaw;) {
		if (sent + PV_SENDSIZE >= lenHeaders + lenRaw) {
			if (send(sock, response + sent, lenHeaders + lenRaw - sent, 0) != (ssize_t)(lenHeaders + lenRaw - sent)) puts("Failed sending");
			break;
		} else {
			const off_t ret = send(sock, response + sent, PV_SENDSIZE, MSG_MORE);

			if (ret != PV_SENDSIZE) {
				puts("Failed sending");
				break;
			}

			sent += ret;
		}
	}

	free(response);
}

void respond_delFile(const int sock, const uint16_t uid, const uint16_t slot) {
	respondStatus(sock, (unlink(PV_USERFILE_PATH) == 0) ? true : false);
}
