#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
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

#define PV_TS_BASE 946684800 // 2020-01-01 00:00:00
#define PV_TS_MAX  1099511627
#define PV_BLOCKSIZE 16
#define PV_CHUNKSIZE 16777216
#define PV_SENDSIZE 1024
#define PV_PATH_USERDIR_LENGTH 65
#define PV_PATH_USERFILE_LENGTH (PV_PATH_USERDIR_LENGTH + 4)

static unsigned char pathKey[crypto_kdf_KEYBYTES];
static char b64_chars[64];

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

// Generates the Base64 character set, shuffled based on the key
void ioSetup(const unsigned char * const newPathKey) {
	memcpy(pathKey, newPathKey, crypto_kdf_KEYBYTES);

	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	int total = 0;
	uint64_t done = 0;

	for (int i = 0; total < 64; i++) {
		uint8_t val[32];
		crypto_kdf_derive_from_key(val, 32, i, "PV:Path1", pathKey);

		for (int j = 0; j < 32; j++) {
			val[j] &= 63;

			if (((done >> val[j]) & 1) == 0) {
				b64_chars[total] = b64_set[val[j]];
				done |= (uint64_t)1 << val[j];
				total++;
			}
		}
	}
}

static int getPath(const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, char * const out) {
	unsigned char path_key[crypto_box_PUBLICKEYBYTES];
	crypto_kdf_derive_from_key(path_key, crypto_box_PUBLICKEYBYTES, 1, "PV:Path2", pathKey);

	memcpy(out, "/var/lib/PostVault/User/", 24);

	for (int i = 0; i < 11; i++) {
		union {
			uint32_t u32;
			uint8_t u8[4];
		} u;

		int offset;
		if (i == 10) {
			if (slot < 0 || slot > UINT8_MAX) {
				out[PV_PATH_USERDIR_LENGTH - 1] = '\0';
				return 0;
			}

			out[PV_PATH_USERDIR_LENGTH - 1] = '/';

			offset = 25;
			u.u8[0] = slot;
			u.u8[1] = uak[31] ^ path_key[31];
			u.u8[2] = uak[30] ^ path_key[30];
		} else {
			offset = 24;
			u.u8[0] = uak[(i * 3) + 2] ^ path_key[(i * 3) + 2];
			u.u8[1] = uak[(i * 3) + 1] ^ path_key[(i * 3) + 1];
			u.u8[2] = uak[(i * 3) + 0] ^ path_key[(i * 3) + 0];
		}

		out[offset + (i * 4) + 0] = b64_chars[(u.u32 >> 18) & 63];
		out[offset + (i * 4) + 1] = b64_chars[(u.u32 >> 12) & 63];
		out[offset + (i * 4) + 2] = b64_chars[(u.u32 >>  6) & 63];
		out[offset + (i * 4) + 3] = b64_chars[(u.u32 >>  0) & 63];
	}

	out[PV_PATH_USERFILE_LENGTH] = '\0';
	return 0;
}

int checkUserDir(const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES]) {
	char path[PV_PATH_USERDIR_LENGTH + 1];
	if (getPath(uak, -1, path) != 0) {puts("getPath() failed"); return -1;}

	struct statx s;
	if (statx(0, path, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW, STATX_MTIME, &s) == 0) {
		// TODO Check things
	} else {
		if (errno == ENOENT) {
			if (mkdir(path, S_IRWXU) != 0) return -1;
		} else {
			return -1;
		}
	}

	return 0;
}

static int getFd(const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, uint32_t * const fileBlocks, uint64_t * const fileTime, const bool replace) {
	char path[PV_PATH_USERFILE_LENGTH + 1];
	if (getPath(uak, slot, path) != 0) {puts("getPath() failed"); return -1;}

	const bool write = (fileBlocks == NULL);
	const int fd = open(path, (write? (O_WRONLY | O_CREAT | (replace? O_TRUNC : 0)) : O_RDONLY) | O_NOATIME | O_NOCTTY | O_NOFOLLOW, write? (S_IRUSR | S_IWUSR) : 0);
	if (fd < 0) {puts("Failed opening file"); return -1;}

	struct statx s;
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MTIME | STATX_SIZE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID, &s) != 0) {
		close(fd);
		puts("statx() failed");
		return -1;
	}

	if (!write && (
	   s.stx_size < PV_BLOCKSIZE
	|| s.stx_size / PV_BLOCKSIZE > 268435456 // 2^28
	|| s.stx_size % PV_BLOCKSIZE != 0
	|| s.stx_mtime.tv_sec < PV_TS_BASE
	|| s.stx_mtime.tv_sec > PV_TS_BASE + PV_TS_MAX
	|| s.stx_mtime.tv_nsec > 999
	)) {
		close(fd);
		printf("Invalid attributes on file %s\n", path);
		return -1;
	}

	if (fileBlocks != NULL) *fileBlocks = s.stx_size / PV_BLOCKSIZE;
	*fileTime = ((s.stx_mtime.tv_sec - PV_TS_BASE) * 1000) + s.stx_mtime.tv_nsec;

	return fd;
}

static void respondStatus(const int sock, const unsigned char status, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]) {
	unsigned char response[96 + crypto_box_MACBYTES];

	memcpy(response,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: 22\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n", 90);

	unsigned char raw[6];
	bzero(raw, 5);
	raw[5] = status;

	unsigned char box_nonce[crypto_box_NONCEBYTES];
	memset(box_nonce, 0xFF, crypto_box_NONCEBYTES);

	if (crypto_box_easy(response + 90, raw, 6, box_nonce, box_pk, box_sk) == 0)
		send(sock, response, sizeof(response), 0);
}

static void mfk_encrypt(unsigned char * const src, const int blockCount, const unsigned char mfk[32]) {
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

void respond_addFile(const int sock, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, const int chunk, const unsigned char mfk[32], const bool replace, const size_t boxSize, const uint64_t ts, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]) {
	const size_t contentSize = boxSize - crypto_box_MACBYTES;
	if (contentSize < PV_BLOCKSIZE || (contentSize % PV_BLOCKSIZE) != 0 || contentSize > PV_CHUNKSIZE || chunk < 0 || chunk > 255) {printf("Invalid size: %zu\n", contentSize); return;}

	uint64_t oldTs;
	const int fd = getFd(uak, slot, NULL, &oldTs, replace);
	if (fd < 0) {perror("fd failed"); return;}

	unsigned char * const box = malloc(boxSize);
	if (box == NULL) {
		close(fd);
		return;
	}

	unsigned char * const content = malloc(contentSize);
	if (content == NULL) {
		free(box);
		close(fd);
		return;
	}

	size_t received = 0;
	while (received < boxSize) {
		const ssize_t ret = recv(sock, box + received, boxSize - received, 0);
		if (ret < 0) {
			free(box);
			free(content);
			close(fd);
			return;
		}

		received += ret;
	}

	unsigned char box_nonce[crypto_box_NONCEBYTES];
	memset(box_nonce, 2, crypto_box_NONCEBYTES);
	if (crypto_box_open_easy(content, box, boxSize, box_nonce, box_pk, box_sk) != 0) {
		puts("Failed opening postbox");
		return;
	}

	free(box);
	mfk_encrypt(content, contentSize / PV_BLOCKSIZE, mfk);

	if (pwrite(fd, content, contentSize, chunk * PV_CHUNKSIZE) != (off_t)contentSize) {
		close(fd);
		free(content);
		puts("Failed writing file");
		return;
	}

	free(content);

	struct timespec t[2];
	t[0].tv_sec = 0;
	t[0].tv_nsec = UTIME_OMIT;

	const uint64_t ts_file = replace? ts : oldTs;
	t[1].tv_sec = PV_TS_BASE + ((ts_file - (ts_file % 1000)) / 1000);
	t[1].tv_nsec = ts_file % 1000;

	if (futimens(fd, t) != 0) {
		perror("futimens");
		close(fd);
		respondStatus(sock, 1, box_pk, box_sk);
	}

	close(fd);
	respondStatus(sock, 0, box_pk, box_sk);
}

void respond_getFile(const int sock, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const int slot, const unsigned int chunk, const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]) {
	uint64_t fileTime;
	uint32_t fileBlocks;
	const int fd = getFd(uak, slot, &fileBlocks, &fileTime, false);
	if (fd < 0) return;

	if (chunk * PV_CHUNKSIZE > fileBlocks * PV_BLOCKSIZE) {
		puts("Invalid size");
		return;
	}

	const off_t lenMax = (fileBlocks * PV_BLOCKSIZE) - (chunk * PV_CHUNKSIZE);
	const off_t lenRead = (lenMax > PV_CHUNKSIZE) ? PV_CHUNKSIZE : lenMax;
	const size_t lenRaw = 14 + lenRead;
	unsigned char * const rawData = malloc(lenRaw);

	const off_t bytesRead = pread(fd, rawData + 14, lenRead, chunk * PV_CHUNKSIZE);
	close(fd);

	if (bytesRead != lenRead) {
		printf("Failed reading file: %ld != %ld\n", bytesRead, lenRead);
		free(rawData);
		return;
	}

	memset(rawData, 0x00, 5); // TODO: LastMod
	memcpy(rawData + 5, (unsigned char*)&fileTime, 5);
	memcpy(rawData + 10, (unsigned char*)&fileBlocks, 4);

	const size_t lenEnc = lenRaw + crypto_box_MACBYTES;
	const size_t lenHeaders = 88 + numberOfDigits(lenEnc);
	unsigned char * const response = malloc(lenHeaders + lenEnc);
	memset(response, 0xFF, lenHeaders + lenEnc);

	sprintf((char*)response,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, lenEnc);

	unsigned char box_nonce[crypto_box_NONCEBYTES];
	memset(box_nonce, 0xFF, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + lenHeaders, rawData, lenRaw, box_nonce, box_pk, box_sk) != 0) {
		free(rawData);
		free(response);
		return;
	}

	free(rawData);

	for (size_t sent = 0; sent < lenHeaders + lenEnc;) {
		usleep(1); // Seems to fix connection reset errors

		if (sent + PV_SENDSIZE >= lenHeaders + lenEnc) {
			if (send(sock, response + sent, lenHeaders + lenEnc - sent, 0) != (ssize_t)(lenHeaders + lenEnc - sent)) puts("Failed sending");
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

void respond_delFile(const int sock, const int slot, const unsigned char uak[crypto_aead_aes256gcm_KEYBYTES], const unsigned char box_pk[crypto_box_PUBLICKEYBYTES], const unsigned char box_sk[crypto_box_SECRETKEYBYTES]) {
	char path[PV_PATH_USERFILE_LENGTH + 1];
	const unsigned char ret = (getPath(uak, slot, path) == 0 && unlink(path) == 0) ? 0 : 0xFF;
	respondStatus(sock, ret, box_pk, box_sk);
}
