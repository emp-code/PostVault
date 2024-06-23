#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/AEM_KDF.h"

#include "IO.h"

#define PV_PATH_USER_DIR  (char[]){'/','V','/', path_chars[uid & 63], path_chars[(uid >> 6) & 63], '\0'}
#define PV_PATH_USER_FILE (char[]){'/','V','/', path_chars[uid & 63], path_chars[(uid >> 6) & 63], '/', path_chars[64 + (slot & 15)], path_chars[64 + ((slot >> 4) & 15)], path_chars[64 + ((slot >> 8) & 15)], path_chars[64 + ((slot >> 12) & 15)], '\0'}
#define PV_PATHCHARS_COUNT 80
static char path_chars[PV_PATHCHARS_COUNT] = "????????????????????????????????????????????????????????????????????????????????";

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
void ioSetup(const unsigned char smk[AEM_KDF_MASTER_KEYLEN]) {
	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	int total = 0;
	uint64_t done = 0;

	uint8_t src[8192];
	aem_kdf_master(src, 8192, AEM_KDF_KEYID_PV_PATH, smk);

	for (int i = 0; total < PV_PATHCHARS_COUNT; i++) {
		if (total == 64) done = 0;

		src[i] &= 63;
		if (((done >> src[i]) & 1) == 0) {
			path_chars[total] = b64_set[src[i]];
			done |= 1LLU << src[i];
			total++;
		}
	}

	sodium_memzero(src, 8192);
}

int checkUserDir(const uint16_t uid) {
	struct statx s;
	if (statx(0, PV_PATH_USER_DIR, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW, STATX_MTIME, &s) == 0) {
		// TODO Check things
	} else {
		if (errno == ENOENT) {
			if (mkdir(PV_PATH_USER_DIR, S_IRWXU) != 0) return -1;
		} else {
			return -1;
		}
	}

	return 0;
}

static int getFd(const uint16_t uid, const int slot, uint32_t * const fileBlocks, uint64_t * const fileTime, const bool keep) {
	const bool write = (fileBlocks == NULL);
	const int fd = open(PV_PATH_USER_FILE, (write? (O_WRONLY | O_CREAT | (keep? 0 : O_TRUNC)) : O_RDONLY) | O_NOATIME | O_NOCTTY | O_NOFOLLOW, write? (S_IRUSR | S_IWUSR) : 0);
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

static void respondStatus(const bool ok) {
	send(PV_SOCK_CLIENT,
		ok?
			"HTTP/1.1 204 PV\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Connection: close\r\n"
			"\r\n"
		:
			"HTTP/1.1 404 PV\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Connection: close\r\n"
			"\r\n"
		, 70, 0);
}

void respond_addFile(const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t rawSize, uint64_t ts_file, unsigned char xmfk[32]) {
	// Open file
	const int fd = getFd(uid, slot, NULL, keep? &ts_file : NULL, keep);
	if (fd < 0) {puts("Failed getFd"); return;}

	// Receive data
	unsigned char * const raw = malloc(rawSize);
	if (raw == NULL) {
		puts("Failed malloc");
		close(fd);
		return;
	}
	bzero(raw, rawSize);

	size_t received = 0;
	while (received < rawSize) {
		const ssize_t ret = recv(PV_SOCK_CLIENT, raw + received, rawSize - received, 0);

		if (ret < 1) {
			perror("Failed recv");
			free(raw);
			close(fd);
			return;
		}

		received += ret;
	}

	const size_t lenContent = rawSize - 32;
	unsigned char * const content = raw + 32;

	// Encrypt with MFK
	const uint64_t xorNonce = chunk;
	crypto_stream_chacha20_xor(content, content, lenContent, (const unsigned char*)&xorNonce, (unsigned char[]) {
		raw[0]  ^ xmfk[0],  raw[1]  ^ xmfk[1],  raw[2]  ^ xmfk[2],  raw[3]  ^ xmfk[3],  raw[4]  ^ xmfk[4],  raw[5]  ^ xmfk[5],  raw[6]  ^ xmfk[6],  raw[7]  ^ xmfk[7],  raw[8]  ^ xmfk[8],  raw[9]  ^ xmfk[9],
		raw[10] ^ xmfk[10], raw[11] ^ xmfk[11], raw[12] ^ xmfk[12], raw[13] ^ xmfk[13], raw[14] ^ xmfk[14], raw[15] ^ xmfk[15], raw[16] ^ xmfk[16], raw[17] ^ xmfk[17], raw[18] ^ xmfk[18], raw[19] ^ xmfk[19],
		raw[20] ^ xmfk[20], raw[21] ^ xmfk[21], raw[22] ^ xmfk[22], raw[23] ^ xmfk[23], raw[24] ^ xmfk[24], raw[25] ^ xmfk[25], raw[26] ^ xmfk[26], raw[27] ^ xmfk[27], raw[28] ^ xmfk[28], raw[29] ^ xmfk[29],
		raw[30] ^ xmfk[30], raw[31] ^ xmfk[31]
	});

	// Write
	if (pwrite(fd, content, lenContent, chunk * PV_CHUNKSIZE) != (off_t)lenContent) {
		perror("Failed writing file");
		free(raw);
		close(fd);
		respondStatus(false);
		return;
	}

	free(raw);

	// Set filesystem times
	struct timespec t[2];
	t[0].tv_sec = 0;
	t[0].tv_nsec = UTIME_OMIT;

	t[1].tv_sec = PV_TS_BASE + ((ts_file - (ts_file % 1000)) / 1000);
	t[1].tv_nsec = ts_file % 1000;

	if (futimens(fd, t) != 0) {
		perror("Failed futimens");
		close(fd);
		respondStatus(false);
		return;
	}

	// Finish
	close(fd);
	respondStatus(true);
}

static void setSlots(const uint16_t uid, unsigned char * const s) {
	bzero(s, 8192);

	for (uint16_t slot = 0; slot < UINT16_MAX; slot++) {
		const int fd = open(PV_PATH_USER_FILE, O_RDONLY | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
		if (fd == -1) continue;

		s[(slot - (slot % 8)) / 8] |= 1 << (slot % 8);
		close(fd);
	}
}

void respond_getFile(const uint16_t uid, const uint16_t slot, const uint16_t chunk) {
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

	const size_t lenRead = MIN(PV_CHUNKSIZE, (fileBlocks * PV_BLOCKSIZE) - startOffset);
	const size_t lenRaw = ((slot == 0) ? 8201 : 9) + lenRead;
	const size_t lenHeaders = 88 + numberOfDigits(lenRaw);
	const size_t lenResponse = lenHeaders + lenRaw;
	unsigned char * const response = malloc(lenResponse);

	sprintf((char*)response,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, lenRaw);

	const ssize_t bytesRead = pread(fd, response + lenHeaders + 9, lenRead, startOffset);
	close(fd);

	if (bytesRead != (ssize_t)lenRead) {
		printf("Failed reading file: %ld != %ld\n", bytesRead, lenRead);
		free(response);
		return;
	}

	memcpy(response + lenHeaders, (unsigned char*)&fileTime, 5);
	memcpy(response + lenHeaders + 5, (unsigned char*)&fileBlocks, 4);
	if (slot == 0) setSlots(uid, response + lenResponse - 8192);

	size_t sent = 0;
	while (sent + PV_SENDSIZE < lenResponse) {
		const ssize_t ret = send(PV_SOCK_CLIENT, response + sent, PV_SENDSIZE, MSG_MORE);
		if (ret != PV_SENDSIZE) {
			puts("Failed sending");
			break;
		}
		sent += ret;
	}

	if (send(PV_SOCK_CLIENT, response + sent, lenResponse - sent, 0) != (ssize_t)(lenResponse - sent)) puts("Failed sending");
	free(response);
}

void respond_delFile(const uint16_t uid, const uint16_t slot) {
	respondStatus((unlink(PV_PATH_USER_FILE) == 0) ? true : false);
}

static int64_t div_floor(const long long a, const long long b) {
	return (a - (a % b)) / b;
}

void respond_vfyFile(const uint16_t uid, const uint16_t slot, const unsigned char * const verifyKey) {
	uint64_t fileTime;
	uint32_t blocks;
	const int fd = getFd(uid, slot, &blocks, &fileTime, false);
	if (fd < 0) {respondStatus(false); return;}

	const int chunks = div_floor(blocks * PV_BLOCKSIZE, PV_CHUNKSIZE) + 1;
	unsigned char * const chunkData = malloc(PV_CHUNKSIZE);
	if (chunkData == NULL) {close(fd); respondStatus(false); return;}

	const ssize_t lenResp = 5 + (chunks * PV_VERIFY_HASHSIZE);
	unsigned char resp[lenResp];
	memcpy(resp, &fileTime, 5);

	for (int i = 0; i < chunks; i++) {
		const ssize_t lenChunk = (i + 1 == chunks) ? (blocks * PV_BLOCKSIZE) - (i * PV_CHUNKSIZE) : PV_CHUNKSIZE;
		if (pread(fd, chunkData, lenChunk, i * PV_CHUNKSIZE) != lenChunk) {close(fd); free(chunkData); respondStatus(false); return;}
		crypto_generichash(resp + 5 + (i * PV_VERIFY_HASHSIZE), PV_VERIFY_HASHSIZE, chunkData, lenChunk, verifyKey, 32);
	}

	free(chunkData);
	close(fd);

	unsigned char hdr[512];
	sprintf((char*)hdr,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, lenResp);
	send(PV_SOCK_CLIENT, hdr, strlen((const char * const)hdr), MSG_MORE);

	for (ssize_t sent = 0; sent < lenResp;) {
		if (sent + PV_SENDSIZE >= lenResp) {
			if (send(PV_SOCK_CLIENT, resp + sent, lenResp - sent, 0) != (lenResp - sent)) puts("Failed sending");
			break;
		} else {
			const off_t ret = send(PV_SOCK_CLIENT, resp + sent, PV_SENDSIZE, MSG_MORE);

			if (ret != PV_SENDSIZE) {
				puts("Failed sending");
				break;
			}

			sent += ret;
		}
	}
}
