#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/AEM_KDF.h"
#include "Common/binTs.h"

#include "IO.h"

#define PV_SLOT_INDEX 0

#define PV_PATH_USER_DIR  (char[]){'/','V','/', path_chars[(uid >> 6) & 63], path_chars[uid & 63], '\0'}
#define PV_PATH_USER_FILE (char[]){'/','V','/', path_chars[(uid >> 6) & 63], path_chars[uid & 63], '/', path_chars[64 + ((slot >> 12) & 63)], path_chars[64 + ((slot >> 6) & 63)], path_chars[64 + (slot & 63)], '\0'}
#define PV_PATHCHARS_COUNT 128
__attribute__((nonstring)) static char path_chars[PV_PATHCHARS_COUNT] = "????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";

unsigned char fmk[AEM_KDF_FMK_KEYLEN];

static long long div_floor(const long long a, const long long b) {
	return (a - (a % b)) / b;
}

static long long div_ceil(const long long a, const long long b) {
	return (a % b == 0) ? a / b : div_floor(a, b) + 1;
}

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
void ioSetup(const unsigned char smk[AEM_KDF_SMK_KEYLEN]) {
	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	int total = 0;
	uint64_t done = 0;

	uint8_t src[8192];
	aem_kdf_smk(src, 8192, AEM_KDF_KEYID_PV_PATH, smk);

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

	aem_kdf_smk(fmk, AEM_KDF_FMK_KEYLEN, AEM_KDF_KEYID_PV_FMK, smk);
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

static int getFd(const uint16_t uid, const int slot, size_t * const bytes, uint64_t * const binTs, const bool keep) {
	const bool write = (bytes == NULL);
	const int fd = open(PV_PATH_USER_FILE, (write? (O_WRONLY | O_CREAT | (keep? 0 : O_TRUNC)) : O_RDONLY) | O_NOATIME | O_NOCTTY | O_NOFOLLOW, write? (S_IRUSR | S_IWUSR) : 0);
	if (fd < 0) {printf("Failed opening file %s: %m [%s]\n", PV_PATH_USER_FILE, write? "w" : "r"); return -1;}

	struct statx s;
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MTIME | STATX_SIZE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID, &s) != 0) {
		close(fd);
		puts("statx() failed");
		return -1;
	}

	if (!write && (
	   s.stx_mtime.tv_sec < div_floor(AEM_BINTS_BEGIN, 1000)
	|| s.stx_mtime.tv_sec > div_floor(AEM_BINTS_BEGIN + AEM_BINTS_MAX, 1000)
	)) {
		close(fd);
		puts("Invalid file attributes");
		return -1;
	}

	if (bytes != NULL) *bytes = s.stx_size;
	if (binTs != NULL && s.stx_size != 0) *binTs = (s.stx_mtime.tv_sec * 1000) + (s.stx_mtime.tv_nsec / 1000000) - AEM_BINTS_BEGIN;

	return fd;
}

static void respondStatus(const bool ok) {
	send(PV_SOCK_CLIENT,
		(unsigned char[]){'H','T','T','P','/','1','.','0',' ','2','0',ok? '4' : '5',' ', 'P', 'V' ,'\r','\n',
		'A','c','c','e','s','s','-','C','o','n','t','r','o','l','-','A','l','l','o','w','-','O','r','i','g','i','n',':',' ','*','\r','\n',
		'C','o','n','t','e','n','t','-','l','e','n','g','t','h',':',' ','0','\r','\n',
		'\r','\n'}
	, 70, 0);
}

void respond_putFile(const uint16_t uid, const uint16_t slot, const uint16_t chunk, const bool keep, const size_t rawSize, uint64_t binTs) {
	// Open file
	const int fd = getFd(uid, slot, NULL, keep? &binTs : NULL, keep);
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
			printf("Failed recv (%d/%d): [%d] %m\n", received, rawSize, ret);
			free(raw);
			close(fd);
			return;
		}

		received += ret;
	}

	const size_t lenContent = rawSize - 44;
	unsigned char * const content = raw + 44;

	// Server-side encryption
	aem_kdf_fmk_direct(raw, 44, binTs, fmk);
	crypto_stream_chacha20_ietf_xor(content, content, lenContent, raw + 32, raw);

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
	t[0].tv_sec = div_floor(AEM_BINTS_BEGIN + binTs, 1000);
	t[0].tv_nsec = ((AEM_BINTS_BEGIN + binTs) % 1000) * 1000000;

	t[1].tv_sec = t[0].tv_sec;
	t[1].tv_nsec = t[0].tv_nsec;

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
	uint64_t binTs = 0;
	size_t bytes = 0;
	const int fd = getFd(uid, slot, &bytes, &binTs, false);
	if (fd < 0) return;

	const size_t startOffset = chunk * PV_CHUNKSIZE;
	if (startOffset > bytes) {
		puts("Invalid size");
		close(fd);
		return;
	}

	const size_t lenRead = MIN(PV_CHUNKSIZE, bytes - startOffset);
	const size_t lenRaw = lenRead + ((slot == PV_SLOT_INDEX) ? 8242 : 50);
	const size_t lenHeaders = 69 + numberOfDigits(lenRaw);
	const size_t lenResponse = lenHeaders + lenRaw;
	unsigned char * const response = malloc(lenResponse);
	if (response == NULL) {syslog(LOG_ERR, "Failed alloc"); close(fd); return;}

	sprintf((char*)response,
		"HTTP/1.0 200 PV\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, lenRaw);

	const ssize_t bytesRead = pread(fd, response + lenHeaders + ((slot == PV_SLOT_INDEX) ? 8242 : 50), lenRead, startOffset);
	close(fd);

	if (bytesRead != (ssize_t)lenRead) {
		printf("Failed reading file: %ld != %ld\n", bytesRead, lenRead);
		free(response);
		return;
	}

	if (slot == PV_SLOT_INDEX && chunk == 0) setSlots(uid, response + lenHeaders);
	aem_kdf_fmk(response + lenHeaders + ((slot == PV_SLOT_INDEX) ? 8192 : 0), 44, binTs, fmk);
	memcpy(response + lenHeaders + ((slot == PV_SLOT_INDEX) ? 8236 : 44), (unsigned char*)&binTs, 6);

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

void respond_vfyFile(const uint16_t uid, const uint16_t slot, const unsigned char * const verifyKey) {
	uint64_t binTs;
	size_t bytes;
	const int fd = getFd(uid, slot, &bytes, &binTs, false);
	if (fd < 0) {respondStatus(false); return;}

	const long long chunks = div_ceil(bytes, PV_CHUNKSIZE);
	unsigned char * const chunkData = malloc(PV_CHUNKSIZE);
	if (chunkData == NULL) {close(fd); respondStatus(false); return;}

	unsigned char hdr[512];
	const int lenHdr = sprintf((char*)hdr,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %lld\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, 6 + (chunks * PV_VERIFY_HASHSIZE));
	memcpy(hdr + lenHdr, &binTs, 6);
	send(PV_SOCK_CLIENT, hdr, lenHdr + 6, MSG_MORE);

	unsigned char hash[PV_VERIFY_HASHSIZE];
	for (int i = 0; i < chunks; i++) {
		const bool last = (i + 1 == chunks);
		const ssize_t lenChunk = last? ((ssize_t)bytes) - ((ssize_t)i * PV_CHUNKSIZE) : PV_CHUNKSIZE;
		if (pread(fd, chunkData, lenChunk, i * PV_CHUNKSIZE) != lenChunk) {puts("Failed reading"); break;}
		crypto_generichash(hash, PV_VERIFY_HASHSIZE, chunkData, lenChunk, verifyKey, 32);
		if (send(PV_SOCK_CLIENT, hash, PV_VERIFY_HASHSIZE, last? 0 : MSG_MORE) != PV_VERIFY_HASHSIZE) {puts("Failed sending"); break;}
	}

	free(chunkData);
	close(fd);
}
