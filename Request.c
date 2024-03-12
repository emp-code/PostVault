#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/AEM_Security.h"
#include "Common/CreateSocket.h"
#include "Common/GetKey.h"
#include "Common/PV_User.h"
#include "Common/memeq.h"
#include "IO.h"

#include "Request.h"

#define PV_REQ_LINE1_LEN 42
#define PV_REQ_TS_MAXDIFF 30000 // in ms

#define PV_FLAG_SHARED 1
#define PV_FLAG_KEEP 2

#define PV_CMD_DOWNLOAD 0
#define PV_CMD_UPLOAD   1
#define PV_CMD_DELETE   2
//#define PV_CMD_       3

// API request container
#define PV_REQ_ENC_OFFSET 8
#define PV_REQ_ENC_LENGTH 3
struct pv_req {
	uint64_t binTs: 40;
	uint64_t userId: 12;
	uint64_t chunk: 12;

	// Encrypted
	uint16_t slot;
	uint8_t flags: 6;
	uint8_t cmd: 2;
	unsigned char mac[crypto_onetimeauth_BYTES];

	unsigned char padding[5];
};

static const int64_t expiration_times[] = { // in ms
	300000, // 5 minutes
	900000, // 15 minutes
	3600000, // 1 hour
	14400000, // 4 hours
	43200000, // 12 hours
	86400000, // 24 hours
	259200000, // 3 days
	604800000, // 7 days
	1209600000, // 2 weeks
	2629746000, // 1 month
	7889238000, // 3 months
	15778476000, // 6 months
	31556952000, // 1 year
	63113904000, // 2 years
	157784760000, // 5 years
	9999999999999 // infinite
};

static struct pv_user user[PV_USERCOUNT];

static int loadUsers(const unsigned char sfk[crypto_aead_aegis256_KEYBYTES]) {
	const int fd = open("/Users.pv", O_RDONLY | O_NOCTTY);
	if (fd < 0) {puts("Failed opening Users.pv"); return -1;}

	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * PV_USERCOUNT) + crypto_aead_aegis256_ABYTES;
	if (lseek(fd, 0, SEEK_END) != lenEnc) {puts("Incorrect size for Users.pv"); close(fd); return -1;}

	unsigned char enc[lenEnc];
	const ssize_t readBytes = pread(fd, enc, lenEnc, 0);
	close(fd);
	if (readBytes != lenEnc) {puts("Failed to read Users.pv"); return -1;}

	if (crypto_aead_aegis256_decrypt((unsigned char*)user, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, sfk) != 0) {
		puts("Failed decrypting Users.pv");
		return -1;
	}

	return 0;
}

int pv_init(void) {
	unsigned char smk[AEM_SECURITY_MASTERKEY_LEN];
	if (getKey(smk, AEM_SECURITY_MASTERKEY_LEN) != 0) return -1;

	unsigned char pathKey[PV_PATHKEY_LEN];
	aem_security_kdf(pathKey, PV_PATHKEY_LEN, smk, AEM_SECURITY_KEYID_SMK_PV_PATH);
	ioSetup(pathKey);
	sodium_memzero(pathKey, PV_PATHKEY_LEN);

	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_security_kdf(sfk, crypto_aead_aegis256_KEYBYTES, smk, AEM_SECURITY_KEYID_SMK_PV_FILE);

	sodium_memzero(smk, AEM_SECURITY_MASTERKEY_LEN);

	const int ret = loadUsers(sfk);
	sodium_memzero(sfk, crypto_aead_aegis256_KEYBYTES);
	if (ret == -1) return -2;

	for (int uid = 0; uid < PV_USERCOUNT; uid++) {
		if (!sodium_is_zero(user[uid].uak, AEM_SECURITY_UAK_LEN)) checkUserDir(uid);
	}

	return createSocket(PV_PORT);
}

static void respondClient(const int sock) {
	// Read request
	unsigned char buf[1024];
	int lenBuf = recv(sock, buf, PV_REQ_LINE1_LEN, 0);
	if (lenBuf != PV_REQ_LINE1_LEN) {puts("Terminating: Invalid length"); return;}

	// Get request type
	const unsigned char *b64_begin;
	if (memeq(buf, "GET /", 5)) b64_begin = buf + 5;
	else if (memeq(buf, "POST /", 6)) b64_begin = buf + 6;
	else {puts("Terminating: Invalid request"); return;}

	// Decode Base64
	struct pv_req req;
	size_t lenRaw = 0;
	sodium_base642bin((unsigned char*)&req, 27, (const char*)b64_begin, 36, NULL, &lenRaw, NULL, sodium_base64_VARIANT_URLSAFE);
	if (lenRaw != 27) {puts("Terminating: Failed decoding Base64"); return;}

	// Verify user
	if (sodium_is_zero(user[req.userId].uak, AEM_SECURITY_UAK_LEN)) {printf("Terminating: Unrecognized user: %u\n", req.userId); return;}

	// Authenticate
	unsigned char secret_hash[PV_REQ_ENC_LENGTH + crypto_onetimeauth_KEYBYTES];
	crypto_generichash(secret_hash, PV_REQ_ENC_LENGTH + crypto_onetimeauth_KEYBYTES, (unsigned char*)&req, 5, user[req.userId].uak, AEM_SECURITY_UAK_LEN);
	if (crypto_onetimeauth_verify(req.mac, (unsigned char*)&req + PV_REQ_ENC_OFFSET, PV_REQ_ENC_LENGTH, secret_hash + PV_REQ_ENC_LENGTH) != 0) {
		puts("Terminating: Failed authentication");
		return;
	}

	// Decrypt
	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 0] ^= secret_hash[0];
	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 1] ^= secret_hash[1];
	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 2] ^= secret_hash[2];

	if ((req.flags & PV_FLAG_SHARED) != 0 && req.cmd != PV_CMD_DOWNLOAD) {
		puts("Terminating: Shared flag on non-download request");
		return;
	}

	// Check timestamp
	const int64_t tsNow = ((int64_t)time(NULL) * 1000) & ((1L << 40) - 1);
	const int64_t tsReq = req.binTs;
	if ((req.flags & PV_FLAG_SHARED) == 0) {
		if (labs(tsNow - tsReq) > PV_REQ_TS_MAXDIFF) {
			puts("Terminating: Suspected replay attack - time difference too large");
			return;
		}
	} else if (tsNow > tsReq + expiration_times[(req.flags >> 1) & 15]) {
		puts("Terminating: Expired shared link");
		return;
	}

	// Take action
	if (memeq(buf, "GET /", 5)) {
		if (req.cmd == PV_CMD_DOWNLOAD) {
			respond_getFile(sock, req.userId, req.slot, req.chunk);
		} else if (req.cmd == PV_CMD_DELETE) {
			respond_delFile(sock, req.userId, req.slot);
		} else {
			puts("Terminating: Invalid GET request");
		}

		return;
	} else if (!memeq(buf, "POST /", 6) || req.cmd != PV_CMD_UPLOAD) {
		puts("Terminating: Invalid POST request");
		return;
	}

	// POST request
	if (sodium_compare((unsigned char*)&req, user[req.userId].lastMod, 5) != 1) {
		puts("Terminating: Suspected replay attack - request older than last modification");
		return;
	}
	memcpy(user[req.userId].lastMod, (unsigned char*)&req, 5);

	lenBuf = 0;
	for(;;) {
		const int lenRcv = recv(sock, buf + lenBuf, 1024 - lenBuf, MSG_PEEK);
		if (lenRcv < 1) {puts("Terminating: Failed receiving request"); break;}
		lenBuf += lenRcv;

		const unsigned char * const cl = memcasemem(buf, lenBuf, "Content-Length:", 15);
		const long uploadSize = (cl != NULL && memchr(cl + 15, '\r', (buf + lenBuf) - (cl + 15)) != NULL) ? strtol((const char*)cl + 15, NULL, 10) : -1;
		if (uploadSize < PV_BLOCKSIZE + PV_MFK_LEN || (uploadSize - PV_MFK_LEN) % PV_BLOCKSIZE != 0 || uploadSize > PV_CHUNKSIZE + PV_MFK_LEN) {
			printf("Invalid upload size: %ld\n", uploadSize);
			return;
		}

		const unsigned char *postBegin = memmem(buf, lenBuf, "\r\n\r\n", 4);
		if (postBegin != NULL) {
			postBegin += 4;
			recv(sock, buf, postBegin - buf, MSG_WAITALL);
			shutdown(sock, SHUT_RD);

			// MFK encryption key
			unsigned char xmfk[32];
			crypto_generichash(xmfk, 32,
				(unsigned char[7]) {*(unsigned char*)&req, *((unsigned char*)&req + 1), *((unsigned char*)&req + 2), *((unsigned char*)&req + 3), *((unsigned char*)&req + 4), *((unsigned char*)&req + 8), *((unsigned char*)&req + 9)}
			, 7, user[req.userId].uak, AEM_SECURITY_UAK_LEN);

			respond_addFile(sock, req.userId, req.slot, req.chunk, (req.flags & PV_FLAG_KEEP) != 0, uploadSize, req.binTs, xmfk);
			break;
		}

		if (lenBuf > 1023) break;
	}

	sodium_memzero(secret_hash, PV_REQ_ENC_LENGTH + crypto_onetimeauth_KEYBYTES);
}

void acceptClients(const int sock) {
	puts("Ready");

	for(;;) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;

		respondClient(newSock);

		// Make sure the response is sent before closing the socket
		shutdown(newSock, SHUT_WR);
		unsigned char x[1024];
		read(newSock, x, 1024);
		read(newSock, x, 1024);
		close(newSock);
	}

	close(sock);
}
