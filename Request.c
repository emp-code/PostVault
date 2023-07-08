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

#include "Common/CreateSocket.h"
#include "Common/GetKey.h"
#include "Common/memeq.h"
#include "IO.h"

#include "Request.h"

#define PV_REQ_LINE1_LEN 152
#define PV_REQ_TS_MAXDIFF 30000 // in ms

#define PV_FLAG_SHARED 1
#define PV_FLAG_KEEP 2

#define PV_CMD_DOWNLOAD 0
#define PV_CMD_UPLOAD   1
#define PV_CMD_DELETE   2
//#define PV_CMD_       3

// API box keys
static unsigned char pv_box_pk[crypto_box_PUBLICKEYBYTES];
static unsigned char pv_box_sk[crypto_box_SECRETKEYBYTES];

// AES256-GCM encrypted request info
struct pv_req_dec {
	uint16_t slot;
	uint8_t flags: 6;
	uint8_t cmd: 2;
};
#define SIZEOF_PV_REQ_DEC 3

// API Request Box
struct pv_req {
	uint64_t binTs: 40;
	uint64_t userId: 12;
	uint64_t chunk: 12;
	unsigned char enc[SIZEOF_PV_REQ_DEC + crypto_aead_aes256gcm_ABYTES];
};

struct pv_user {
	unsigned char uak[crypto_aead_aes256gcm_KEYBYTES]; // User API Key
	unsigned char lastMod[5]; // To protect against replay attacks
	unsigned char c1[5];
	uint8_t level: 2;
	uint8_t u1: 2;
	uint8_t u2: 4;
};

static struct pv_user users[4096];

static int loadUsers(const unsigned char sfk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
	const int fd = open("/Users.pv", O_RDONLY | O_NOCTTY);
	if (fd < 0) {puts("Failed opening Users.pv"); return -1;}

	const size_t lenEnc = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (sizeof(struct pv_user) * 4096) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	if (lseek(fd, 0, SEEK_END) != lenEnc) {puts("Incorrect size for Users.pv"); close(fd); return -1;}

	unsigned char enc[lenEnc];
	const ssize_t readBytes = pread(fd, enc, lenEnc, 0);
	close(fd);
	if (readBytes != lenEnc) {puts("Failed to read Users.pv"); return -1;}

	if (crypto_aead_xchacha20poly1305_ietf_decrypt((unsigned char*)users, NULL, NULL, enc + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, lenEnc - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL, 0, enc, sfk) != 0) {
		puts("Failed decrypting Users.pv");
		return -1;
	}

	return 0;
}

int pv_init(void) {
	if (sodium_init() != 0) return -1;

	unsigned char smk[crypto_kdf_KEYBYTES];
	if (getKey(smk, crypto_kdf_KEYBYTES) != 0) return -1;

	unsigned char seed[crypto_box_SEEDBYTES];
	crypto_kdf_derive_from_key(seed, crypto_box_SEEDBYTES, 1, "PVt:Box0", smk);
	crypto_box_seed_keypair(pv_box_pk, pv_box_sk, seed);
	sodium_memzero(seed, crypto_box_SEEDBYTES);
	printf("SPK=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n", pv_box_pk[0], pv_box_pk[1], pv_box_pk[2], pv_box_pk[3], pv_box_pk[4], pv_box_pk[5], pv_box_pk[6], pv_box_pk[7], pv_box_pk[8], pv_box_pk[9], pv_box_pk[10], pv_box_pk[11], pv_box_pk[12], pv_box_pk[13], pv_box_pk[14], pv_box_pk[15], pv_box_pk[16], pv_box_pk[17], pv_box_pk[18], pv_box_pk[19], pv_box_pk[20], pv_box_pk[21], pv_box_pk[22], pv_box_pk[23], pv_box_pk[24], pv_box_pk[25], pv_box_pk[26], pv_box_pk[27], pv_box_pk[28], pv_box_pk[29], pv_box_pk[30], pv_box_pk[31]);

	unsigned char pathKey[crypto_kdf_KEYBYTES];
	crypto_kdf_derive_from_key(pathKey, crypto_kdf_KEYBYTES, 1, "PVt:Pth0", smk);
	ioSetup(pathKey);
	sodium_memzero(pathKey, crypto_kdf_KEYBYTES);

	unsigned char sfk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	crypto_kdf_derive_from_key(sfk, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 1, "PVt:Fil0", smk);
	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	const int ret = loadUsers(sfk);
	sodium_memzero(sfk, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
	if (ret == -1) return -1;

	for (int uid = 0; uid < 4096; uid++) {
		if (!sodium_is_zero(users[uid].uak, crypto_aead_aes256gcm_KEYBYTES)) checkUserDir(uid);
	}

	return createSocket(PV_PORT);
}

static void respondClient(const int sock) {
	unsigned char buf[1024];
	int lenBuf = recv(sock, buf, PV_REQ_LINE1_LEN, 0);
	if (lenBuf < PV_REQ_LINE1_LEN) return;

	const unsigned char *b64_begin;
	if (memeq(buf, "GET /", 5)) b64_begin = buf + 5;
	else if (memeq(buf, "POST /", 6)) b64_begin = buf + 6;
	else return;

	unsigned char box[75];
	size_t boxLen = 0;
	sodium_base642bin(box, 75, (const char*)b64_begin, 100, NULL, &boxLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (boxLen != 75) {puts("Terminating: Failed decoding Base64"); return;}

	unsigned char box_nonce[crypto_box_NONCEBYTES];
	memset(box_nonce, 0x01, crypto_box_NONCEBYTES);

	const unsigned char * const box_pk = box + 43;

	struct pv_req req;
	if (crypto_box_open_easy((unsigned char*)&req, box, 43, box_nonce, box_pk, pv_box_sk) != 0) {puts("Terminating: Failed opening Request Box"); return;}

	if (sodium_is_zero(users[req.userId].uak, crypto_aead_aes256gcm_KEYBYTES)) {printf("Terminating: Unrecognized user: %u\n", req.userId); return;}

	unsigned char aes_nonce[crypto_aead_aes256gcm_NPUBBYTES];
	bzero(aes_nonce, crypto_aead_aes256gcm_NPUBBYTES);
	memcpy(aes_nonce, (unsigned char*)&req, 5);

	struct pv_req_dec dec;
	if (crypto_aead_aes256gcm_decrypt((unsigned char*)&dec, NULL, NULL, req.enc, SIZEOF_PV_REQ_DEC + crypto_aead_aes256gcm_ABYTES, NULL, 0, aes_nonce, users[req.userId].uak) != 0) {
		puts("Terminating: Failed decrypting AES-GCM");
		return;
	}

	if ((dec.flags & PV_FLAG_SHARED) != 0 && dec.cmd != PV_CMD_DOWNLOAD) {
		puts("Terminating: Shared flag on non-download request");
		return;
	}

	const int64_t tsCurrent = ((int64_t)time(NULL) * 1000) & ((1l << 40) - 1);
	const int64_t tsRequest = req.binTs;
	if ((dec.flags & PV_FLAG_SHARED) == 0 && labs(tsCurrent - tsRequest) > PV_REQ_TS_MAXDIFF) {
		puts("Terminating: Suspected replay attack - time difference too large");
		return;
	}

	if (memeq(buf, "GET /", 5)) {
		if (dec.cmd == PV_CMD_DOWNLOAD) {
			return respond_getFile(sock, box_pk, pv_box_sk, req.userId, dec.slot, req.chunk);
		} else if (dec.cmd == PV_CMD_DELETE) {
			return respond_delFile(sock, box_pk, pv_box_sk, req.userId, dec.slot);
		} else {
			puts("Terminating: Invalid GET request");
			return;
		}
	} else if (!memeq(buf, "POST /", 6) || dec.cmd != PV_CMD_UPLOAD) {
		puts("Terminating: Invalid POST request");
		return;
	}

	// POST request
	if (sodium_compare((unsigned char*)&req, users[req.userId].lastMod, 5) != 1) {
		puts("Terminating: Suspected replay attack - request older than last modification");
		return;
	}
	memcpy(users[req.userId].lastMod, (unsigned char*)&req, 5);

	lenBuf = 0;

	while (1) {
		const int lenRcv = recv(sock, buf + lenBuf, 1024 - lenBuf, MSG_PEEK);
		if (lenRcv < 1) {puts("Terminating: Failed receiving request"); break;}
		lenBuf += lenRcv;

		const unsigned char * const cl = memcasemem(buf, lenBuf, "Content-Length:", 15);
		const long uploadSize = (cl != NULL && memchr(cl + 15, '\r', (buf + lenBuf) - (cl + 15)) != NULL) ? strtol((const char*)cl + 15, NULL, 10) : -1;
		if (uploadSize < 1) {
			puts("Terminating: Invalid size for Upload");
			return;
		}

		const unsigned char *postBegin = memmem(buf, lenBuf, "\r\n\r\n", 4);
		if (postBegin != NULL) {
			postBegin += 4;
			recv(sock, buf, postBegin - buf, MSG_WAITALL);
			shutdown(sock, SHUT_RD);

			respond_addFile(sock, box_pk, pv_box_sk, req.userId, dec.slot, req.chunk, (dec.flags & PV_FLAG_KEEP) != 0, uploadSize, req.binTs);
			break;
		}

		if (lenBuf > 1023) break;
	}
}

void acceptClients(const int sock) {
	while (1) {
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
