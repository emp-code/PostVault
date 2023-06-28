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

#define PV_MFK_LEN 32 // AES-256
#define PV_MFK_DOWNLOAD 0xBE
// 0xCE reserved
#define PV_MFK_DELETE 0xDE

// API box keys
static unsigned char pv_box_pk[crypto_box_PUBLICKEYBYTES];
static unsigned char pv_box_sk[crypto_box_SECRETKEYBYTES];

// AES256-GCM encrypted request info
struct pv_req_dec {
	uint16_t slot: 12; // File #0-4095
	uint16_t flag_u0: 1;
	uint16_t flag_replace: 1; // Replace existing file on upload
	uint16_t flag_u2: 1;
	uint16_t flag_u3: 1;

	unsigned char mfk[PV_MFK_LEN]; // On uploads: Mutual File Key (AES256-CTR) for the server-side encryption; otherwise, verifies type of request (Download/Delete)
};

// API Request Box
struct pv_req {
	uint32_t userId;
	unsigned char ts[5]; // 5-byte time in milliseconds, used as nonce
	unsigned char chunk; // 16-MiB chunk, #0-255
	unsigned char enc[sizeof(struct pv_req_dec) + crypto_aead_chacha20poly1305_ABYTES];
};

struct pv_user {
	unsigned char uak[crypto_aead_aes256gcm_KEYBYTES]; // User Access Key, grants access to PostVault
	uint32_t userId; // To identify the user
	unsigned char lastMod[5]; // To protect against replay attacks
	unsigned char r1[5]; // Reserved
	uint16_t r2; // Reserved
};

static int userCount = 0;
static struct pv_user *users;

static void loadUsers(const unsigned char * const sfk) {
	const int fd = open("/Users.pv", O_RDONLY | O_NOCTTY);
	if (fd < 0) {puts("Failed opening Users.pv"); return;}

	const unsigned int maxUsers = lseek(fd, 0, SEEK_END) / (sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES);
	if (maxUsers < 1) {puts("No registered users"); return;}
	users = malloc(maxUsers * sizeof(struct pv_user));

	for(uint64_t i = 0; i < maxUsers; i++) {
		unsigned char enc[sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES];
		const ssize_t readBytes = pread(fd, enc, sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES, userCount * (sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES));
		if (readBytes < 0) return;

		if (crypto_aead_chacha20poly1305_decrypt((unsigned char*)users + (userCount * sizeof(struct pv_user)), NULL, NULL, enc, sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES, NULL, 0, (unsigned char*)&i, sfk) != 0) {
			printf("User #%d corrupt\n", userCount);
			close(fd);
			return;
		}

		if (checkUserDir(users[userCount].uak) != 0) {
			printf("User #%d directory error\n", userCount);
		}

		userCount++;
	}

	close(fd);
}

int pv_init(void) {
	if (sodium_init() != 0) return -1;

	unsigned char smk[crypto_kdf_KEYBYTES];
	if (getKey(smk, crypto_kdf_KEYBYTES) != 0) return -1;

	unsigned char seed[crypto_box_SEEDBYTES];
	crypto_kdf_derive_from_key(seed, crypto_box_SEEDBYTES, 1, "PV:Seed0", smk);
	crypto_box_seed_keypair(pv_box_pk, pv_box_sk, seed);
	sodium_memzero(seed, crypto_box_SEEDBYTES);
	printf("SPK=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n", pv_box_pk[0], pv_box_pk[1], pv_box_pk[2], pv_box_pk[3], pv_box_pk[4], pv_box_pk[5], pv_box_pk[6], pv_box_pk[7], pv_box_pk[8], pv_box_pk[9], pv_box_pk[10], pv_box_pk[11], pv_box_pk[12], pv_box_pk[13], pv_box_pk[14], pv_box_pk[15], pv_box_pk[16], pv_box_pk[17], pv_box_pk[18], pv_box_pk[19], pv_box_pk[20], pv_box_pk[21], pv_box_pk[22], pv_box_pk[23], pv_box_pk[24], pv_box_pk[25], pv_box_pk[26], pv_box_pk[27], pv_box_pk[28], pv_box_pk[29], pv_box_pk[30], pv_box_pk[31]);

	unsigned char pathKey[crypto_kdf_KEYBYTES];
	crypto_kdf_derive_from_key(pathKey, crypto_kdf_KEYBYTES, 1, "PV:Path0", smk);
	ioSetup(pathKey);
	sodium_memzero(pathKey, crypto_kdf_KEYBYTES);

	unsigned char sfk[crypto_aead_chacha20poly1305_KEYBYTES];
	crypto_kdf_derive_from_key(sfk, crypto_aead_chacha20poly1305_KEYBYTES, 1, "PV:FileA", smk);
	loadUsers(sfk);
	sodium_memzero(sfk, crypto_aead_chacha20poly1305_KEYBYTES);
	if (userCount < 1) {puts("Failed loading user data"); return -1;}

	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	return createSocket(PV_PORT);
}

static int getUserFromId(const uint32_t id) {
	for (int i = 0; i < userCount; i++) {
		if (id == users[i].userId) return i;
	}

	return -1;
}

static bool mfkRepeatsChar(const unsigned char * const mfk) {
	unsigned char c[PV_MFK_LEN - 1];
	memset(c, mfk[0], PV_MFK_LEN - 1);
	const bool ret = (sodium_compare(mfk + 1, c, PV_MFK_LEN - 1) == 0);
	sodium_memzero(c, PV_MFK_LEN - 1);
	return ret;
}

static void respondClient(const int sock) {
	unsigned char buf[1024];
	int lenBuf = recv(sock, buf, PV_REQ_LINE1_LEN, 0);
	if (lenBuf < PV_REQ_LINE1_LEN) return;

	const unsigned char *b64_begin;
	if (memeq(buf, "GET /", 5)) b64_begin = buf + 5;
	else if (memeq(buf, "POST /", 6)) b64_begin = buf + 6;
	else return;

	unsigned char box[108];
	size_t boxLen = 0;
	sodium_base642bin(box, 108, (const char*)b64_begin, 144, NULL, &boxLen, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
	if (boxLen != 108) {puts("Terminating: Failed decoding Base64");return;}

	unsigned char box_nonce[crypto_box_NONCEBYTES];
	memset(box_nonce, 0x01, crypto_box_NONCEBYTES);

	const unsigned char * const box_pk = box + 76;

	struct pv_req req;
	if (crypto_box_open_easy((unsigned char*)&req, box, 76, box_nonce, box_pk, pv_box_sk) != 0) {puts("Terminating: Failed opening Request Box"); return;}

	const int user = getUserFromId(req.userId);
	if (user < 0) {puts("Terminating: Unrecognized user"); return;}

	unsigned char aes_nonce[crypto_aead_aes256gcm_NPUBBYTES];
	bzero(aes_nonce, crypto_aead_aes256gcm_NPUBBYTES);
	memcpy(aes_nonce, req.ts, 5);

	uint64_t ts;
	memcpy((unsigned char*)&ts, req.ts, 5);

	struct pv_req_dec dec;
	if (crypto_aead_aes256gcm_decrypt((unsigned char*)&dec, NULL, NULL, req.enc, sizeof(struct pv_req_dec) + crypto_aead_aes256gcm_ABYTES, NULL, 0, aes_nonce, users[user].uak) != 0) {
		puts("Terminating: Failed decrypting AES-GCM");
		return;
	}

	const int64_t tsCurrent = ((int64_t)time(NULL) * 1000) & ((1l << 40) - 1);
	const unsigned char tsRequest[8] = {req.ts[0], req.ts[1], req.ts[2], req.ts[3], req.ts[4], 0, 0, 0};
	if (labs(tsCurrent - *(int64_t*)tsRequest) > PV_REQ_TS_MAXDIFF) {
		puts("Terminating: Suspected replay attack - time difference too large");
		return;
	}

	if (memeq(buf, "GET /", 5)) {
		if (dec.mfk[0] != PV_MFK_DOWNLOAD || !mfkRepeatsChar(dec.mfk)) {
			puts("Terminating: Invalid MFK for Download");
			return;
		}

		return respond_getFile(sock, users[user].uak, dec.slot, req.chunk, box_pk, pv_box_sk);
	}

	// POST request
	if (sodium_compare(req.ts, users[user].lastMod, 5) != 1) {
		puts("Terminating: Suspected replay attack - request older than last modification");
		return;
	}
	memcpy(users[user].lastMod, req.ts, 5);

	lenBuf = 0;

	while (1) {
		const int lenRcv = recv(sock, buf + lenBuf, 1024 - lenBuf, MSG_PEEK);
		if (lenRcv < 1) {puts("Terminating: Failed receiving request"); break;}
		lenBuf += lenRcv;

		const unsigned char * const cl = memcasemem(buf, lenBuf, "Content-Length:", 15);
		const long uploadSize = (cl != NULL && memchr(cl + 15, '\r', (buf + lenBuf) - (cl + 15)) != NULL) ? strtol((const char*)cl + 15, NULL, 10) : -1;

		if (uploadSize == 0) {
			shutdown(sock, SHUT_RD);

			if (dec.mfk[0] != PV_MFK_DELETE || !mfkRepeatsChar(dec.mfk)) {
				puts("Terminating: Invalid MFK for Delete");
				return;
			}

			return respond_delFile(sock, dec.slot, users[user].uak, box_pk, pv_box_sk);
		}

		const unsigned char *postBegin = memmem(buf, lenBuf, "\r\n\r\n", 4);
		if (postBegin != NULL) {
			if (uploadSize < 1) break;

			postBegin += 4;
			recv(sock, buf, postBegin - buf, MSG_WAITALL);
			shutdown(sock, SHUT_RD);

			respond_addFile(sock, users[user].uak, dec.slot, req.chunk, dec.mfk, dec.flag_replace, uploadSize, ts, box_pk, pv_box_sk);
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
