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

#include "Common/AEM_KDF.h"
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
#define PV_CMD_VERIFY   3

// API request container
#define PV_REQ_ENC_OFFSET 8
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

static int loadUsers(const unsigned char smk[AEM_KDF_MASTER_KEYLEN]) {
	const int fd = open("/Users.pv", O_RDONLY | O_NOCTTY);
	if (fd < 0) {puts("Failed opening Users.pv"); return -1;}

	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * PV_USERCOUNT) + crypto_aead_aegis256_ABYTES;
	if (lseek(fd, 0, SEEK_END) != lenEnc) {puts("Incorrect size for Users.pv"); close(fd); return -1;}

	unsigned char enc[lenEnc];
	const ssize_t readBytes = pread(fd, enc, lenEnc, 0);
	close(fd);
	if (readBytes != lenEnc) {puts("Failed to read Users.pv"); return -1;}

	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_master(sfk, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_PV_FILE, smk);

	const int ret = crypto_aead_aegis256_decrypt((unsigned char*)user, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, sfk);
	sodium_memzero(sfk, crypto_aead_aegis256_KEYBYTES);

	if (ret != 0) {
		puts("Failed decrypting Users.pv");
		return -1;
	}

	return 0;
}

int pv_init(void) {
	unsigned char smk[AEM_KDF_MASTER_KEYLEN];
	if (getKey(smk) != 0) return -1;

	const int ret = loadUsers(smk);
	ioSetup(smk);

	sodium_memzero(smk, AEM_KDF_MASTER_KEYLEN);
	if (ret == -1) return -1;

	for (int uid = 0; uid < PV_USERCOUNT; uid++) {
		if (!sodium_is_zero(user[uid].uak, AEM_KDF_SUB_KEYLEN)) checkUserDir(uid);
	}

	return createSocket(PV_PORT);
}

static void respond400(void) {
	send(PV_SOCK_CLIENT,
		"HTTP/1.1 400 PV\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 70, 0);
}

static void respond403(void) {
	send(PV_SOCK_CLIENT,
		"HTTP/1.1 403 PV\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 70, 0);
}

static void respond404(void) {
	send(PV_SOCK_CLIENT,
		"HTTP/1.1 404 PV\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 70, 0);
}

static void respond410(void) {
	send(PV_SOCK_CLIENT,
		"HTTP/1.1 410 PV\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 70, 0);
}

static void respondClient(void) {
	// Read request
	unsigned char buf[1024];
	int lenBuf = recv(PV_SOCK_CLIENT, buf, PV_REQ_LINE1_LEN, 0);
	if (lenBuf != PV_REQ_LINE1_LEN) return; // Failed reading request

	// Get request method
	const unsigned char *b64_begin;
	if (memeq(buf, "GET /", 5)) b64_begin = buf + 5;
	else if (memeq(buf, "POST /", 6)) b64_begin = buf + 6;
	else return; // Invalid method

	// Decode Base64
	struct pv_req req;
	size_t lenRaw = 0;
	sodium_base642bin((unsigned char*)&req, 27, (const char*)b64_begin, 36, NULL, &lenRaw, NULL, sodium_base64_VARIANT_URLSAFE);
	if (lenRaw != 27) {
		// Invalid Base64
		respond400();
		return;
	}

	// Verify user exists
	if (sodium_is_zero(user[req.userId].uak, AEM_KDF_SUB_KEYLEN)) {
		// No such user
		respond403();
		return;
	}

	// Authenticate and decrypt
	unsigned char uak_key[3 + crypto_onetimeauth_KEYBYTES];
	aem_kdf_sub(uak_key, 3 + crypto_onetimeauth_KEYBYTES, req.binTs | ((buf[0] == 'P') ? 144115188075855872LLU : 72057594037927936LLU), user[req.userId].uak); // [7]=2:1

	if (crypto_onetimeauth_verify(req.mac, (unsigned char*)&req + PV_REQ_ENC_OFFSET, 3, uak_key + 3) != 0) {
		// Authentication failed
		respond403();
		return;
	}

	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 0] ^= uak_key[0];
	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 1] ^= uak_key[1];
	((unsigned char*)&req)[PV_REQ_ENC_OFFSET + 2] ^= uak_key[2];
	sodium_memzero(uak_key, 3 + crypto_onetimeauth_KEYBYTES);

	if ((req.flags & PV_FLAG_SHARED) != 0 && req.cmd != PV_CMD_DOWNLOAD) {
		// Invalid flags
		respond400();
		return;
	}

	// Check timestamp
	const int64_t tsNow = ((int64_t)time(NULL) * 1000) & ((1L << 40) - 1);
	const int64_t tsReq = req.binTs;
	if ((req.flags & PV_FLAG_SHARED) == 0) {
		if (labs(tsNow - tsReq) > PV_REQ_TS_MAXDIFF) {
			// Suspected replay attack - time difference too large
			respond404();
			return;
		}
	} else if (tsNow > tsReq + expiration_times[(req.flags >> 1) & 15]) {
		// Expired shared link
		respond410();
		return;
	}

	// GET request
	if (buf[0] == 'G') {
		if (req.cmd == PV_CMD_DOWNLOAD) {
			respond_getFile(req.userId, req.slot, req.chunk);
		} else if (req.cmd == PV_CMD_DELETE) {
			respond_delFile(req.userId, req.slot);
		} else if (req.cmd == PV_CMD_VERIFY) {
			unsigned char verifyKey[32];
			aem_kdf_sub(verifyKey, 32, req.binTs | 216172782113783808LLU, user[req.userId].uak); // [7]=3
			respond_vfyFile(req.userId, req.slot, verifyKey);
			sodium_memzero(verifyKey, 32);
		} else {
			// Invalid command for GET
			respond400();
		}

		return;
	}

	// POST request
	if (req.cmd != PV_CMD_UPLOAD) {
		// Invalid command for POST
		respond400();
		return;
	}

	if (sodium_compare((unsigned char*)&req, user[req.userId].lastMod, 5) != 1) {
		// Suspected replay attack - request older than last modification
		respond404();
		return;
	}
	memcpy(user[req.userId].lastMod, (unsigned char*)&req, 5);

	lenBuf = 0;
	for(;;) {
		const int lenRcv = recv(PV_SOCK_CLIENT, buf + lenBuf, 1024 - lenBuf, MSG_PEEK);
		if (lenRcv < 1) {puts("Terminating: Failed receiving request"); break;}
		lenBuf += lenRcv;

		const unsigned char * const cl = memcasemem(buf, lenBuf, "Content-Length:", 15);
		const long uploadSize = (cl != NULL && memchr(cl + 15, '\r', (buf + lenBuf) - (cl + 15)) != NULL) ? strtol((const char*)cl + 15, NULL, 10) : -1;
		if (uploadSize < PV_BLOCKSIZE + 32 || (uploadSize - 32) % PV_BLOCKSIZE != 0 || uploadSize > PV_CHUNKSIZE + 32) {
			respond400(); // Invalid body size
			return;
		}

		const unsigned char *postBegin = memmem(buf, lenBuf, "\r\n\r\n", 4);
		if (postBegin != NULL) {
			postBegin += 4;
			recv(PV_SOCK_CLIENT, buf, postBegin - buf, MSG_WAITALL);
			shutdown(PV_SOCK_CLIENT, SHUT_RD);

			// MFK encryption key
			unsigned char xmfk[32];
			aem_kdf_sub(xmfk, 32, req.binTs | ((uint64_t)req.slot << 40), user[req.userId].uak);

			respond_addFile(req.userId, req.slot, req.chunk, (req.flags & PV_FLAG_KEEP) != 0, uploadSize, req.binTs, xmfk);
			break;
		}

		if (lenBuf > 1023) break;
	}
}

void acceptClients(void) {
	puts("Ready");

	for(;;) {
		if (accept4(PV_SOCK_ACCEPT, NULL, NULL, SOCK_CLOEXEC) != PV_SOCK_CLIENT) continue;

		respondClient();

		// Make sure the response is sent before closing the socket
		shutdown(PV_SOCK_CLIENT, SHUT_WR);
		unsigned char x[1024];
		read(PV_SOCK_CLIENT, x, 1024);
		read(PV_SOCK_CLIENT, x, 1024);
		close(PV_SOCK_CLIENT);
	}

	close(PV_SOCK_CLIENT);
}
