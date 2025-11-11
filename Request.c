#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>

#include <sodium.h>

#include "Common/AEM_KDF.h"
#include "Common/CreateSocket.h"
#include "Common/GetKey.h"
#include "Common/PV_User.h"
#include "Common/binTs.h"
#include "Common/memeq.h"
#include "IO.h"

#include "Request.h"

#define PV_REQ_LINE1_LEN 41
#define PV_REQ_TS_MAXDIFF 30000 // in ms

#define PV_CMD_GET 0
#define PV_CMD_VFY 1
#define PV_CMD_DEL 2
#define PV_CMD_ADD 3
#define PV_CMD_UPD 4
//#define PV_CMD_- 5
//#define PV_CMD_- 6
//#define PV_CMD_- 7

struct pv_req {
	uint64_t binTs: 42;

	// Encrypted
	uint64_t cmd: 3;
	uint64_t share: 3;
	uint64_t slot: 16;
	unsigned char mac[crypto_onetimeauth_BYTES];

	uint64_t chunk: 18;
	uint64_t unused: 46;
};

static const long long expiration_times[] = { // in ms
	-99999999999, // private
	300000,       // 5 minutes
	3600000,      // 1 hour
	21600000,     // 6 hours
	86400000,     // 24 hours
	604800000,    // 7 days
	2629746000,   // 1 month
	9999999999999 // infinite
};

struct pv_user user[PV_USERCOUNT];

static int loadUsers(const unsigned char smk[AEM_KDF_SMK_KEYLEN]) {
	const int fd = open("/Users.pv", O_RDONLY | O_NOCTTY);
	if (fd < 0) {puts("Failed opening Users.pv"); return -1;}

	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * PV_USERCOUNT) + crypto_aead_aegis256_ABYTES;
	if (lseek(fd, 0, SEEK_END) != lenEnc) {puts("Incorrect size for Users.pv"); close(fd); return -1;}

	unsigned char enc[lenEnc];
	const ssize_t readBytes = pread(fd, enc, lenEnc, 0);
	close(fd);
	if (readBytes != lenEnc) {puts("Failed to read Users.pv"); return -1;}

	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_smk(sfk, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_PV_FILE, smk);

	const int ret = crypto_aead_aegis256_decrypt((unsigned char*)user, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, sfk);
	sodium_memzero(sfk, crypto_aead_aegis256_KEYBYTES);

	if (ret != 0) {
		puts("Failed decrypting Users.pv");
		return -1;
	}

	return 0;
}

int pv_init(void) {
	unsigned char smk[AEM_KDF_SMK_KEYLEN];
	if (getKey(smk) != 0) return -1;

	const int ret = loadUsers(smk);
	ioSetup(smk);

	sodium_memzero(smk, AEM_KDF_SMK_KEYLEN);
	if (ret == -1) return -1;

	for (int uid = 0; uid < PV_USERCOUNT; uid++) {
		if (!sodium_is_zero(user[uid].uak, AEM_KDF_UAK_KEYLEN)) checkUserDir(uid);
	}

	return createSocket();
}

static void unauthResponse(const unsigned char c1, const unsigned char c2, const unsigned char c3) {
	send(PV_SOCK_CLIENT,
		(unsigned char[]){'H','T','T','P','/','1','.','0',' ',c1,c2,c3,' ', 'x' ,'\r','\n',
		'A','c','c','e','s','s','-','C','o','n','t','r','o','l','-','A','l','l','o','w','-','O','r','i','g','i','n',':',' ','*','\r','\n',
		'C','o','n','t','e','n','t','-','l','e','n','g','t','h',':',' ','0','\r','\n',
		'\r','\n'}
	, 70, 0);
}

__attribute__((warn_unused_result, nonnull))
static int auth_decrypt(struct pv_req * const req, const bool post) {
	const unsigned char auth_src[3] = {(req->cmd << 2) | (req->share << 5), req->slot & 255, req->slot >> 8};

	for (int uid = 0; uid < PV_USERCOUNT; uid++) {
		unsigned char key[3 + crypto_onetimeauth_KEYBYTES];
		aem_kdf_uak(key, 3 + crypto_onetimeauth_KEYBYTES, req->binTs, post, AEM_KDF_UAK_URL, user[uid].uak);

		if (crypto_onetimeauth_verify(req->mac, auth_src, 3, key + 3) == 0) {
			req->cmd ^= key[0] & 7;
			req->share ^= (key[0] >> 5) & 7;
			req->slot ^= key[1] | (key[2] << 8);
			return uid;
		}
	}

	// Authentication failed
	return -1;
}

static void respondClient(void) {
	// Read request
	unsigned char buf[1024];
	int lenBuf = recv(PV_SOCK_CLIENT, buf, PV_REQ_LINE1_LEN, 0);
	if (lenBuf != PV_REQ_LINE1_LEN) return; // Failed reading request

	// Get request method
	unsigned char *b64_begin;
	if (memeq(buf, "GET /", 5)) b64_begin = buf + 5;
	else if (memeq(buf, "POST /", 6)) b64_begin = buf + 6;
	else return; // Invalid method

	// Decode Base64
	b64_begin[35] = 'A';
	struct pv_req req;
	size_t lenRaw = 0;
	sodium_base642bin((unsigned char*)&req, 27, (const char*)b64_begin, 36, NULL, &lenRaw, NULL, sodium_base64_VARIANT_URLSAFE);
	if (lenRaw != 27) {
		// Invalid Base64
		unauthResponse('4','0','0');
		return;
	}

	const int uid = auth_decrypt(&req, buf[0] == 'P');
	if (uid < 0) {unauthResponse('4','0','3'); return;}

	// Check timestamp
	const long long tsNow = getBinTs();
	const long long tsReq = req.binTs;
	if (req.share == 0) {
		if (llabs(tsNow - tsReq) > PV_REQ_TS_MAXDIFF) {
			// Suspected replay attack - time difference too large
			unauthResponse('4','0','4');
			return;
		}
	} else if (tsNow > tsReq + expiration_times[req.share]) {
		// Expired shared link
		unauthResponse('4','1','0');
		return;
	}

	// GET request
	if (buf[0] == 'G') {
		switch (req.cmd) {
			case PV_CMD_GET:
				respond_getFile(uid, req.slot, req.chunk);
			break;

			case PV_CMD_DEL:
				respond_delFile(uid, req.slot);
			break;

			case PV_CMD_VFY:
//				unsigned char verifyKey[32];
//				aem_kdf_uak(verifyKey, 32, req.binTs, user[uid].uak);
//				respond_vfyFile(uid, req.slot, verifyKey);
//				sodium_memzero(verifyKey, 32);
				unauthResponse('5','0','0'); // To be remade
			break;

			default:
				// Invalid command for GET
				unauthResponse('4','0','0');
				return;
		}

		return;
	}

	// POST request
	if (req.cmd != PV_CMD_ADD) {
		// Invalid command for POST
		unauthResponse('4','0','0');
		return;
	}

	if (req.binTs <= user[uid].lastMod) {
		// Suspected replay attack - request older than last modification
		unauthResponse('4','1','0');
		return;
	}
	user[uid].lastMod = req.binTs;

	lenBuf = 0;
	for(;;) {
		const int lenRcv = recv(PV_SOCK_CLIENT, buf + lenBuf, 1024 - lenBuf, MSG_PEEK);
		if (lenRcv < 1) {puts("Terminating: Failed receiving request"); break;}
		lenBuf += lenRcv;

		const unsigned char * const cl = memcasemem(buf, lenBuf, "Content-Length:", 15);
		const long uploadSize = (cl != NULL && memchr(cl + 15, '\r', (buf + lenBuf) - (cl + 15)) != NULL) ? strtol((const char*)cl + 15, NULL, 10) : -1;
		if (uploadSize < 44 || uploadSize > PV_CHUNKSIZE + 44) {
			// Invalid body size
			unauthResponse('4','0','0');
			return;
		}

		const unsigned char *postBegin = memmem(buf, lenBuf, "\r\n\r\n", 4);
		if (postBegin != NULL) {
			postBegin += 4;
			recv(PV_SOCK_CLIENT, buf, postBegin - buf, MSG_WAITALL);
			respond_putFile(uid, req.slot, req.chunk, uploadSize, req.binTs);
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
		close(PV_SOCK_CLIENT);
	}

	close(PV_SOCK_ACCEPT);
}
