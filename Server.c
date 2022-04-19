#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/GetKey.h"
#include "Common/memeq.h"

#define PV_LEN_INFO ((256 * 32) + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) // 8232

#define PV_MAXLEN_REQ 1000
#define PV_MINLEN_REQ 138
#define PV_BUFSIZE 102400
#define PV_MIN_TS 1640995200 // 2022-01-01

#define PV_REQUEST_INFO 1
#define PV_REQUEST_FILE 2

#define PV_LEN_RESPONSE_LIST_HEADERS 93
#define PV_LEN_RESPONSE_FILE_HEADERS 88

unsigned char spk[crypto_box_PUBLICKEYBYTES];
unsigned char ssk[crypto_box_SECRETKEYBYTES];

unsigned char upk[crypto_box_PUBLICKEYBYTES];
unsigned char fileNum = 0xFF;

int pv_init(void) {
	if (getKey(spk, ssk) != 0) return -1;
	printf("SPK=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n", spk[0], spk[1], spk[2], spk[3], spk[4], spk[5], spk[6], spk[7], spk[8], spk[9], spk[10], spk[11], spk[12], spk[13], spk[14], spk[15], spk[16], spk[17], spk[18], spk[19], spk[20], spk[21], spk[22], spk[23], spk[24], spk[25], spk[26], spk[27], spk[28], spk[29], spk[30], spk[31]);
	return 0;
}

static int getRequestInfo(const unsigned char * const url) {
	unsigned char box[82];
	size_t lenBox = 0;
	sodium_base642bin(box, 82, (const char * const)url, 108, NULL, &lenBox, NULL, sodium_base64_VARIANT_URLSAFE);

	unsigned char decrypted[crypto_box_PUBLICKEYBYTES + 1];
	if (crypto_box_seal_open(decrypted, box, lenBox, spk, ssk) != 0) {
		puts("Failed opening box");
		return -1;
	}

	memcpy(upk, decrypted, crypto_box_PUBLICKEYBYTES);
	if (lenBox < 81) return PV_REQUEST_INFO;

	fileNum = decrypted[crypto_box_PUBLICKEYBYTES];
	return PV_REQUEST_FILE;
}

static void setInfo(unsigned char * const target) {
	bzero(target, 2048);

	char path[87];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);

	for (unsigned char i = 0;; i++) {
		path[83] = '/';
		sodium_bin2hex(path + 84, 3, &i, 1);

		struct stat s;
		if (lstat(path, &s) != 0) {if (i == 255) break; continue;}

		const time_t ts64 = s.st_mtim.tv_sec;
		const off_t bytes = s.st_size;

		if (ts64 < PV_MIN_TS || ts64 > UINT32_MAX || bytes < 1 || bytes > UINT32_MAX) {
			// Invalid file -> delete
			unlink(path);
			if (i == 255) break;
			continue;
		}

		const uint32_t vals[2] = {ts64, bytes};
		memcpy(target + (i * 8), (unsigned char*)vals, 8);

		if (i == 255) break;
	}
}

static void respondList(const int sock) {
	// Open the info file
	char path[89];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);
	memcpy(path + 83, "/info\0", 6);

	const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) return; // TODO respond

	// Prepare response
	unsigned char resp[PV_LEN_RESPONSE_LIST_HEADERS + 10280]; // PV_LEN_INFO (8232) + 8*256 (2048)

	memcpy((char*)resp,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: 10280\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, PV_LEN_RESPONSE_LIST_HEADERS);

	// Read file
	const ssize_t r = read(fd, resp + PV_LEN_RESPONSE_LIST_HEADERS, PV_LEN_INFO);
	close(fd);
	if (r != PV_LEN_INFO) return; // TODO respnd

	// Add sizes and timestamps
	setInfo(resp + PV_LEN_RESPONSE_LIST_HEADERS + PV_LEN_INFO);

	// Send the response
	send(sock, resp, PV_LEN_RESPONSE_LIST_HEADERS + 10280, 0);
}

static int numberOfDigits(const off_t x) {
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

static void respondFile(const int sock) {
	// Read file
	char path[89];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);
	path[83] = '/';
	sodium_bin2hex(path + 84, 3, &fileNum, 1);

	const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) return; // TODO: respond

	const off_t lenFile = lseek(fd, 0, SEEK_END);
	if (lenFile < 1) return; // TODO: respond

	const size_t lenHeaders = PV_LEN_RESPONSE_FILE_HEADERS + numberOfDigits(lenFile);
	unsigned char * const resp = malloc(lenHeaders + lenFile);
	if (resp == NULL) return; // TODO: respond

	sprintf((char*)resp,
		"HTTP/1.1 200 PV\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, lenFile);

	const ssize_t r = pread(fd, resp + lenHeaders, lenFile, 0);
	close(fd);
	if (r != lenFile) {free(resp); return;} // TODO: respond

	// Send response
	send(sock, resp, lenHeaders + lenFile, 0);
	free(resp);
}

static void respondGet(const int sock, const unsigned char * const url) {
	switch (getRequestInfo(url)) {
		case PV_REQUEST_INFO: return respondList(sock);
		case PV_REQUEST_FILE: return respondFile(sock);
	}
}

static int receiveInfo(const int sock, const unsigned char * const beginData, const size_t lenBeginData) {
	unsigned char info[PV_LEN_INFO];
	memcpy(info, beginData, lenBeginData);
	size_t lenInfo = lenBeginData;

	while (lenInfo < PV_LEN_INFO) {
		errno = 0;
		const ssize_t r = recv(sock, info + lenInfo, PV_LEN_INFO - lenInfo, 0);
		if (r < 1) break;
		lenInfo += r;
	}

	if (lenInfo != PV_LEN_INFO) {
		printf("recvinfo fail: %m (%zd/%d)\n", lenInfo, PV_LEN_INFO);
		return -1;
	}

	char path[89];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);
	memcpy(path + 83, "/info\0", 6);

	const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW, S_IRUSR | S_IWUSR);
	const ssize_t written = write(fd, info, PV_LEN_INFO);
	close(fd);

	if (written != PV_LEN_INFO) {
		printf("recvInfo fail: %m\n");
		return -1;
	}

	return 0;
}

static int receiveFile(const int sock, const size_t lenFile) {
	char path[87];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);
	path[83] = '/';
	sodium_bin2hex(path + 84, 3, &fileNum, 1);

	const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW, S_IRUSR | S_IWUSR);

	unsigned char buf[PV_BUFSIZE];
	size_t written = 0;

	while (written < lenFile) {
		const ssize_t lenBuf = recv(sock, buf, (lenFile - written >= PV_BUFSIZE) ? PV_BUFSIZE : lenFile - written, 0);
		if (lenBuf < 1 || write(fd, buf, lenBuf) != lenBuf) break;
		written += lenBuf;
	}

	close(fd);

	if (written != lenFile) {
		printf("recvFile fail: %m\n");
		return -1;
	}

	return 0;
}

static int deleteFile(void) {
	char path[87];
	memcpy(path, "/var/lib/PostVault/", 19);
	sodium_bin2hex(path + 19, 65, upk, 32);
	path[83] = '/';
	sodium_bin2hex(path + 84, 3, &fileNum, 1);

	return unlink(path);
}

static void respondPost(const int sock, const unsigned char * const url, const size_t len) {
	if (getRequestInfo(url) != PV_REQUEST_FILE) {puts("respondPost: Non-file"); return;}

	const unsigned char * const headersEnd = memmem(url, len, "\r\n\r\n", 4);
	if (headersEnd == NULL) {puts("respondPost: No headersEnd"); return;}

	const unsigned char *strCl = memcasemem(url, headersEnd - url, "\nContent-Length:", 16);
	if (strCl == NULL) {puts("respondPost: No CL"); return;}
	strCl += 16;
	while (isspace(*strCl)) {strCl++; if (strCl >= headersEnd) {puts("respondPost: No CL end"); return;}}

	const long cl = strtol((char*)strCl, NULL, 10);
	if (cl == 0)	{
		deleteFile();
	} else {
		receiveInfo(sock, headersEnd + 4, (url + len) - (headersEnd + 4));
		receiveFile(sock, cl - PV_LEN_INFO);
	}

	send(sock, 
		"HTTP/1.1 204 PV\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"\r\n"
	, 89, 0);
}

void respondClient(const int sock) {
	unsigned char buf[PV_MAXLEN_REQ];

	int ret = recv(sock, buf, PV_MAXLEN_REQ, 0);

	if (ret >= PV_MINLEN_REQ) {
		if (memeq(buf, "GET /", 5)) return respondGet(sock, buf + 5);
		if (memeq(buf, "POST /", 6)) return respondPost(sock, buf + 6, ret - 6);
	}
}
