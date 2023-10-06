#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/AEM_Security.h"
#include "../Common/PV_User.h"

static void printApiPk(const unsigned char smk[AEM_SECURITY_MASTERKEY_LEN]) {
	unsigned char pv_api_pk[crypto_scalarmult_BYTES];
	unsigned char pv_api_sk[crypto_scalarmult_SCALARBYTES];

	aem_security_kdf(pv_api_sk, crypto_scalarmult_SCALARBYTES, smk, AEM_SECURITY_KEYID_SERVER_API);
	crypto_scalarmult_base(pv_api_pk, pv_api_sk);

	printf("PK=");

	for (unsigned int i = 0; i < crypto_scalarmult_BYTES; i++)
		printf("%.2x", pv_api_pk[i]);

	printf("\n");

	sodium_memzero(pv_api_pk, crypto_scalarmult_BYTES);
	sodium_memzero(pv_api_sk, crypto_scalarmult_SCALARBYTES);
}

static void printMasterKey(const char * const msg, const unsigned char smk[AEM_SECURITY_MASTERKEY_LEN]) {
	char b64[65];
	sodium_bin2base64(b64, sizeof(b64), smk, AEM_SECURITY_MASTERKEY_LEN, sodium_base64_VARIANT_ORIGINAL);
	printf("%s%s\n", msg, b64);
	sodium_memzero(b64, sizeof(b64));
}

int main(void) {
	if (sodium_init() != 0) return 1;

	// Create Users.pv
	const int fd = open("Users.pv", O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		puts("Terminating: Failed creating Users.pv");
		return 1;
	}

	// Generate a valid SMK
	unsigned char smk[AEM_SECURITY_MASTERKEY_LEN];
	unsigned char ma_umk[AEM_SECURITY_MASTERKEY_LEN];
	unsigned char ma_uak[AEM_SECURITY_UAK_LEN];

	for(;;) {
		randombytes_buf(smk, AEM_SECURITY_MASTERKEY_LEN);
		aem_security_kdf(ma_umk, AEM_SECURITY_MASTERKEY_LEN, smk, AEM_SECURITY_KEYID_SERVER_MA_UMK);
		aem_security_kdf(ma_uak, AEM_SECURITY_UAK_LEN, ma_umk, AEM_SECURITY_KEYID_USER_UAK);
		if (aem_security_uid(ma_uak) == 0) break;
	}

	// Print keys
	printMasterKey("SMK=", smk);
	printMasterKey("MA UMK=", ma_umk);
	printApiPk(smk);
	sodium_memzero(ma_umk, crypto_kdf_KEYBYTES);

	// Set user data
	struct pv_user users[4096];
	bzero(users, sizeof(struct pv_user) * 4096);

	users[0].level = 3;
	memcpy(users[0].uak, ma_uak, AEM_SECURITY_UAK_LEN);
	sodium_memzero(ma_uak, AEM_SECURITY_UAK_LEN);

	// Get the Server File Key
	unsigned char sfk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	aem_security_kdf(sfk, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, smk, AEM_SECURITY_KEYID_SERVER_FILE);
	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	// Encrypt the user data
	const size_t lenEnc = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (sizeof(struct pv_user) * PV_USERCOUNT) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	crypto_aead_xchacha20poly1305_ietf_encrypt(enc + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL, (unsigned char*)users, sizeof(struct pv_user) * PV_USERCOUNT, NULL, 0, NULL, enc, sfk);
	sodium_memzero((unsigned char*)users, sizeof(struct pv_user) * PV_USERCOUNT);
	sodium_memzero(sfk, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

	// Write Users.pv and close the file
	if (write(fd, enc, lenEnc) != lenEnc) perror("write");
	close(fd);

	return 0;
}
