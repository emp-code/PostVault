#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/GetKey.h"
#include "../Common/PV_User.h"

int main(void) {
	if (sodium_init() != 0) return 1;

	// Ask for the Server Master Key
	unsigned char smk[AEM_KDF_SMK_KEYLEN];
	if (getKey(smk) != 0) return -1;

	// Create Users.pv
	const int fd = open("Users.pv", O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		puts("Terminating: Failed creating Users.pv");
		return 1;
	}

	// Set user data
	struct pv_user users[4096];
	bzero(users, sizeof(struct pv_user) * 4096);

	users[0].level = 3;

	unsigned char ma_umk[AEM_KDF_UMK_KEYLEN];
	aem_kdf_smk(ma_umk, AEM_KDF_UMK_KEYLEN, AEM_KDF_KEYID_SMK_UMK, smk);
	aem_kdf_umk(users[0].uak, AEM_KDF_UAK_KEYLEN, AEM_KDF_KEYID_UMK_UAK, ma_umk);

	// Get the Server File Key
	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_smk(sfk, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_PV_FILE, smk);
	sodium_memzero(smk, AEM_KDF_SMK_KEYLEN);

	// Encrypt the user data
	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * PV_USERCOUNT) + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, (unsigned char*)users, sizeof(struct pv_user) * PV_USERCOUNT, NULL, 0, NULL, enc, sfk);
	sodium_memzero((unsigned char*)users, sizeof(struct pv_user) * PV_USERCOUNT);
	sodium_memzero(sfk, crypto_aead_aegis256_KEYBYTES);

	// Write Users.pv and close the file
	if (write(fd, enc, lenEnc) != lenEnc) perror("write");
	close(fd);

	return 0;
}
