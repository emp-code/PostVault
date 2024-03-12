#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/AEM_Security.h"
#include "../Common/GetKey.h"
#include "../Common/PV_User.h"

static void printMasterKey(const char * const msg, const unsigned char smk[AEM_SECURITY_MASTERKEY_LEN]) {
	char b64[65];
	sodium_bin2base64(b64, sizeof(b64), smk, AEM_SECURITY_MASTERKEY_LEN, sodium_base64_VARIANT_ORIGINAL);
	printf("%s%s\n", msg, b64);
	sodium_memzero(b64, sizeof(b64));
}

int main(int argc, char *argv[]) {
	if (sodium_init() != 0) return 1;

	if (argc != 3 || strlen(argv[2]) != 3 || ((strlen(argv[1]) != 8 || (strcmp(argv[1], "Users.pv") != 0)) && (strlen(argv[1]) < 9 || strcmp(argv[1] + strlen(argv[1]) - 9, "/Users.pv") != 0)) || argv[2][0] < 'a' || argv[2][1] < 'a' || argv[2][2] < 'a' || argv[2][0] > 'p' || argv[2][1] > 'p' || argv[2][2] > 'p') {
		printf("Usage %s Users.pv username (aaa-ppp)\n", argv[0]);
		return 1;
	}

	// Open the file
	const int fd = open(argv[1], O_RDWR | O_NOCTTY);
	if (fd < 0) {
		printf("Terminating: Failed opening %s\n", argv[1]);
		return 1;
	}

	// Ask for the Server Master Key
	unsigned char smk[AEM_SECURITY_MASTERKEY_LEN];
	printf("Enter the Server Master Key (SMK) for %s\n", argv[1]);
	if (getKey(smk, AEM_SECURITY_MASTERKEY_LEN) != 0) return -1;

	// Get the Server File Key
	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_security_kdf(sfk, crypto_aead_aegis256_KEYBYTES, smk, AEM_SECURITY_KEYID_SMK_PV_FILE);
	sodium_memzero(smk, AEM_SECURITY_MASTERKEY_LEN);

	// Load the user data
	struct pv_user users[4096];
	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * 4096) + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	if (read(fd, enc, lenEnc) != lenEnc) {
		printf("Failed reading %s\n", argv[1]);
		close(fd);
		return 1;
	}

	if (crypto_aead_aegis256_decrypt((unsigned char*)users, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, sfk) != 0) {
		puts("Failed decrypting data. Incorrect SMK?");
		close(fd);
		return 1;
	}

	// Verify the UserID isn't already taken
	const uint16_t desired_uid = (argv[2][0] - 'a') | ((argv[2][1] - 'a') << 4) | ((argv[2][2] - 'a') << 8);
	if (!sodium_is_zero(users[desired_uid].uak, AEM_SECURITY_UAK_LEN)) {
		puts("UserID already taken");
		close(fd);
		return 1;
	}

	// Generate a valid UMK for the chosen UserID
	unsigned char new_umk[AEM_SECURITY_MASTERKEY_LEN];
	unsigned char new_uak[AEM_SECURITY_UAK_LEN];

	for(;;) {
		randombytes_buf(new_umk, AEM_SECURITY_MASTERKEY_LEN);
		aem_security_kdf(new_uak, AEM_SECURITY_UAK_LEN, new_umk, AEM_SECURITY_KEYID_UMK_UAK);
		if (aem_security_uid(new_uak) == desired_uid) break;
	}

	printMasterKey("UMK=", new_umk);
	sodium_memzero(new_umk, AEM_SECURITY_MASTERKEY_LEN);

	// Set the new user's data
	memcpy(users[desired_uid].uak, new_uak, AEM_SECURITY_UAK_LEN);
	sodium_memzero(new_uak, AEM_SECURITY_UAK_LEN);

	// Encrypt the user data
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, (unsigned char*)users, sizeof(struct pv_user) * 4096, NULL, 0, NULL, enc, sfk);
	sodium_memzero((unsigned char*)users, sizeof(struct pv_user) * 4096);
	sodium_memzero(sfk, crypto_aead_aegis256_KEYBYTES);

	// Write the user data and close the file
	if (pwrite(fd, enc, lenEnc, 0) != lenEnc) perror("write");
	close(fd);

	return 0;
}
