#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/GetKey.h"
#include "../Common/PV_User.h"

int main(int argc, char *argv[]) {
	if (sodium_init() != 0) return 1;

	if (argc != 3 || ((strlen(argv[1]) != 8 || (strcmp(argv[1], "Users.pv") != 0)) && (strlen(argv[1]) < 9 || strcmp(argv[1] + strlen(argv[1]) - 9, "/Users.pv") != 0)) || strlen(argv[2]) != AEM_KDF_SUB_KEYLEN * 2) {
		printf("Usage: %s Users.pv UAK-in-hex\n", argv[0]);
		return 1;
	}

	unsigned char new_uak[AEM_KDF_SUB_KEYLEN];
	sodium_hex2bin(new_uak, AEM_KDF_SUB_KEYLEN, argv[2], AEM_KDF_SUB_KEYLEN * 2, NULL, NULL, NULL);

	// Open the file
	const int fd = open(argv[1], O_RDWR | O_NOCTTY);
	if (fd < 0) {
		perror("Terminating: Failed opening file");
		return 1;
	}

	// Ask for the Server Master Key
	unsigned char smk[AEM_KDF_MASTER_KEYLEN];
	if (getKey(smk) != 0) return -1;

	// Get the Server File Key
	unsigned char sfk[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_master(sfk, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_PV_FILE, smk);
	sodium_memzero(smk, AEM_KDF_MASTER_KEYLEN);

	// Load the user data
	struct pv_user users[4096];
	const size_t lenEnc = crypto_aead_aegis256_NPUBBYTES + (sizeof(struct pv_user) * 4096) + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	if (read(fd, enc, lenEnc) != lenEnc) {
		perror("Failed reading Users.pv");
		close(fd);
		return 1;
	}

	if (crypto_aead_aegis256_decrypt((unsigned char*)users, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, sfk) != 0) {
		puts("Failed decrypting data. Incorrect SMK?");
		close(fd);
		return 1;
	}

	// Verify the UserID isn't already taken
	const uint16_t new_uid = aem_getUserId(new_uak);
	if (!sodium_is_zero(users[new_uid].uak, AEM_KDF_SUB_KEYLEN)) {
		printf("UserID %d already taken\n", new_uid);
		close(fd);
		return 1;
	}

	// Set the new user's data
	memcpy(users[new_uid].uak, new_uak, AEM_KDF_SUB_KEYLEN);
	sodium_memzero(new_uak, AEM_KDF_SUB_KEYLEN);

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
