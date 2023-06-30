#include <strings.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sodium.h>

#include "../Common/GetKey.h"

struct pv_user {
	unsigned char uak[crypto_aead_aes256gcm_KEYBYTES]; // User API Key
	unsigned char lastMod[5]; // To protect against replay attacks
	unsigned char c1[5];
	uint8_t level: 2;
	uint8_t u1: 4;
	uint8_t u2: 2;
};

int main(void) {
	if (sodium_init() != 0) return 1;

	const int fd = open("Users.pv", O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY, 600);
	if (fd < 0) {
		puts("Terminating: Failed creating Users.pv");
		return 1;
	}

	struct pv_user users[4096];
	bzero(users, sizeof(struct pv_user) * 4096);

	// Get keys
	puts("Enter the Server Master Key (SMK)");
	unsigned char smk[crypto_kdf_KEYBYTES];
	if (getKey(smk, crypto_kdf_KEYBYTES) != 0) return -1;

	unsigned char sfk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	crypto_kdf_derive_from_key(sfk, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 1, "PVt:Fil0", smk);

	// Get Master Admin's keys
	unsigned char ma_umk[crypto_kdf_KEYBYTES];
	crypto_kdf_derive_from_key(ma_umk, crypto_kdf_KEYBYTES, 1, "AEM_Usr0", smk);
	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	unsigned char ma_uak[crypto_aead_aes256gcm_KEYBYTES];
	crypto_kdf_derive_from_key(ma_uak, crypto_aead_aes256gcm_KEYBYTES, 1, "PVt-Uak0", ma_umk);
	sodium_memzero(ma_umk, crypto_kdf_KEYBYTES);

	// Get MA's UserID
	uint16_t uid_base[crypto_aead_chacha20poly1305_ABYTES / 2];
	crypto_aead_chacha20poly1305_encrypt((unsigned char*)uid_base, NULL, (const unsigned char*)"UserID", 6, NULL, 0, NULL, (unsigned char[]){0,0,0,0,0,0,0,0}, ma_uak);
	const uint16_t ma_uid = uid_base[0] & 4095;
	printf("MA UID: %u\n", ma_uid);

	// Set MA's data
	users[ma_uid].level = 3;
	memcpy(users[ma_uid].uak, ma_uak, crypto_aead_aes256gcm_KEYBYTES);
	sodium_memzero(ma_uak, crypto_aead_aes256gcm_KEYBYTES);

	// Encrypt the user data
	const size_t lenEnc = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (sizeof(struct pv_user) * 4096) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	crypto_aead_xchacha20poly1305_ietf_encrypt(enc + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL, (unsigned char*)users, sizeof(struct pv_user) * 4096, NULL, 0, NULL, enc, sfk);
	sodium_memzero((unsigned char*)users, sizeof(struct pv_user) * 4096);

	// Write Users.pv
	if (write(fd, enc, lenEnc) != lenEnc) perror("write");
	close(fd);

	return 0;
}
