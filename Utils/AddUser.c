#include <strings.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/GetKey.h"

struct pv_user {
	unsigned char uak[32]; // User Access Key, grants access to PostVault
	uint32_t userId;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
};

int main() {
	if (sodium_init() != 0) return 1;
	puts("PostVault: AddUser");

	const int fd = open("Users.pv", O_WRONLY | O_CREAT | O_NOCTTY, 600);
	if (fd < 0) {
		puts("Terminating: Failed openign Users.pv");
		return 1;
	}

	const off_t l = lseek(fd, 0, SEEK_END);
	if (l > 0 && l % (sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES) != 0) {
		printf("%ld\n", l);
		puts("Terminating: Users.pv corrupted");
		close(fd);
		return 1;
	}

	struct pv_user u;
	bzero(&u, sizeof(struct pv_user));

	puts("Enter the Server Master Key (SMK)");
	unsigned char smk[crypto_kdf_KEYBYTES];
	if (getKey(smk, crypto_kdf_KEYBYTES) != 0) return -1;

	unsigned char sfk[crypto_aead_chacha20poly1305_KEYBYTES];
	crypto_kdf_derive_from_key(sfk, crypto_aead_chacha20poly1305_KEYBYTES, 1, "PV:FileA", smk);
	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	puts("Enter the User Registration Key (URK)");
	if (getKey((unsigned char*)&u, 36) != 0) return 1;

	uint64_t n = l / (sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES);
	unsigned char enc[sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES];
	crypto_aead_chacha20poly1305_encrypt(enc, NULL, (unsigned char*)&u, sizeof(struct pv_user), NULL, 0, NULL, (unsigned char*)&n, sfk);

	const int ret = write(fd, enc, sizeof(struct pv_user) + crypto_aead_chacha20poly1305_ABYTES);
	close(fd);

	if (ret == 0) printf("User #%lu registered\n", n);
	return ret;
}
