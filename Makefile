CC=gcc
CFLAGS=-O2 -march=native -pipe -Wall -Wextra -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration

all: PostVault

PostVault: *.c Common/*.c
	$(CC) $(CFLAGS) -o PostVault *.c Common/*.c -lsodium -lcap

.PHONY: clean
clean:
	-rm PostVault
