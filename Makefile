CC=gcc
CFLAGS=-DPV_PORT=1307 -O2 -march=native -pipe -Wall -Wextra -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration -Werror=discarded-array-qualifiers -fanalyzer

all: PostVault PV_AddUser

PostVault: *.c Common/*.c
	$(CC) $(CFLAGS) -o PostVault *.c Common/*.c -lsodium -lcap

PV_AddUser: Utils/AddUser.c Common/GetKey.c Common/ToggleEcho.c
	$(CC) $(CFLAGS) -o PV_AddUser Utils/AddUser.c Common/GetKey.c Common/ToggleEcho.c -lsodium

.PHONY: clean
clean:
	-rm PostVault PV_AddUser
