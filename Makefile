CC=gcc
CFLAGS=-O2 -march=native -pipe -std=gnu2x -Wall -Wextra -Wpedantic -Wno-comment -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Werror=incompatible-pointer-types -Werror=implicit-function-declaration -Werror=discarded-array-qualifiers -Werror=alloc-zero -Wbidi-chars=any  -Wduplicated-branches -Wfloat-equal -Wshadow -Wbad-function-cast -Wcast-qual -Wcast-align -Wlogical-op -Wmissing-declarations -Winvalid-utf8 -Wpadded -Wredundant-decls -Wstrict-prototypes -Wunused-macros -Wwrite-strings -Wpointer-arith -Wstack-usage=999999 -Wtrampolines -Wno-format -fanalyzer

all: PostVault
#PV_AddUser PV_MakeUser

PostVault: *.c Common/*.c
	$(CC) $(CFLAGS) -DPV_LOCAL -DPV_PORT=308 -o PostVault *.c Common/*.c -lsodium -lcap -lm

PV_AddUser: Utils/AddUser.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c
	$(CC) $(CFLAGS) -o Utils/PV_AddUser Utils/AddUser.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

PV_MakeUser: Utils/MakeUser.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c
	$(CC) $(CFLAGS) -o Utils/PV_MakeUser -DAEM_KDF_UMK Utils/MakeUser.c Common/AEM_KDF.c Common/GetKey.c Common/ToggleEcho.c -lsodium

.PHONY: clean
clean:
	-rm PostVault PV_AddUser PV_MakeUser
