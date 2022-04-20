#ifndef __x86_64__ 
	#error Must be used on a 64-bit system
#endif

#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/socket.h>

#include <unistd.h>

#include <sodium.h>

#include "Common/CreateSocket.h"
#include "Server.h"

#define PV_PORT 888

static void acceptClients(void) {
	const int sock = createSocket(PV_PORT, true, 10, 10);
	if (sock < 0) return;

	puts("Ready");

	while (1) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;
		respondClient(newSock);
		close(newSock);
	}

	close(sock);
}

int main(void) {
	if (sodium_init() != 0) return 1;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 10;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return 11; // Disable core dumps and ptrace
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 12; // Kill early if memory corruption detected

	if (pv_init() != 0) return 99;

	acceptClients();

	return EXIT_SUCCESS;
}
