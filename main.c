#ifndef __x86_64__
	#error Must be run on a 64-bit system
#endif

#include <locale.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "Common/CreateSocket.h"

#include "Request.h"

#include <sodium.h>

static void acceptClients(void) {
	const int sock = createSocket(PV_PORT);
	if (sock < 0) {puts("Failed creating socket"); return;}

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
	setlocale(LC_ALL, "C");
	if (sodium_init() != 0) return 1;

	if (pv_init() != 0) return 99;

	acceptClients();

	return 0;
}
