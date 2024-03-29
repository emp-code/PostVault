#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "memeq.h"

#include "CreateSocket.h"

__attribute__((warn_unused_result))
int createSocket(const int port) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) return -1;

	struct sockaddr_in servAddr;
	bzero((char*) &servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(port);

	const int intTrue = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int)) != 0) {close(sock); return -1;}

#ifdef PV_LOCAL
	servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) != 0) {close(sock); return -1;}
	if (setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (const void*)&intTrue, sizeof(int)) != 0) {close(sock); return -1;}
#else
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	struct if_nameindex * const ni = if_nameindex();
	for (int i = 0;; i++) {
		if (ni[i].if_index == 0) {if_freenameindex(ni); close(sock); return -1;}
		if (memeq(ni[i].if_name, "lo", 2)) continue;
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ni[i].if_name, strlen(ni[i].if_name) + 1) != 0) {if_freenameindex(ni); close(sock); return -1;}
		break;
	}
	if_freenameindex(ni);
#endif

	if (bind(sock, (struct sockaddr*) &servAddr, sizeof(servAddr)) != 0) {close(sock); return -1;}

	listen(sock, 10);
	return sock;
}
