#include <arpa/inet.h>
#include <sys/socket.h>
#include <strings.h>

#include "CreateSocket.h"

__attribute__((warn_unused_result))
int createSocket(const int port) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) return -1;

	struct sockaddr_in servAddr;
	bzero((char*) &servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*) &servAddr, sizeof(servAddr)) != 0) return -1;

	listen(sock, 10);
	return sock;
}
