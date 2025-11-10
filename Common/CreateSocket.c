#include <sys/socket.h>
#include <syslog.h>
#include <sys/un.h>
#include <unistd.h>

#include "CreateSocket.h"

__attribute__((warn_unused_result))
int createSocket(void) {
	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "socket failed: %m"); return -1;}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, "\0PostVault", 10);

	if (bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + 10) != 0) {syslog(LOG_ERR, "bind failed: %m"); close(sock); return -1;}
	if (listen(sock, 100) != 0) {syslog(LOG_ERR, "listen failed: %m"); close(sock); return -1;}

	return sock;
}
