#ifndef __x86_64__ 
	#error Must be used on a 64-bit system
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <locale.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sodium.h>

#include "Common/CreateSocket.h"
#include "Common/ValidFd.h"

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

static bool ptraceDisabled(void) {
	const int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) return false;

	char val;
	if (read(fd, &val, 1) != 1) {close(fd); return false;}

	if (val != '3') {
		val = '3';
		if (
		   pwrite(fd, &val, 1, 0) != 1
		|| pread(fd, &val, 1, 0) != 1
		)  {close(fd); return false;}
	}

	close(fd);
	return (val == '3');
}

int main(void) {
	setlocale(LC_ALL, "C");

	if (getuid() != 0) {puts("Terminating: Must be started as root"); return 1;}
	if (!ptraceDisabled()) {puts("Terminating: Failed disabling ptrace"); return 2;}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 10;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return 11; // Disable core dumps and ptrace
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 12; // Kill early if memory corruption detected

	if (sodium_init() != 0) return 1;
	if (pv_init() != 0) return 99;

	acceptClients();

	return EXIT_SUCCESS;
}
