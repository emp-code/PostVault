#ifndef __x86_64__
	#error Must be run on a 64-bit system
#endif

#include <grp.h>
#include <linux/securebits.h>
#include <locale.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>

#include "Request.h"

static int setCaps(void) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	const cap_value_t capVals[8] = {
		CAP_DAC_OVERRIDE, // Bypass file permission checks
		CAP_NET_BIND_SERVICE, // Bind to port #<1024
		CAP_NET_RAW, // Bind to specific interfaces
		CAP_SETGID, // Set group IDs
		CAP_SETPCAP, // Allow capability/secbit changes
		CAP_SETUID, // Set user ID
		CAP_SYS_CHROOT, // Allow chroot
		CAP_SYS_RESOURCE // Allow changing resource limits
	};

	cap_t caps = cap_get_proc();

	return (
	   cap_clear(caps) == 0
	&& cap_set_flag(caps, CAP_PERMITTED, 8, capVals, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_EFFECTIVE, 8, capVals, CAP_SET) == 0
	&& cap_set_proc(caps) == 0
	&& cap_free(caps) == 0
	&& prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED) == 0
	) ? 0 : -1;
}

int main(void) {
	if (sodium_init() == -1) return 1;

	setlocale(LC_ALL, "C");

	if (unshare(
		  CLONE_FILES // File descriptor table
		| CLONE_FS // chroot/chdir/umask
		| CLONE_NEWIPC // Unused
		| CLONE_NEWNS // Mount namespace
		| CLONE_NEWUTS // Hostname
		| CLONE_SYSVSEM // Unused
	) != 0) return 2;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)         != 0) return 3;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)             != 0) return 4; // Disable core dumps and ptrace
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 5; // Kill early if memory corruption detected

	if (setCaps() != 0) return 6;

	const struct passwd * const p = getpwnam("postvault");
	if (p == NULL) return 7;

	if (chroot("/var/lib/PostVault") != 0 || chdir("/") != 0) return 8;

	if (pv_init() < 0) return 9;

	if (setgroups(0, NULL) != 0
	|| setgid(p->pw_gid) != 0
	|| setuid(p->pw_uid) != 0
	) return 10;

	acceptClients();
	return 0;
}
