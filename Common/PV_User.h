#ifndef PV_USER_H
#define PV_USER_H

#include "AEM_KDF.h"

#define PV_USERCOUNT 4096

struct pv_user {
	uint64_t lastMod: 42;
	uint64_t level: 2;
	uint64_t unused1: 20;
	uint64_t unused2;
	unsigned char unused3[5];
	unsigned char uak[AEM_KDF_UAK_KEYLEN];
};

#endif
