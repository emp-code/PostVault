#ifndef PV_USER_H
#define PV_USER_H

#include "AEM_KDF.h"

#define PV_USERCOUNT 4096

struct pv_user {
	unsigned char uak[AEM_KDF_SUB_KEYLEN];
	unsigned char lastMod[5];
	unsigned char c1[5];
	uint8_t level: 2;
	uint8_t u1: 2;
	uint8_t u2: 4;
};

#endif
