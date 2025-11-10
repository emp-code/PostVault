#ifndef AEM_BINTS_H
#define AEM_BINTS_H

#include <stdint.h>

#define AEM_BINTS_BEGIN 1735689600000 // 2025-01-01 00:00:00 UTC
#define AEM_BINTS_MAX 4398046511103 // 2^42-1

uint64_t getBinTs(void);

#endif
