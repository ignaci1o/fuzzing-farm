#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bug: si el input empieza por "CRASH" y tiene >10 bytes, desborda
int parsear(const char *buf, size_t len) {
    char tmp[8];
    if (len > 4 && memcmp(buf, "CRASH", 5) == 0) {
        memcpy(tmp, buf + 5, len - 5);   // sin límite -> overflow
        return tmp[0];
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
