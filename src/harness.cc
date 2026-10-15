#include <stdint.h>
#include <stddef.h>

extern "C" int parsear(const char *buf, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parsear((const char *)data, size);
    return 0;
}
