#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

int sha256 (uint8_t* M, size_t length, uint32_t H[8]);

#endif
