#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "simple_inttypes.h"

int encrypt(u8* dest, const u8* src, const u64 key, const size_t size);

#endif
