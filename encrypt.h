#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "error.h"
#include "simple_inttypes.h"
#include "random.h"

status_t encrypt(u8* dest, u8* src, const size_t dest_size, const size_t src_size, RandomContext* context);

#endif
