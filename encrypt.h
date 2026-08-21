#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "simple_inttypes.h"
#include "random.h"

status_t encrypt(u8* buffer, const size_t src_size);
status_t decrypt(u8* buffer, const size_t src_size);

#endif
