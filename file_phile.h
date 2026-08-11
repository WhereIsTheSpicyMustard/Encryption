#ifndef FILE_PHILE_H
#define FILE_PHILE_H

#include <stddef.h>
#include <stdint.h>

uint8_t* load_file (const char* filename, size_t* size);
int save_file (const uint8_t* byte_arr, const size_t count, const char* filename);

#endif
