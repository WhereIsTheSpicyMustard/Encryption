#include "file_phile.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


// manually free buffer after use
uint8_t* load_file(const char* filename, size_t* size)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) return NULL;

    fseek(fp, 0, SEEK_END);
    const long file_size = ftell(fp);
    rewind(fp);

    if (file_size < 0) {
        fclose(fp);
        return NULL;
    }

    uint8_t* buffer = malloc((size_t)file_size);

    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }

    const size_t bytes_read = fread(buffer, 1, (size_t)file_size, fp);

    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return NULL;
    }

    *size = (size_t)file_size;
    return buffer;
}

int save_file(const uint8_t* byte_arr, const size_t count, const char* filename)
{
    if (byte_arr == NULL || filename == NULL) return 1;
    if (count == 0) return 0;

    FILE* fp = fopen(filename, "wb");
    if (fp == NULL) return 1;

    if (fwrite(byte_arr, 1, count, fp) != count) {
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
}

