#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "simple_inttypes.h"
#include "file_phile.h"
#include "sha256.h"
#include "random.h"
#include "encrypt.h"

int main(int argc, char* argv[])
{
    int ret_val = 0;

    if (argc != 3) {
        printf("Usage: ./main <file path (data)> <file path (key)>\n");
        return 1;
    }

    RandomContext context = {0};

    size_t size;
    u8* buffer = load_file(argv[2], &size);
    if (buffer == NULL) {
        printf("Error: file: %s not found\n", argv[2]);
        return 1;
    }

    u32 hash[8];
    if (sha256(buffer, size, hash)) {
        printf("Error generating hash\n");
        ret_val = 1;
        goto cleanup;
    }

    if (random_create(&context, hash)) {
        printf("Error creating random context\n");
        ret_val = 1;
        goto cleanup;
    }

    if (random_get(&context, 0)) {
        printf("Error\n");
        ret_val = 1;
        goto cleanup;
    }

    for (int i = 0; i < 8; i++) {
        printf("%08x", context.data[i]);
    }
    printf("\n");


cleanup:
    free(buffer); // unnesasary since the program is ending here anyways but just good practice
    buffer = NULL;
    return ret_val;
}
