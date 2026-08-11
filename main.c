#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simple_inttypes.h"
#include "file_phile.h"
#include "sha256.h"
#include "random.h"
#include "encrypt.h"

typedef enum {
    F,S
} Mode;

int main(int argc, char* argv[])
{
    int mode;
    int ret_val = 0;
    u8* key = NULL;

    if (argc != 2) {
        printf("Usage: <file path (data)>\n");
        return 1;
    }

    size_t buffer_size;
    u8* buffer = load_file(argv[1], &buffer_size);
    if (buffer == NULL) {
        printf("Error: file %s not found\n", argv[1]);
        return 1;
    }

    char key_input[128];
    printf("Select input type [f]ile or [s]tring: ");
    if (fgets(key_input, 128, stdin) == NULL) {
        printf("Error reading argument\n");
        ret_val = 1;
        goto cleanup;
    }

    switch (key_input[0]) {
        case 'f':
            printf("Input file path: ");
            mode = F;
            break;
        case 's':
            printf("Input string: ");
            mode = S;
            break;
        default:
            printf("Invalid argument\n");
            ret_val = 1;
            goto cleanup;
    }

    if (fgets(key_input, 128, stdin) == NULL) {
        printf("Error reading argument\n");
        ret_val = 1;
        goto cleanup;
    }

    size_t key_size;
    if (mode == F) {
        key = load_file(key_input, &key_size);
    } else {
        key = calloc(128, 1);
    }

    if (key == NULL) {
        printf("Error: failed to allocate %s\n", key_input);
        ret_val = 1;
        goto cleanup;
    }

    if (mode == S) {
        memcpy(key, key_input, 128);
        for (key_size = 0; (key[key_size] != '\0') && key_size < 128; key_size++) {}
        --key_size; // exclude \n character
    }





    RandomContext context = {0};

    // get sha256 hash of keyfile
    u32 hash[8];
    if (sha256(buffer, buffer_size, hash)) {
        printf("Error generating hash\n");
        ret_val = 1;
        goto cleanup;
    }

    if (random_create(&context, hash)) {
        printf("Error creating random context\n");
        ret_val = 1;
        goto cleanup;
    }


cleanup:
    free(buffer); // unnesasary since the program is ending here anyways but just good practice
    free(key);
    buffer = NULL;
    key = NULL;
    return ret_val;
}
