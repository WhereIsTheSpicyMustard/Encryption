#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simple_inttypes.h"
#include "file_phile.h"
#include "sha256.h"
#include "random.h"
#include "encrypt.h"

#define CLEANUP(x) do { printf(x); ret_val = 1; goto cleanup; } while (0)

int main(int argc, char* argv[])
{
    int ret_val = 0;
    u8* key_bytes = NULL;
    u8* buffer = NULL;
    u8* buffer_out = NULL;

    if (argc != 2) {
        printf("Usage: <file path (data)>\n");
        return 1;
    }

    /*************** load buffer as bytes ***************/
    size_t buffer_size;
    buffer = load_file(argv[1], &buffer_size);
    if (buffer == NULL) {
        printf("Error: file %s not found\n", argv[1]);
        return 1;
    }
    /****************************************************/


    /*************** prompt input type ******************/
    char input_type[16] = {0};
    printf("Select input type [f]ile or [s]tring: ");
    if (fgets(input_type, 16, stdin) == NULL)
        CLEANUP("Error reading argument\n");
    /****************************************************/


    /*************** load key from file or string ******************/
    char key_input[128];
    size_t key_size;
    switch (input_type[0]) {
        case 'f':
            printf("Input file path: ");

            if (fgets(key_input, 128, stdin) == NULL)
                CLEANUP("Error reading argument\n");

            key_input[strcspn(key_input, "\n")] = '\0'; // strip trailing newline
            key_bytes = load_file(key_input, &key_size);

            if (key_bytes == NULL)
                CLEANUP("Error: failed to load file\n");

        break;
        case 's':
            printf("Input string: ");
            key_bytes = calloc(128, sizeof *key_bytes);

            if (key_bytes == NULL)
                CLEANUP("Error: failed to allocate key\n");

            if (fgets(key_input, 128, stdin) == NULL)
                CLEANUP("Error reading argument\n");

            memcpy(key_bytes, key_input, 128);
            for (key_size = 0; (key_bytes[key_size] != '\0') && (key_size < 128); ++key_size) {}
            if (key_size == 0)
                CLEANUP("Invalid argument of size 0");

            --key_size; // exclude \n character

        break;
        default: CLEANUP("Invalid argument\n");
    }
    /********************************************************************/


    // ==================== TEST ==================================
    // for (size_t i = 0; i < key_size; ++i) {
    //     printf("%c", (char)key[i]);
    // }
    // printf("\n");
    // ============================================================


    /*************** prepare data ***************/

    // get sha256 hash of key
    u32 hash[8];
    if (sha256(key_bytes, key_size, hash))
        CLEANUP("Error generating hash\n");

    // init random context -- contains encryption key (hash of key_bytes)
    RandomContext context = {0};
    if (random_create(&context, hash))
        CLEANUP("Error creating random context\n");

    const size_t buffer_out_size = buffer_size;
    buffer_out = calloc(buffer_out_size, 1);
    if (encrypt(buffer_out, buffer, buffer_out_size, buffer_size, &context)) {
        CLEANUP("Error [en/de]crypting buffer\n");
    }

    if (save_file(buffer_out, buffer_out_size, "output.enc"))
        CLEANUP("Error saving file\n");

cleanup:
    free(buffer); // unnesasary since the program is ending here anyways but just good practice
    free(buffer_out);
    free(key_bytes);
    return ret_val;
}
