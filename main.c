#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simple_inttypes.h"
#include "file_phile.h"
#include "sha256.h"
#include "random.h"
#include "encrypt.h"

#define MAX_INPUT_LENGTH 128

#define CLEANUP(x) do { printf(x); ret_val = 1; goto cleanup; } while (0)

static int read_line(char* buf, const int size)
{
    if (NULL == fgets(buf, size, stdin)) return 1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

static int ask_string(const char* prompt, char* out, const int out_size)
{
    for (;;) {
        printf("%s: ", prompt);
        if (read_line(out, out_size)) return 1;
        if (out[0] != '\0') return 0;
        printf("  (invalid argument)\n");
    }
}


int main(void)
{
    //                  hash + newline
    static const size_t padding = 33;

    int ret_val = 0;
    u8* key_bytes = NULL;
    u8* buffer = NULL;

    char string_buffer[MAX_INPUT_LENGTH];

    /****************************************************/
    // load target file

    size_t buffer_size;
    if (ask_string("Input target file", string_buffer, MAX_INPUT_LENGTH))
        CLEANUP("Error: could not read argument\n");
    buffer = load_file(string_buffer, &buffer_size);
    if (buffer == NULL)
        CLEANUP("Error: file not found\n");
    /****************************************************/


    /********************************************************************/
    // load key from string
    if (ask_string("Input encryption key (max 128 characters)", string_buffer, MAX_INPUT_LENGTH))
        CLEANUP("Error: could not read argument\n");

    size_t key_size;
    key_bytes = calloc(MAX_INPUT_LENGTH, sizeof *key_bytes);
    if (key_bytes == NULL)
        CLEANUP("Error: failed to allocate key\n");

    memcpy(key_bytes, string_buffer, MAX_INPUT_LENGTH);
    for (key_size = 0; (key_bytes[key_size] != '\0') && (key_size < MAX_INPUT_LENGTH); ++key_size) {}
    if (key_size == 0)
        CLEANUP("Invalid argument of size 0");
    /********************************************************************/


    if (ask_string("Select opperation [e]ncryption | [d]ecryption", string_buffer, MAX_INPUT_LENGTH))
        CLEANUP("Error: could not read argument\n");
    if (string_buffer[0] != 'e' && string_buffer[0] != 'd')
        CLEANUP("Error: invalid argument\n");
    if (string_buffer[1] != '\0')
        CLEANUP("Error: invalid argument\n");

    const char MODE = string_buffer[0];


    // ==================== TEST ==================================
    for (size_t i = 0; i < key_size; ++i) {
        printf("%c", (char)key_bytes[i]);
    }
    printf("\n");
    // ============================================================


    /*************** prepare data ***************/

    // get sha256 hash of key_bytes
    u32 key[8];
    if (sha256(key_bytes, key_size, key))
        CLEANUP("Error: failed generating key\n");

    // init random context, contains encryption key (hash of key_bytes)
    RandomContext context = {0};
    if (random_create(&context, key))
        CLEANUP("Error: failed to create random context\n");

    char* file_name = "FILENAME";
    if (MODE == 'e') {
        /***********************************************************/
        // add padding for file metadata
        u8* tmp = realloc(buffer, buffer_size + padding);
        if (tmp == NULL)
            CLEANUP("Error: failed to realloc\n");
        buffer = tmp;
        memmove(buffer + padding, buffer, buffer_size); // slide buffer forward to make room for metadata
        buffer_size += padding; // update size

        // append metadata


        // generate verification hash
        u32 hash[8];
        if (sha256(buffer, buffer_size, hash))
            CLEANUP("Error generating hash\n");

        // append verification hash



        /***********************************************************/

        if (encrypt(buffer, buffer_size, &context))
            CLEANUP("Error [en/de]crypting buffer\n");

        file_name = "encrypted.enc";
    } else if (MODE == 'd') { // decrypt


        CLEANUP("Not implemented\n");
        file_name = "decrypted";
    }

    if (save_file(buffer, buffer_size, file_name))
        CLEANUP("Error: could not save file\n");

cleanup:
    free(buffer); // unnesasary since the program is ending here anyways but just good practice
    free(key_bytes);
    return ret_val;
}
