/*
TODO
- strip padding from decrypted output
*/

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
#define PAD_MOD 840

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
    // hash + padding length + newline
    static const size_t header_size = 32 + 8 + 1;
    static const char* const ENC_STR = "encrypted.enc";
    static const char* const DEC_STR = "decrypted.enc";

    int ret_val = 0;
    u8* key_bytes = NULL;
    u8* buffer = NULL;

    char string_buffer[MAX_INPUT_LENGTH];

    /****************************************************/
    // load target file
    size_t buffer_size;
    if (ask_string("Input target file (max 128 characters)", string_buffer, MAX_INPUT_LENGTH))
        CLEANUP("Error: could not read argument\n");
    buffer = load_file(string_buffer, &buffer_size);
    if (buffer == NULL)
        CLEANUP("Error: file not found\n");

    /****************************************************/


    /********************************************************************/
    // load key from string
    if (ask_string("Input encryption key (max 32 characters)", string_buffer, MAX_INPUT_LENGTH))
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
    // for (size_t i = 0; i < key_size; ++i) {
    //     printf("%c", (char)key_bytes[i]);
    // }
    // printf("\n");
    // ============================================================


    /*************** prepare data ***************/
    // get sha256 hash of key_bytes
    u32 key[8];
    if (sha256(key_bytes, key_size, key))
        CLEANUP("Error: failed generating key\n");

    if (random_create(key))
         CLEANUP("Error: failed to initialize random context\n");

    u32 hash[8];
    size_t padding = 1313131313;
    if (MODE == 'e') {
        /***********************************************************/
        // add padding for file metadata - final size needs to be a multiple of 840
        padding = PAD_MOD - ((buffer_size + header_size) % PAD_MOD);
        u8* tmp = realloc(buffer, buffer_size + header_size + padding);
        if (tmp == NULL)
            CLEANUP("Error: failed to realloc\n");
        buffer = tmp;
        memset(buffer + buffer_size, 0, header_size + padding); // clear new memory
        memmove(buffer + header_size, buffer, buffer_size); // slide buffer forward to make room for metadata
        buffer_size += header_size + padding; // update size
        memset(buffer, 0, header_size); // clear header

        // insert metadata
        buffer[header_size - 1] = '\n';

        // insert padding length
        printf("Inserted %zu padded bytes\n", padding);
        memcpy(buffer + 32, &padding, 8);

        // generate verification hash
        if (sha256(buffer, buffer_size, hash))
            CLEANUP("Error: failed generating hash\n");

        // insert verification hash - 32 bytes reserved at buffer start
        memcpy(buffer, hash, 32);

        // TEST
        // if (save_file(buffer, buffer_size, "debug_in.enc"))
        //     CLEANUP("Error: could not save file\n");
        /***********************************************************/

        if (encrypt(buffer, buffer_size))
            CLEANUP("Error: failed encrypting buffer\n");

    } else if (MODE == 'd') { // decrypt

        if (decrypt(buffer, buffer_size))
            CLEANUP("Error: failed decrypting buffer\n");

        // TEST
        // if (save_file(buffer, buffer_size, "debug.enc"))
        //     CLEANUP("Error: could not save file\n");

        // extract padding
        padding = 1212121212;
        memcpy(&padding, buffer + 32, 8);

        u32 new_hash[8];
        memcpy(hash, buffer, 32);
        memset(buffer, 0, 32);
        if (sha256(buffer, buffer_size, new_hash))
            CLEANUP("Error: failed to verify hash\n");

        // printf("    Hash | New Hash \n");
        for (int i = 0; i < 8; ++i) {
            // printf("%08x | %08x\n", hash[i], new_hash[i]);
            if (hash[i] == new_hash[i]) continue;
            printf("Invalid hash. Opperation canceled\n");
            padding = 0;
            goto cleanup;

        }
        printf("Success: hash verified\n");
        printf("Truncating %zu padded bytes\n", padding);

    }

    if (MODE == 'd') {
        if (save_file(buffer + header_size, buffer_size - header_size - padding, DEC_STR))
            CLEANUP("Error: could not save file\n");
    } else {
        if (save_file(buffer, buffer_size, ENC_STR))
            CLEANUP("Error: could not save file\n");
    }

cleanup:
    free(buffer); // unnesasary since the program is ending here anyways but just good practice
    free(key_bytes);
    random_destroy();
    return ret_val;
}
