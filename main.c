#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "simple_inttypes.h"
#include "file_phile.h"

#include "random.h"
#include "encrypt.h"

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;

    return 0;

    size_t size = 0;
    u8* buffer = load_file("", &size);
    if (buffer == NULL) {
        printf("Error reading file\n");
        return 1;
    }

    free(buffer);
    buffer = NULL;
    return 0;
}
