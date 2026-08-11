#ifndef ENCRYPT_ERROR_H
#define ENCRYPT_ERROR_H

#define ERROR_FAIL(x) do {fprintf(stderr, "%s failed at %s:%d: %s\n", __func__, __FILE__, __LINE__, error_parse(x)); return (x);} while (0)

typedef enum {
    ERR_NONE = 0,
    ERR_OOB,
    ERR_SHA,
    ERR_NULL,
} status_t;

char* error_parse(const status_t err);

#endif
