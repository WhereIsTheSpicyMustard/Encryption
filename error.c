#include "error.h"

char* error_parse(const status_t err)
{
    switch (err) {
        case ERR_NONE:   return "Error: none";
        case ERR_OOB:    return "Error: array index out of bounds";
        case ERR_SHA:    return "Error: SHA256 failed";
        case ERR_NULL:   return "Error: NULL pointer";
        default:         return "Error: uknown";
    }
}
