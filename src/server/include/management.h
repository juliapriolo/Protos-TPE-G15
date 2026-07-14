#ifndef MANAGEMENT_H
#define MANAGEMENT_H

#include <stddef.h>

#include "../../utils/include/selector.h"

#define MANAGEMENT_BUFFER_SIZE 1024

typedef struct management_state {
    char read_buffer[MANAGEMENT_BUFFER_SIZE];
    char write_buffer[MANAGEMENT_BUFFER_SIZE];
    size_t read_len;
    size_t write_len;
    size_t write_off;
} management_state_t;

extern const fd_handler management_accept_handler;

#endif
