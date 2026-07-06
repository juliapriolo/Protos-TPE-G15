#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <stdbool.h>
#include <stdint.h>

void access_log_connection(const char *username,
                           const char *host,
                           uint16_t port,
                           bool success);

#endif
