#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

typedef struct server_metrics {
    uint64_t historical_connections;
    uint64_t concurrent_connections;
    uint64_t bytes_client_to_target;
    uint64_t bytes_target_to_client;
} server_metrics_t;

void metrics_connection_opened(void);
void metrics_connection_closed(void);
void metrics_add_client_to_target_bytes(uint64_t bytes);
void metrics_add_target_to_client_bytes(uint64_t bytes);
server_metrics_t metrics_snapshot(void);
uint64_t metrics_total_transferred_bytes(const server_metrics_t *metrics);

#endif
