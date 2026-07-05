#include "include/metrics.h"

static server_metrics_t current_metrics;

void metrics_connection_opened(void) {
    current_metrics.historical_connections++;
    current_metrics.concurrent_connections++;
}

void metrics_connection_closed(void) {
    if (current_metrics.concurrent_connections > 0) {
        current_metrics.concurrent_connections--;
    }
}

void metrics_add_client_to_target_bytes(uint64_t bytes) {
    current_metrics.bytes_client_to_target += bytes;
}

void metrics_add_target_to_client_bytes(uint64_t bytes) {
    current_metrics.bytes_target_to_client += bytes;
}

server_metrics_t metrics_snapshot(void) {
    return current_metrics;
}

uint64_t metrics_total_transferred_bytes(const server_metrics_t *metrics) {
    if (metrics == 0) {
        return 0;
    }

    return metrics->bytes_client_to_target + metrics->bytes_target_to_client;
}
