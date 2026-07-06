#include "include/access_log.h"

#include <stdio.h>
#include <time.h>

#define ACCESS_LOG_FILE "access.log"
#define ACCESS_LOG_TIME_SIZE 32

void access_log_connection(const char *username,
                           const char *host,
                           uint16_t port,
                           bool success) {
    FILE *file = fopen(ACCESS_LOG_FILE, "a");

    if (file == NULL) {
        perror("access log");
        return;
    }

    time_t now = time(NULL);
    struct tm utc_time;
    char timestamp[ACCESS_LOG_TIME_SIZE];

    if (gmtime_r(&now, &utc_time) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc_time) == 0) {
        snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }

    fprintf(
        file,
        "%s user=%s dest=%s port=%hu status=%s\n",
        timestamp,
        username == NULL || username[0] == '\0' ? "anonymous" : username,
        host == NULL || host[0] == '\0' ? "unknown" : host,
        port,
        success ? "OK" : "FAIL"
    );
    fflush(file);
    fclose(file);
}
