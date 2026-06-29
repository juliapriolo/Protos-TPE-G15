#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

#define SERVER_DEFAULT_PORT 1080
#define SERVER_BACKLOG 128
#define SERVER_BUFFER_SIZE 4096

typedef enum {
    CLIENT_STAGE_GREETING = 0,
    CLIENT_STAGE_REQUEST,
    CLIENT_STAGE_RELAY,
    CLIENT_STAGE_CLOSING
} client_stage_t;

typedef struct client_state {
    uint8_t read_buffer[SERVER_BUFFER_SIZE];
    uint8_t write_buffer[SERVER_BUFFER_SIZE];
    uint8_t c2t_buffer[SERVER_BUFFER_SIZE];
    uint8_t t2c_buffer[SERVER_BUFFER_SIZE];

    size_t read_len;
    size_t write_len;
    size_t write_off;
    size_t c2t_len;
    size_t c2t_off;
    size_t t2c_len;
    size_t t2c_off;

    int client_fd;
    int target_fd;
    struct sockaddr_in target_addr;

    client_stage_t stage;
    bool relay_started;
} client_state_t;

int server_run(const char *host, const char *port);

#endif
