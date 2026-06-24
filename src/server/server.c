#include "include/server.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "../utils/include/selector.h"

static volatile sig_atomic_t done = 0;

static void sigterm_handler(const int signal) {
    (void) signal;
    done = 1;
}

static int set_nonblocking(const int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_passive_socket(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *current = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int addr_status = getaddrinfo(host, port, &hints, &result);

    if (addr_status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addr_status));
        return -1;
    }

    int server_fd = -1;

    for (current = result; current != NULL; current = current->ai_next) {
        server_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);

        if (server_fd == -1) {
            continue;
        }

        int option = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

        if (set_nonblocking(server_fd) == -1) {
            close(server_fd);
            server_fd = -1;
            continue;
        }

        if (bind(server_fd, current->ai_addr, current->ai_addrlen) == -1) {
            close(server_fd);
            server_fd = -1;
            continue;
        }

        if (listen(server_fd, SERVER_BACKLOG) == -1) {
            close(server_fd);
            server_fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(result);
    return server_fd;
}

static void client_close(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state != NULL) {
        free(state);
    }

    close(key->fd);
}

static void client_write(struct selector_key *key) {
    client_state_t *state = key->data;

    while (state->write_off < state->write_len) {
        ssize_t sent = send(
            key->fd,
            state->write_buffer + state->write_off,
            state->write_len - state->write_off,
            MSG_NOSIGNAL
        );

        if (sent > 0) {
            state->write_off += (size_t) sent;
            continue;
        }

        if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }

        selector_unregister_fd(key->s, key->fd);
        client_close(key);
        return;
    }

    state->write_len = 0;
    state->write_off = 0;

    if (state->stage == CLIENT_STAGE_CLOSING) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    selector_set_interest_key(key, OP_READ);
}

static void prepare_test_response(client_state_t *state) {
    const char *message = "SOCKS5 server skeleton alive\n";

    state->write_len = strlen(message);
    state->write_off = 0;

    memcpy(state->write_buffer, message, state->write_len);
}

static void client_read(struct selector_key *key) {
    client_state_t *state = key->data;

    ssize_t received = recv(
        key->fd,
        state->read_buffer,
        sizeof(state->read_buffer),
        0
    );

    if (received > 0) {
        state->read_len = (size_t) received;

        /*
         * Por ahora esto NO parsea SOCKS5.
         * Este punto después se reemplaza por:
         *
         * CLIENT_STAGE_GREETING:
         *   leer VER, NMETHODS, METHODS
         *
         * CLIENT_STAGE_REQUEST:
         *   leer CMD, ATYP, DST.ADDR, DST.PORT
         *
         * CLIENT_STAGE_RELAY:
         *   copiar bytes entre cliente y destino
         */

        prepare_test_response(state);
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    if (received == 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
    }

    selector_unregister_fd(key->s, key->fd);
}

static const fd_handler client_handler = {
    .handle_read = client_read,
    .handle_write = client_write,
    .handle_close = client_close,
};

static void accept_connection(struct selector_key *key) {
    while (true) {
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_fd = accept(
            key->fd,
            (struct sockaddr *) &client_addr,
            &client_addr_len
        );

        if (client_fd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }

            perror("accept");
            return;
        }

        if (set_nonblocking(client_fd) == -1) {
            close(client_fd);
            continue;
        }

        client_state_t *state = calloc(1, sizeof(*state));

        if (state == NULL) {
            close(client_fd);
            continue;
        }

        state->stage = CLIENT_STAGE_GREETING;

        selector_status status = selector_register(
            key->s,
            client_fd,
            &client_handler,
            OP_READ,
            state
        );

        if (status != SELECTOR_SUCCESS) {
            free(state);
            close(client_fd);
        }
    }
}

static const fd_handler accept_handler = {
    .handle_read = accept_connection,
};

int server_run(const char *host, const char *port) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (port == NULL) {
        port = "1080";
    }

    int server_fd = create_passive_socket(host, port);

    if (server_fd == -1) {
        fprintf(stderr, "could not create passive socket\n");
        return 1;
    }

    if (selector_init(NULL) != SELECTOR_SUCCESS) {
        close(server_fd);
        fprintf(stderr, "selector_init failed\n");
        return 1;
    }

    fd_selector selector = selector_new(1024);

    if (selector == NULL) {
        selector_close();
        close(server_fd);
        fprintf(stderr, "selector_new failed\n");
        return 1;
    }

    selector_status status = selector_register(
        selector,
        server_fd,
        &accept_handler,
        OP_READ,
        NULL
    );

    if (status != SELECTOR_SUCCESS) {
        selector_destroy(selector);
        selector_close();
        close(server_fd);
        fprintf(stderr, "could not register server socket\n");
        return 1;
    }

    printf("SOCKS5 skeleton listening on port %s\n", port);

    while (!done) {
        selector_select(selector);
    }

    selector_unregister_fd(selector, server_fd);
    close(server_fd);

    selector_destroy(selector);
    selector_close();

    return 0;
}

int main(int argc, char *argv[]) {
    const char *port = "1080";

    if (argc > 1) {
        port = argv[1];
    }

    return server_run(NULL, port);
}
