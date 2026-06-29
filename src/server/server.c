#include "include/server.h"
#include "include/socks5.h"

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

static void update_relay_interests(fd_selector selector, client_state_t *state) {
    if (state == NULL || !state->relay_started) {
        return;
    }

    if (state->client_fd != -1) {
        fd_interest interest = OP_NOOP;

        if (state->c2t_len == 0) {
            interest |= OP_READ;
        }

        if (state->t2c_len > state->t2c_off) {
            interest |= OP_WRITE;
        }

        selector_set_interest(selector, state->client_fd, interest);
    }

    if (state->target_fd != -1) {
        fd_interest interest = OP_NOOP;

        if (state->t2c_len == 0) {
            interest |= OP_READ;
        }

        if (state->c2t_len > state->c2t_off) {
            interest |= OP_WRITE;
        }

        selector_set_interest(selector, state->target_fd, interest);
    }
}

static void close_connection(fd_selector selector, client_state_t *state) {
    if (state == NULL) {
        return;
    }

    if (state->client_fd != -1) {
        int client_fd = state->client_fd;
        state->client_fd = -1;
        selector_unregister_fd(selector, client_fd);
        return;
    }

    if (state->target_fd != -1) {
        int target_fd = state->target_fd;
        state->target_fd = -1;

        if (selector_unregister_fd(selector, target_fd) != SELECTOR_SUCCESS) {
            close(target_fd);
        }
    }
}

static void client_close(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state != NULL) {
        if (state->client_fd == key->fd) {
            state->client_fd = -1;
        }

        if (state->target_fd != -1) {
            int target_fd = state->target_fd;
            state->target_fd = -1;

            if (selector_unregister_fd(key->s, target_fd) != SELECTOR_SUCCESS) {
                close(target_fd);
            }
        }

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

        close_connection(key->s, state);
        return;
    }

    if (state->write_len > 0) {
        state->write_len = 0;
        state->write_off = 0;

        if (state->stage == CLIENT_STAGE_CLOSING) {
            selector_unregister_fd(key->s, key->fd);
            return;
        }

        if (state->stage == CLIENT_STAGE_RELAY && !state->relay_started) {
            state->relay_started = true;
            update_relay_interests(key->s, state);
            return;
        }

        selector_set_interest_key(key, OP_READ);
        return;
    }

    if (state->stage != CLIENT_STAGE_RELAY) {
        selector_set_interest_key(key, OP_READ);
        return;
    }

    while (state->t2c_off < state->t2c_len) {
        ssize_t sent = send(
            key->fd,
            state->t2c_buffer + state->t2c_off,
            state->t2c_len - state->t2c_off,
            MSG_NOSIGNAL
        );

        if (sent > 0) {
            state->t2c_off += (size_t) sent;
            continue;
        }

        if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }

        close_connection(key->s, state);
        return;
    }

    state->t2c_len = 0;
    state->t2c_off = 0;
    update_relay_interests(key->s, state);
}

static void prepare_greeting_response(client_state_t *state, uint8_t method) {
    socks5_prepare_greeting_response(
        state->write_buffer,
        &state->write_len,
        &state->write_off,
        method
    );
}

static void prepare_request_response(client_state_t *state, uint8_t reply) {
    socks5_prepare_request_response(
        state->write_buffer,
        &state->write_len,
        &state->write_off,
        reply
    );
}

static bool connect_to_target(client_state_t *state) {
    int target_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (target_fd == -1) {
        return false;
    }

    state->target_fd = target_fd;

    if (connect(
            target_fd,
            (const struct sockaddr *) &state->target_addr,
            sizeof(state->target_addr)
        ) == -1) {
        close(state->target_fd);
        state->target_fd = -1;
        return false;
    }

    return true;
}

static void target_close(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state != NULL && state->target_fd == key->fd) {
        state->target_fd = -1;
    }

    close(key->fd);
}

static void target_read(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state->t2c_len != 0) {
        update_relay_interests(key->s, state);
        return;
    }

    ssize_t received = recv(
        key->fd,
        state->t2c_buffer,
        sizeof(state->t2c_buffer),
        0
    );

    if (received > 0) {
        state->t2c_len = (size_t) received;
        state->t2c_off = 0;
        update_relay_interests(key->s, state);
        return;
    }

    if (received == 0) {
        close_connection(key->s, state);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
    }

    close_connection(key->s, state);
}

static void target_write(struct selector_key *key) {
    client_state_t *state = key->data;

    while (state->c2t_off < state->c2t_len) {
        ssize_t sent = send(
            key->fd,
            state->c2t_buffer + state->c2t_off,
            state->c2t_len - state->c2t_off,
            MSG_NOSIGNAL
        );

        if (sent > 0) {
            state->c2t_off += (size_t) sent;
            continue;
        }

        if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }

        close_connection(key->s, state);
        return;
    }

    state->c2t_len = 0;
    state->c2t_off = 0;
    update_relay_interests(key->s, state);
}

static const fd_handler target_handler = {
    .handle_read = target_read,
    .handle_write = target_write,
    .handle_close = target_close,
};

static void client_read(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state->stage == CLIENT_STAGE_RELAY) {
        if (state->c2t_len != 0) {
            update_relay_interests(key->s, state);
            return;
        }

        ssize_t received = recv(
            key->fd,
            state->c2t_buffer,
            sizeof(state->c2t_buffer),
            0
        );

        if (received > 0) {
            state->c2t_len = (size_t) received;
            state->c2t_off = 0;
            update_relay_interests(key->s, state);
            return;
        }

        if (received == 0) {
            close_connection(key->s, state);
            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }

        close_connection(key->s, state);
        return;
    }

    ssize_t received = recv(
        key->fd,
        state->read_buffer,
        sizeof(state->read_buffer),
        0
    );

    if (received > 0) {
        state->read_len = (size_t) received;

        if (state->stage == CLIENT_STAGE_GREETING) {
            if (state->read_len < 2) {
                selector_unregister_fd(key->s, key->fd);
                return;
            }

            uint8_t version = state->read_buffer[0];
            uint8_t nmethods = state->read_buffer[1];

            if (version != SOCKS5_VERSION || state->read_len < 2 + nmethods) {
                selector_unregister_fd(key->s, key->fd);
                return;
            }

            bool accepts_no_auth = socks5_client_offers_no_auth(
                state->read_buffer + 2,
                nmethods
            );

            if (accepts_no_auth) {
                prepare_greeting_response(state, SOCKS5_METHOD_NO_AUTH);
                state->stage = CLIENT_STAGE_REQUEST;
            } else {
                prepare_greeting_response(state, SOCKS5_METHOD_NO_ACCEPTABLE);
                state->stage = CLIENT_STAGE_CLOSING;
            }

            selector_set_interest_key(key, OP_WRITE);
            return;
        }

        if (state->stage == CLIENT_STAGE_REQUEST) {
            if (state->read_len < SOCKS5_IPV4_REQUEST_SIZE) {
                return;
            }

            if (!socks5_parse_ipv4_connect(
                    state->read_buffer,
                    state->read_len,
                    &state->target_addr
                )) {
                prepare_request_response(state, SOCKS5_REPLY_GENERAL_FAILURE);
                state->stage = CLIENT_STAGE_CLOSING;
                selector_set_interest_key(key, OP_WRITE);
                return;
            }

            bool connected = connect_to_target(state);
            bool relay_ready = false;

            if (connected && set_nonblocking(state->target_fd) != -1) {
                selector_status status = selector_register(
                    key->s,
                    state->target_fd,
                    &target_handler,
                    OP_NOOP,
                    state
                );

                relay_ready = status == SELECTOR_SUCCESS;
            }

            if (connected && !relay_ready) {
                close(state->target_fd);
                state->target_fd = -1;
            }

            prepare_request_response(
                state,
                relay_ready ? SOCKS5_REPLY_SUCCESS : SOCKS5_REPLY_GENERAL_FAILURE
            );
            state->stage = relay_ready ? CLIENT_STAGE_RELAY : CLIENT_STAGE_CLOSING;
            selector_set_interest_key(key, OP_WRITE);
            return;
        }
    }

    if (received == 0) {
        close_connection(key->s, state);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
    }

    close_connection(key->s, state);
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
        state->client_fd = client_fd;
        state->target_fd = -1;

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

    struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS) {
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
