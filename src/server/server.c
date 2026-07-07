#include "include/server.h"
#include "include/socks5.h"
#include "include/metrics.h"
#include "include/users.h"
#include "include/access_log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "../utils/include/selector.h"
#include "../utils/include/args.h"

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t force_shutdown = 0;
static size_t active_client_connections = 0;

struct resolver_job {
    fd_selector selector;
    int client_fd;
    client_state_t *state;
    char host[SOCKS5_MAX_DOMAIN_LENGTH + 1];
    char port[6];
    pthread_mutex_t mutex;
    struct addrinfo *result;
    int status;
    bool done;
};

static uint8_t socks5_reply_for_errno(int error);
static bool start_next_target_connection(fd_selector selector, client_state_t *state);
static void format_metrics_response(char *buffer, size_t buffer_size);

static void sigterm_handler(const int signal) {
    (void) signal;

    if (shutdown_requested) {
        force_shutdown = 1;
    } else {
        shutdown_requested = 1;
    }
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

static void format_metrics_response(char *buffer, size_t buffer_size) {
    server_metrics_t metrics = metrics_snapshot();

    snprintf(
        buffer,
        buffer_size,
        "historical_connections=%" PRIu64 "\n"
        "concurrent_connections=%" PRIu64 "\n"
        "successful_connections=%" PRIu64 "\n"
        "failed_connections=%" PRIu64 "\n"
        "bytes_transferred=%" PRIu64 "\n"
        "bytes_client_to_target=%" PRIu64 "\n"
        "bytes_target_to_client=%" PRIu64 "\n",
        metrics.historical_connections,
        metrics.concurrent_connections,
        metrics.successful_connections,
        metrics.failed_connections,
        metrics_total_transferred_bytes(&metrics),
        metrics.bytes_client_to_target,
        metrics.bytes_target_to_client
    );
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

static void free_target_addresses(client_state_t *state) {
    if (state != NULL && state->target_addresses != NULL) {
        freeaddrinfo(state->target_addresses);
        state->target_addresses = NULL;
        state->target_address_current = NULL;
    }
}

static void detach_resolver_job(client_state_t *state) {
    struct resolver_job *job = state->resolver_job;

    if (job == NULL) {
        return;
    }

    pthread_mutex_lock(&job->mutex);
    job->state = NULL;

    if (job->done) {
        if (job->result != NULL) {
            freeaddrinfo(job->result);
            job->result = NULL;
        }
        pthread_mutex_unlock(&job->mutex);
        pthread_mutex_destroy(&job->mutex);
        free(job);
    } else {
        pthread_mutex_unlock(&job->mutex);
    }

    state->resolver_job = NULL;
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

        detach_resolver_job(state);
        free_target_addresses(state);
        metrics_connection_closed();
        active_client_connections--;
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
            metrics_add_target_to_client_bytes((uint64_t) sent);
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

static void prepare_auth_response(client_state_t *state, uint8_t status) {
    socks5_prepare_auth_response(
        state->write_buffer,
        &state->write_len,
        &state->write_off,
        status
    );
}

static bool requires_authentication(void) {
    return users_are_configured();
}

static bool credentials_are_valid(const uint8_t *username,
                                  uint8_t username_len,
                                  const uint8_t *password,
                                  uint8_t password_len) {
    return users_credentials_are_valid(username, username_len, password, password_len);
}

static bool parse_auth_request(client_state_t *state, bool *authenticated) {
    *authenticated = false;

    if (state->read_len < 2) {
        return false;
    }

    if (state->read_buffer[0] != SOCKS5_AUTH_VERSION) {
        return true;
    }

    uint8_t username_len = state->read_buffer[1];
    size_t password_len_index = 2 + (size_t) username_len;

    if (state->read_len < password_len_index + 1) {
        return false;
    }

    uint8_t password_len = state->read_buffer[password_len_index];
    size_t expected_len = password_len_index + 1 + (size_t) password_len;

    if (state->read_len < expected_len) {
        return false;
    }

    *authenticated = credentials_are_valid(
        state->read_buffer + 2,
        username_len,
        state->read_buffer + password_len_index + 1,
        password_len
    );

    if (*authenticated) {
        memcpy(state->username, state->read_buffer + 2, username_len);
        state->username[username_len] = '\0';
    }

    return true;
}

static void remember_request_destination(client_state_t *state,
                                         const socks5_request_t *request) {
    state->destination_port = request->port;
    state->access_logged = false;

    if (request->atyp == SOCKS5_ATYP_DOMAIN) {
        snprintf(
            state->destination_host,
            sizeof(state->destination_host),
            "%s",
            request->host
        );
        return;
    }

    if (request->atyp == SOCKS5_ATYP_IPV4) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *) &request->addr;
        if (inet_ntop(
                AF_INET,
                &addr->sin_addr,
                state->destination_host,
                sizeof(state->destination_host)
            ) != NULL) {
            return;
        }
    }

    if (request->atyp == SOCKS5_ATYP_IPV6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *) &request->addr;
        if (inet_ntop(
                AF_INET6,
                &addr->sin6_addr,
                state->destination_host,
                sizeof(state->destination_host)
            ) != NULL) {
            return;
        }
    }

    snprintf(state->destination_host, sizeof(state->destination_host), "unknown");
}

static void access_log_client_connection(client_state_t *state, bool success) {
    if (state->access_logged || state->destination_host[0] == '\0') {
        return;
    }

    access_log_connection(
        state->username,
        state->destination_host,
        state->destination_port,
        success
    );
    state->access_logged = true;
}

static uint8_t socks5_reply_for_errno(int error) {
    switch (error) {
    case 0:
        return SOCKS5_REPLY_SUCCESS;
    case ENETUNREACH:
        return SOCKS5_REPLY_NETWORK_UNREACHABLE;
    case EHOSTUNREACH:
    case EHOSTDOWN:
#ifdef ENODATA
    case ENODATA:
#endif
        return SOCKS5_REPLY_HOST_UNREACHABLE;
    case ECONNREFUSED:
        return SOCKS5_REPLY_CONNECTION_REFUSED;
    case ETIMEDOUT:
        return SOCKS5_REPLY_TTL_EXPIRED;
    default:
        return SOCKS5_REPLY_GENERAL_FAILURE;
    }
}

static uint8_t socks5_reply_for_gai_error(int error) {
    switch (error) {
    case 0:
        return SOCKS5_REPLY_SUCCESS;
    case EAI_AGAIN:
        return SOCKS5_REPLY_TTL_EXPIRED;
    case EAI_NONAME:
#ifdef EAI_NODATA
    case EAI_NODATA:
#endif
        return SOCKS5_REPLY_HOST_UNREACHABLE;
    default:
        return SOCKS5_REPLY_GENERAL_FAILURE;
    }
}

static void *resolve_target(void *data) {
    struct resolver_job *job = data;
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(job->host, job->port, &hints, &result);

    pthread_mutex_lock(&job->mutex);
    job->result = result;
    job->status = status;
    job->done = true;

    bool has_waiting_client = job->state != NULL;
    fd_selector selector = job->selector;
    int client_fd = job->client_fd;
    pthread_mutex_unlock(&job->mutex);

    if (has_waiting_client) {
        selector_notify_block(selector, client_fd);
        return NULL;
    }

    if (result != NULL) {
        freeaddrinfo(result);
    }
    pthread_mutex_destroy(&job->mutex);
    free(job);
    return NULL;
}

static bool start_target_resolution(fd_selector selector,
                                    client_state_t *state,
                                    const char *host,
                                    uint16_t port) {
    struct resolver_job *job = calloc(1, sizeof(*job));

    if (job == NULL) {
        return false;
    }

    if (pthread_mutex_init(&job->mutex, NULL) != 0) {
        free(job);
        return false;
    }

    job->selector = selector;
    job->client_fd = state->client_fd;
    job->state = state;
    snprintf(job->host, sizeof(job->host), "%s", host);
    snprintf(job->port, sizeof(job->port), "%hu", port);
    job->status = EAI_AGAIN;
    state->resolver_job = job;

    pthread_t resolver_thread;
    int status = pthread_create(&resolver_thread, NULL, resolve_target, job);

    if (status != 0) {
        state->resolver_job = NULL;
        pthread_mutex_destroy(&job->mutex);
        free(job);
        return false;
    }

    pthread_detach(resolver_thread);
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

static bool target_connection_succeeded(int fd, int *socket_error) {
    int error = 0;
    socklen_t socket_error_len = sizeof(error);

    if (getsockopt(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            &error,
            &socket_error_len
        ) == -1) {
        *socket_error = errno;
        return false;
    }

    *socket_error = error;
    return *socket_error == 0;
}

static void target_write(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state->stage == CLIENT_STAGE_CONNECTING) {
        int socket_error = 0;
        bool connected = target_connection_succeeded(key->fd, &socket_error);

        if (!connected) {
            state->last_connect_error = socket_error;
            selector_unregister_fd(key->s, key->fd);

            if (start_next_target_connection(key->s, state)) {
                return;
            }
        } else {
            selector_set_interest(key->s, key->fd, OP_NOOP);
        }

        prepare_request_response(
            state,
            connected ? SOCKS5_REPLY_SUCCESS :
                        socks5_reply_for_errno(state->last_connect_error)
        );
        if (connected) {
            metrics_connection_succeeded();
        } else {
            metrics_connection_failed();
        }
        access_log_client_connection(state, connected);
        state->stage = connected ? CLIENT_STAGE_RELAY : CLIENT_STAGE_CLOSING;
        selector_set_interest(key->s, state->client_fd, OP_WRITE);
        return;
    }

    while (state->c2t_off < state->c2t_len) {
        ssize_t sent = send(
            key->fd,
            state->c2t_buffer + state->c2t_off,
            state->c2t_len - state->c2t_off,
            MSG_NOSIGNAL
        );

        if (sent > 0) {
            state->c2t_off += (size_t) sent;
            metrics_add_client_to_target_bytes((uint64_t) sent);
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

static bool register_connecting_socket(fd_selector selector,
                                       client_state_t *state,
                                       int target_fd) {
    selector_status status = selector_register(
        selector,
        target_fd,
        &target_handler,
        OP_WRITE,
        state
    );

    if (status != SELECTOR_SUCCESS) {
        state->last_connect_error = errno;
        close(target_fd);
        state->target_fd = -1;
        return false;
    }

    state->stage = CLIENT_STAGE_CONNECTING;
    return true;
}

static bool start_target_connection(fd_selector selector,
                                    client_state_t *state,
                                    const struct sockaddr *addr,
                                    socklen_t addr_len) {
    int target_fd = socket(addr->sa_family, SOCK_STREAM, 0);

    if (target_fd == -1) {
        state->last_connect_error = errno;
        return false;
    }

    if (set_nonblocking(target_fd) == -1) {
        state->last_connect_error = errno;
        close(target_fd);
        return false;
    }

    state->target_fd = target_fd;

    if (connect(
            target_fd,
            addr,
            addr_len
        ) == -1 && errno != EINPROGRESS) {
        state->last_connect_error = errno;
        close(state->target_fd);
        state->target_fd = -1;
        return false;
    }

    return register_connecting_socket(selector, state, target_fd);
}

static bool start_next_target_connection(fd_selector selector, client_state_t *state) {
    while (state->target_address_current != NULL) {
        struct addrinfo *current = state->target_address_current;
        state->target_address_current = current->ai_next;

        if (current->ai_family != AF_INET && current->ai_family != AF_INET6) {
            continue;
        }

        if (start_target_connection(
                selector,
                state,
                current->ai_addr,
                (socklen_t) current->ai_addrlen
            )) {
            return true;
        }
    }

    return false;
}

static void begin_request_connection(struct selector_key *key,
                                     client_state_t *state,
                                     const socks5_request_t *request) {
    free_target_addresses(state);
    state->last_connect_error = 0;
    remember_request_destination(state, request);

    if (request->atyp == SOCKS5_ATYP_DOMAIN) {
        detach_resolver_job(state);

        bool resolution_started = start_target_resolution(
            key->s,
            state,
            request->host,
            request->port
        );

        if (!resolution_started) {
            prepare_request_response(state, SOCKS5_REPLY_GENERAL_FAILURE);
            metrics_connection_failed();
            access_log_client_connection(state, false);
            state->stage = CLIENT_STAGE_CLOSING;
            selector_set_interest_key(key, OP_WRITE);
            return;
        }

        state->stage = CLIENT_STAGE_RESOLVING;
        selector_set_interest_key(key, OP_NOOP);
        return;
    }

    memcpy(&state->target_addr, &request->addr, sizeof(state->target_addr));
    state->target_addr_len = request->addr_len;

    if (!start_target_connection(
            key->s,
            state,
            (const struct sockaddr *) &state->target_addr,
            state->target_addr_len
        )) {
        prepare_request_response(
            state,
            socks5_reply_for_errno(state->last_connect_error)
        );
        metrics_connection_failed();
        access_log_client_connection(state, false);
        state->stage = CLIENT_STAGE_CLOSING;
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    selector_set_interest_key(key, OP_NOOP);
}

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
        state->read_buffer + state->read_len,
        sizeof(state->read_buffer) - state->read_len,
        0
    );

    if (received > 0) {
        state->read_len += (size_t) received;

        if (state->stage == CLIENT_STAGE_GREETING) {
            if (state->read_len < 2) {
                return;
            }

            uint8_t version = state->read_buffer[0];
            uint8_t nmethods = state->read_buffer[1];

            if (version != SOCKS5_VERSION || state->read_len < 2 + nmethods) {
                if (version == SOCKS5_VERSION) {
                    return;
                }
                selector_unregister_fd(key->s, key->fd);
                return;
            }

            bool accepts_username_password = socks5_client_offers_username_password(
                state->read_buffer + 2,
                nmethods
            );
            bool accepts_no_auth = socks5_client_offers_no_auth(
                state->read_buffer + 2,
                nmethods
            );

            if (requires_authentication() && accepts_username_password) {
                prepare_greeting_response(state, SOCKS5_METHOD_USERNAME_PASSWORD);
                state->stage = CLIENT_STAGE_AUTH;
            } else if (!requires_authentication() && accepts_no_auth) {
                prepare_greeting_response(state, SOCKS5_METHOD_NO_AUTH);
                state->stage = CLIENT_STAGE_REQUEST;
            } else {
                prepare_greeting_response(state, SOCKS5_METHOD_NO_ACCEPTABLE);
                state->stage = CLIENT_STAGE_CLOSING;
            }

            state->read_len = 0;
            selector_set_interest_key(key, OP_WRITE);
            return;
        }

        if (state->stage == CLIENT_STAGE_AUTH) {
            bool authenticated = false;

            if (!parse_auth_request(state, &authenticated)) {
                return;
            }

            prepare_auth_response(
                state,
                authenticated ? SOCKS5_AUTH_SUCCESS : SOCKS5_AUTH_FAILURE
            );
            state->stage = authenticated ? CLIENT_STAGE_REQUEST : CLIENT_STAGE_CLOSING;
            state->read_len = 0;
            selector_set_interest_key(key, OP_WRITE);
            return;
        }

        if (state->stage == CLIENT_STAGE_REQUEST) {
            if (state->read_len < 4) {
                return;
            }

            uint8_t request_reply = socks5_request_reply_for(
                state->read_buffer,
                state->read_len
            );

            if (request_reply != SOCKS5_REPLY_SUCCESS) {
                if (socks5_request_is_incomplete(state->read_buffer, state->read_len)) {
                    return;
                }

                prepare_request_response(state, request_reply);
                metrics_connection_failed();
                state->stage = CLIENT_STAGE_CLOSING;
                state->read_len = 0;
                selector_set_interest_key(key, OP_WRITE);
                return;
            }

            socks5_request_t request;

            if (!socks5_parse_connect_request(
                    state->read_buffer,
                    state->read_len,
                    &request
                )) {
                prepare_request_response(state, SOCKS5_REPLY_GENERAL_FAILURE);
                metrics_connection_failed();
                state->stage = CLIENT_STAGE_CLOSING;
                state->read_len = 0;
                selector_set_interest_key(key, OP_WRITE);
                return;
            }

            begin_request_connection(key, state, &request);
            state->read_len = 0;
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

static void client_block(struct selector_key *key) {
    client_state_t *state = key->data;
    struct resolver_job *job;
    struct addrinfo *result;
    int status;

    if (state == NULL || state->stage != CLIENT_STAGE_RESOLVING) {
        return;
    }

    job = state->resolver_job;
    if (job == NULL) {
        return;
    }

    pthread_mutex_lock(&job->mutex);
    if (!job->done) {
        pthread_mutex_unlock(&job->mutex);
        return;
    }

    result = job->result;
    status = job->status;
    job->result = NULL;
    job->state = NULL;
    pthread_mutex_unlock(&job->mutex);

    pthread_mutex_destroy(&job->mutex);
    free(job);
    state->resolver_job = NULL;

    if (status != 0 || result == NULL) {
        prepare_request_response(
            state,
            socks5_reply_for_gai_error(status)
        );
        metrics_connection_failed();
        access_log_client_connection(state, false);
        state->stage = CLIENT_STAGE_CLOSING;
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    state->target_addresses = result;
    state->target_address_current = result;

    if (!start_next_target_connection(key->s, state)) {
        prepare_request_response(
            state,
            socks5_reply_for_errno(state->last_connect_error)
        );
        metrics_connection_failed();
        access_log_client_connection(state, false);
        state->stage = CLIENT_STAGE_CLOSING;
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    selector_set_interest_key(key, OP_NOOP);
}

static const fd_handler client_handler = {
    .handle_read = client_read,
    .handle_write = client_write,
    .handle_block = client_block,
    .handle_close = client_close,
};

static void management_prepare_response(management_state_t *state) {
    char *command;
    char *arg1;
    char *arg2;

    state->read_buffer[state->read_len] = '\0';
    state->read_buffer[strcspn(state->read_buffer, "\r\n")] = '\0';

    command = strtok(state->read_buffer, " \t");
    arg1 = strtok(NULL, " \t");
    arg2 = strtok(NULL, " \t");

    if (command == NULL) {
        snprintf(state->write_buffer, sizeof(state->write_buffer), "error=empty_command\n");
    } else if (strcasecmp(command, "STATS") == 0 ||
               strcasecmp(command, "METRICS") == 0) {
        format_metrics_response(state->write_buffer, sizeof(state->write_buffer));
    } else if (strcasecmp(command, "USERS") == 0) {
        users_format_list(state->write_buffer, sizeof(state->write_buffer));
    } else if (strcasecmp(command, "ADDUSER") == 0) {
        users_result_t result;

        if (arg1 == NULL || arg2 == NULL || strtok(NULL, " \t") != NULL) {
            snprintf(state->write_buffer, sizeof(state->write_buffer), "error=usage_ADDUSER_user_pass\n");
        } else {
            result = users_add(arg1, arg2);
            snprintf(
                state->write_buffer,
                sizeof(state->write_buffer),
                "adduser=%s\nusers_count=%zu\n",
                users_result_name(result),
                users_count()
            );
        }
    } else if (strcasecmp(command, "DELUSER") == 0) {
        users_result_t result;

        if (arg1 == NULL || arg2 != NULL) {
            snprintf(state->write_buffer, sizeof(state->write_buffer), "error=usage_DELUSER_user\n");
        } else {
            result = users_remove(arg1);
            snprintf(
                state->write_buffer,
                sizeof(state->write_buffer),
                "deluser=%s\nusers_count=%zu\n",
                users_result_name(result),
                users_count()
            );
        }
    } else if (strcasecmp(command, "QUIT") == 0) {
        snprintf(state->write_buffer, sizeof(state->write_buffer), "ok=bye\n");
    } else if (strcasecmp(command, "HELP") == 0) {
        snprintf(
            state->write_buffer,
            sizeof(state->write_buffer),
            "commands=STATS,METRICS,USERS,ADDUSER,DELUSER,HELP,QUIT\n"
        );
    } else {
        snprintf(state->write_buffer, sizeof(state->write_buffer), "error=unknown_command\n");
    }

    state->write_len = strlen(state->write_buffer);
    state->write_off = 0;
}

static void management_close(struct selector_key *key) {
    management_state_t *state = key->data;

    free(state);
    close(key->fd);
}

static void management_write(struct selector_key *key) {
    management_state_t *state = key->data;

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
        return;
    }

    selector_unregister_fd(key->s, key->fd);
}

static void management_read(struct selector_key *key) {
    management_state_t *state = key->data;

    ssize_t received = recv(
        key->fd,
        state->read_buffer + state->read_len,
        sizeof(state->read_buffer) - state->read_len - 1,
        0
    );

    if (received > 0) {
        state->read_len += (size_t) received;

        if (memchr(state->read_buffer, '\n', state->read_len) != NULL ||
            state->read_len == sizeof(state->read_buffer) - 1) {
            management_prepare_response(state);
            selector_set_interest_key(key, OP_WRITE);
        }
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

static const fd_handler management_client_handler = {
    .handle_read = management_read,
    .handle_write = management_write,
    .handle_close = management_close,
};

static void accept_management_connection(struct selector_key *key) {
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

            perror("accept management");
            return;
        }

        if (set_nonblocking(client_fd) == -1) {
            close(client_fd);
            continue;
        }

        management_state_t *state = calloc(1, sizeof(*state));

        if (state == NULL) {
            close(client_fd);
            continue;
        }

        selector_status status = selector_register(
            key->s,
            client_fd,
            &management_client_handler,
            OP_READ,
            state
        );

        if (status != SELECTOR_SUCCESS) {
            free(state);
            close(client_fd);
        }
    }
}

static const fd_handler management_accept_handler = {
    .handle_read = accept_management_connection,
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
        snprintf(state->username, sizeof(state->username), "anonymous");

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
        } else {
            metrics_connection_opened();
            active_client_connections++;
        }
    }
}

static const fd_handler accept_handler = {
    .handle_read = accept_connection,
};

int server_run(const char *host,
               const char *port,
               const char *management_host,
               const char *management_port) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (port == NULL) {
        port = "1080";
    }

    if (management_port == NULL) {
        management_port = "8080";
    }

    int server_fd = create_passive_socket(host, port);

    if (server_fd == -1) {
        fprintf(stderr, "could not create passive socket\n");
        return 1;
    }

    int management_fd = create_passive_socket(management_host, management_port);

    if (management_fd == -1) {
        close(server_fd);
        fprintf(stderr, "could not create management socket\n");
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
        close(management_fd);
        close(server_fd);
        fprintf(stderr, "selector_init failed\n");
        return 1;
    }

    fd_selector selector = selector_new(1024);

    if (selector == NULL) {
        selector_close();
        close(management_fd);
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
        close(management_fd);
        close(server_fd);
        fprintf(stderr, "could not register server socket\n");
        return 1;
    }

    status = selector_register(
        selector,
        management_fd,
        &management_accept_handler,
        OP_READ,
        NULL
    );

    if (status != SELECTOR_SUCCESS) {
        selector_unregister_fd(selector, server_fd);
        selector_destroy(selector);
        selector_close();
        close(management_fd);
        close(server_fd);
        fprintf(stderr, "could not register management socket\n");
        return 1;
    }

    printf("SOCKS5 listening on %s:%s\n", host == NULL ? "0.0.0.0" : host, port);
    printf(
        "Management listening on %s:%s\n",
        management_host == NULL ? "0.0.0.0" : management_host,
        management_port
    );

    bool stopped_accepting = false;

    while (!force_shutdown) {
        selector_select(selector);

        if (shutdown_requested && !stopped_accepting) {
            stopped_accepting = true;
            selector_unregister_fd(selector, server_fd);
            selector_unregister_fd(selector, management_fd);
            close(server_fd);
            close(management_fd);
            printf(
                "shutdown requested: no longer accepting new connections, "
                "waiting for %zu active connection(s)\n",
                active_client_connections
            );
        }

        if (stopped_accepting && active_client_connections == 0) {
            break;
        }
    }

    if (!stopped_accepting) {
        selector_unregister_fd(selector, server_fd);
        selector_unregister_fd(selector, management_fd);
        close(server_fd);
        close(management_fd);
    }

    if (force_shutdown && active_client_connections > 0) {
        printf(
            "forced shutdown: dropping %zu active connection(s)\n",
            active_client_connections
        );
    }

    selector_destroy(selector);

    server_metrics_t metrics = metrics_snapshot();

    printf(
        "Metrics: historical_connections=%" PRIu64
        " concurrent_connections=%" PRIu64
        " successful_connections=%" PRIu64
        " failed_connections=%" PRIu64
        " bytes_transferred=%" PRIu64
        " bytes_client_to_target=%" PRIu64
        " bytes_target_to_client=%" PRIu64 "\n",
        metrics.historical_connections,
        metrics.concurrent_connections,
        metrics.successful_connections,
        metrics.failed_connections,
        metrics_total_transferred_bytes(&metrics),
        metrics.bytes_client_to_target,
        metrics.bytes_target_to_client
    );

    selector_close();

    return 0;
}



int main(int argc, char *argv[]) {
    struct socks5args args;
    char port[6];
    char management_port[6];
    size_t users_count = 0;

    parse_args(argc, argv, &args);

    for (size_t i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        users_count++;
    }

    users_init_from_args(args.users, users_count);

    snprintf(port, sizeof(port), "%hu", args.socks_port);
    snprintf(management_port, sizeof(management_port), "%hu", args.mng_port);

    return server_run(args.socks_addr, port, args.mng_addr, management_port);
}
