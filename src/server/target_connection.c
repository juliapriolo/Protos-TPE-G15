#include "include/target_connection.h"
#include "include/access_log.h"
#include "include/client_session.h"
#include "include/metrics.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

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

static bool start_next_target_connection(fd_selector selector, client_state_t *state);

void target_connection_free_addresses(client_state_t *state) {
    if (state != NULL && state->target_addresses != NULL) {
        freeaddrinfo(state->target_addresses);
        state->target_addresses = NULL;
        state->target_address_current = NULL;
    }
}

void target_connection_detach_resolver(client_state_t *state) {
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
        client_session_update_relay_interests(key->s, state);
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
        client_session_update_relay_interests(key->s, state);

        if (state->client_fd != -1) {
            struct selector_key client_key = {
                .s = key->s,
                .fd = state->client_fd,
                .data = state,
            };
            client_write(&client_key);
        }
        return;
    }

    if (received == 0) {
        client_session_close_connection(key->s, state);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return;
    }

    client_session_close_connection(key->s, state);
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

void target_write(struct selector_key *key) {
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

        socks5_prepare_request_response(
            state->write_buffer,
            &state->write_len,
            &state->write_off,
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

        client_session_close_connection(key->s, state);
        return;
    }

    state->c2t_len = 0;
    state->c2t_off = 0;
    client_session_update_relay_interests(key->s, state);
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

void target_connection_begin(struct selector_key *key,
                             client_state_t *state,
                             const socks5_request_t *request) {
    target_connection_free_addresses(state);
    state->last_connect_error = 0;
    remember_request_destination(state, request);

    if (request->atyp == SOCKS5_ATYP_DOMAIN) {
        target_connection_detach_resolver(state);

        bool resolution_started = start_target_resolution(
            key->s,
            state,
            request->host,
            request->port
        );

        if (!resolution_started) {
            socks5_prepare_request_response(
                state->write_buffer,
                &state->write_len,
                &state->write_off,
                SOCKS5_REPLY_GENERAL_FAILURE
            );
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
        socks5_prepare_request_response(
            state->write_buffer,
            &state->write_len,
            &state->write_off,
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

void target_connection_on_resolve(struct selector_key *key) {
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
        socks5_prepare_request_response(
            state->write_buffer,
            &state->write_len,
            &state->write_off,
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
        socks5_prepare_request_response(
            state->write_buffer,
            &state->write_len,
            &state->write_off,
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
