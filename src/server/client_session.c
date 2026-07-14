#include "include/client_session.h"
#include "include/auth.h"
#include "include/metrics.h"
#include "include/socks5.h"
#include "include/target_connection.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

static size_t active_client_connections = 0;

size_t client_session_active_count(void) {
    return active_client_connections;
}

void client_session_update_relay_interests(fd_selector selector, client_state_t *state) {
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

void client_session_close_connection(fd_selector selector, client_state_t *state) {
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

        target_connection_detach_resolver(state);
        target_connection_free_addresses(state);
        metrics_connection_closed();
        active_client_connections--;
        free(state);
    }

    close(key->fd);
}

void client_write(struct selector_key *key) {
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

        client_session_close_connection(key->s, state);
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
            client_session_update_relay_interests(key->s, state);
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

        client_session_close_connection(key->s, state);
        return;
    }

    state->t2c_len = 0;
    state->t2c_off = 0;
    client_session_update_relay_interests(key->s, state);
}

static void client_read(struct selector_key *key) {
    client_state_t *state = key->data;

    if (state->stage == CLIENT_STAGE_RELAY) {
        if (state->c2t_len != 0) {
            client_session_update_relay_interests(key->s, state);
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
            client_session_update_relay_interests(key->s, state);

            if (state->target_fd != -1) {
                struct selector_key target_key = {
                    .s = key->s,
                    .fd = state->target_fd,
                    .data = state,
                };
                target_write(&target_key);
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

            if (accepts_username_password) {
                socks5_prepare_greeting_response(
                    state->write_buffer,
                    &state->write_len,
                    &state->write_off,
                    SOCKS5_METHOD_USERNAME_PASSWORD
                );
                state->stage = CLIENT_STAGE_AUTH;
            } else if (!auth_is_required() && accepts_no_auth) {
                socks5_prepare_greeting_response(
                    state->write_buffer,
                    &state->write_len,
                    &state->write_off,
                    SOCKS5_METHOD_NO_AUTH
                );
                state->stage = CLIENT_STAGE_REQUEST;
            } else {
                socks5_prepare_greeting_response(
                    state->write_buffer,
                    &state->write_len,
                    &state->write_off,
                    SOCKS5_METHOD_NO_ACCEPTABLE
                );
                state->stage = CLIENT_STAGE_CLOSING;
            }

            state->read_len = 0;
            selector_set_interest_key(key, OP_WRITE);
            return;
        }

        if (state->stage == CLIENT_STAGE_AUTH) {
            bool authenticated = false;

            if (!auth_parse_request(state, &authenticated)) {
                return;
            }

            socks5_prepare_auth_response(
                state->write_buffer,
                &state->write_len,
                &state->write_off,
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

                socks5_prepare_request_response(
                    state->write_buffer,
                    &state->write_len,
                    &state->write_off,
                    request_reply
                );
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
                socks5_prepare_request_response(
                    state->write_buffer,
                    &state->write_len,
                    &state->write_off,
                    SOCKS5_REPLY_GENERAL_FAILURE
                );
                metrics_connection_failed();
                state->stage = CLIENT_STAGE_CLOSING;
                state->read_len = 0;
                selector_set_interest_key(key, OP_WRITE);
                return;
            }

            target_connection_begin(key, state, &request);
            state->read_len = 0;
            return;
        }
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

static const fd_handler client_handler = {
    .handle_read = client_read,
    .handle_write = client_write,
    .handle_block = target_connection_on_resolve,
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

const fd_handler accept_handler = {
    .handle_read = accept_connection,
};
