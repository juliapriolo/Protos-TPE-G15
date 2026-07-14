#include "include/management.h"
#include "include/metrics.h"
#include "include/server.h"
#include "include/users.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/socket.h>

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

const fd_handler management_accept_handler = {
    .handle_read = accept_management_connection,
};
