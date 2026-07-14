#include "include/server.h"
#include "include/client_session.h"
#include "include/management.h"
#include "include/metrics.h"
#include "include/users.h"

#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "../utils/include/selector.h"
#include "../utils/include/args.h"

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t force_shutdown = 0;

static void sigterm_handler(const int signal) {
    (void) signal;

    if (shutdown_requested) {
        force_shutdown = 1;
    } else {
        shutdown_requested = 1;
    }
}

int set_nonblocking(const int fd) {
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
                client_session_active_count()
            );
        }

        if (stopped_accepting && client_session_active_count() == 0) {
            break;
        }
    }

    if (!stopped_accepting) {
        selector_unregister_fd(selector, server_fd);
        selector_unregister_fd(selector, management_fd);
        close(server_fd);
        close(management_fd);
    }

    if (force_shutdown && client_session_active_count() > 0) {
        printf(
            "forced shutdown: dropping %zu active connection(s)\n",
            client_session_active_count()
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
