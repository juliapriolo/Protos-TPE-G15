#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#define CLIENT_BUFFER_SIZE 1024

static void usage(const char *program) {
    fprintf(
        stderr,
        "Usage: %s [-L management_addr] [-P management_port] [METRICS|HELP]\n",
        program
    );
}

static int connect_to_management(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *current = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(host, port, &hints, &result);

    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    int fd = -1;

    for (current = result; current != NULL; current = current->ai_next) {
        fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (connect(fd, current->ai_addr, current->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    return fd;
}

static bool send_command(int fd, const char *command) {
    char buffer[CLIENT_BUFFER_SIZE];
    int len = snprintf(buffer, sizeof(buffer), "%s\n", command);

    if (len < 0 || (size_t) len >= sizeof(buffer)) {
        fprintf(stderr, "command too long\n");
        return false;
    }

    size_t sent = 0;

    while (sent < (size_t) len) {
        ssize_t n = send(fd, buffer + sent, (size_t) len - sent, MSG_NOSIGNAL);

        if (n > 0) {
            sent += (size_t) n;
            continue;
        }

        if (n == -1 && errno == EINTR) {
            continue;
        }

        perror("send");
        return false;
    }

    return true;
}

static bool print_response(int fd) {
    char buffer[CLIENT_BUFFER_SIZE];

    while (true) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);

        if (received > 0) {
            fwrite(buffer, 1, (size_t) received, stdout);
            continue;
        }

        if (received == 0) {
            return true;
        }

        if (errno == EINTR) {
            continue;
        }

        perror("recv");
        return false;
    }
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    const char *port = "8080";
    const char *command = "METRICS";
    int option;

    while ((option = getopt(argc, argv, "hL:P:")) != -1) {
        switch (option) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'L':
            host = optarg;
            break;
        case 'P':
            port = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (optind < argc) {
        command = argv[optind++];
    }

    if (optind < argc) {
        usage(argv[0]);
        return 1;
    }

    int fd = connect_to_management(host, port);

    if (fd == -1) {
        fprintf(stderr, "could not connect to management server %s:%s\n", host, port);
        return 1;
    }

    bool ok = send_command(fd, command) && print_response(fd);
    close(fd);

    return ok ? 0 : 1;
}
