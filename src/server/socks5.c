#include "include/socks5.h"

#include <string.h>

bool socks5_client_offers_no_auth(const uint8_t *methods, size_t nmethods) {
    for (size_t i = 0; i < nmethods; i++) {
        if (methods[i] == SOCKS5_METHOD_NO_AUTH) {
            return true;
        }
    }

    return false;
}

void socks5_prepare_greeting_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t method
) {
    buffer[0] = SOCKS5_VERSION;
    buffer[1] = method;
    *len = SOCKS5_GREETING_RESPONSE_SIZE;
    *off = 0;
}

void socks5_prepare_request_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t reply
) {
    buffer[0] = SOCKS5_VERSION;
    buffer[1] = reply;
    buffer[2] = 0x00;
    buffer[3] = SOCKS5_ATYP_IPV4;

    buffer[4] = 0x00;
    buffer[5] = 0x00;
    buffer[6] = 0x00;
    buffer[7] = 0x00;

    buffer[8] = 0x00;
    buffer[9] = 0x00;

    *len = SOCKS5_RESPONSE_SIZE;
    *off = 0;
}

bool socks5_parse_ipv4_connect(
    const uint8_t *buffer,
    size_t len,
    struct sockaddr_in *target_addr
) {
    if (len < SOCKS5_IPV4_REQUEST_SIZE ||
        buffer[0] != SOCKS5_VERSION ||
        buffer[1] != SOCKS5_CMD_CONNECT ||
        buffer[2] != 0x00 ||
        buffer[3] != SOCKS5_ATYP_IPV4) {
        return false;
    }

    uint16_t port = ((uint16_t) buffer[8] << 8) | (uint16_t) buffer[9];

    memset(target_addr, 0, sizeof(*target_addr));
    target_addr->sin_family = AF_INET;
    memcpy(&target_addr->sin_addr.s_addr, buffer + 4, 4);
    target_addr->sin_port = htons(port);

    return true;
}
