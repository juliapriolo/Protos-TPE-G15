#include "include/socks5.h"

#include <arpa/inet.h>
#include <string.h>

bool socks5_client_offers_no_auth(const uint8_t *methods, size_t nmethods) {
    for (size_t i = 0; i < nmethods; i++) {
        if (methods[i] == SOCKS5_METHOD_NO_AUTH) {
            return true;
        }
    }

    return false;
}

bool socks5_client_offers_username_password(const uint8_t *methods, size_t nmethods) {
    for (size_t i = 0; i < nmethods; i++) {
        if (methods[i] == SOCKS5_METHOD_USERNAME_PASSWORD) {
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

void socks5_prepare_auth_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t status
) {
    buffer[0] = SOCKS5_AUTH_VERSION;
    buffer[1] = status;

    *len = SOCKS5_AUTH_RESPONSE_SIZE;
    *off = 0;
}

uint8_t socks5_request_reply_for(
    const uint8_t *buffer,
    size_t len
) {
    if (len < 4 || buffer[0] != SOCKS5_VERSION || buffer[2] != 0x00) {
        return SOCKS5_REPLY_GENERAL_FAILURE;
    }

    if (buffer[1] != SOCKS5_CMD_CONNECT) {
        return SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
    }

    if (buffer[3] != SOCKS5_ATYP_IPV4 &&
        buffer[3] != SOCKS5_ATYP_DOMAIN &&
        buffer[3] != SOCKS5_ATYP_IPV6) {
        return SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED;
    }

    if (socks5_request_is_incomplete(buffer, len)) {
        return SOCKS5_REPLY_GENERAL_FAILURE;
    }

    return SOCKS5_REPLY_SUCCESS;
}

bool socks5_request_is_incomplete(
    const uint8_t *buffer,
    size_t len
) {
    if (len < 4) {
        return true;
    }

    switch (buffer[3]) {
    case SOCKS5_ATYP_IPV4:
        return len < SOCKS5_IPV4_REQUEST_SIZE;
    case SOCKS5_ATYP_IPV6:
        return len < SOCKS5_IPV6_REQUEST_SIZE;
    case SOCKS5_ATYP_DOMAIN:
        if (len < 5) {
            return true;
        }
        return len < 5 + (size_t) buffer[4] + 2;
    default:
        return false;
    }
}

bool socks5_parse_connect_request(
    const uint8_t *buffer,
    size_t len,
    socks5_request_t *request
) {
    uint8_t reply = socks5_request_reply_for(buffer, len);

    if (reply != SOCKS5_REPLY_SUCCESS || request == NULL) {
        return false;
    }

    memset(request, 0, sizeof(*request));
    request->atyp = buffer[3];

    if (buffer[3] == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *addr = (struct sockaddr_in *) &request->addr;
        request->port = ((uint16_t) buffer[8] << 8) | (uint16_t) buffer[9];

        addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr.s_addr, buffer + 4, 4);
        addr->sin_port = htons(request->port);
        request->addr_len = sizeof(*addr);
        return true;
    }

    if (buffer[3] == SOCKS5_ATYP_IPV6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &request->addr;
        request->port = ((uint16_t) buffer[20] << 8) | (uint16_t) buffer[21];

        addr->sin6_family = AF_INET6;
        memcpy(&addr->sin6_addr, buffer + 4, 16);
        addr->sin6_port = htons(request->port);
        request->addr_len = sizeof(*addr);
        return true;
    }

    if (buffer[3] == SOCKS5_ATYP_DOMAIN) {
        uint8_t domain_len = buffer[4];
        size_t port_index = 5 + (size_t) domain_len;

        if (domain_len == 0) {
            return false;
        }

        memcpy(request->host, buffer + 5, domain_len);
        request->host[domain_len] = '\0';
        request->port = ((uint16_t) buffer[port_index] << 8) |
                        (uint16_t) buffer[port_index + 1];
        return true;
    }

    return false;
}
