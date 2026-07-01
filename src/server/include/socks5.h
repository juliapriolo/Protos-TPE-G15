#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_METHOD_NO_AUTH 0x00
#define SOCKS5_METHOD_USERNAME_PASSWORD 0x02
#define SOCKS5_METHOD_NO_ACCEPTABLE 0xFF
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_CONNECTION_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08
#define SOCKS5_IPV4_REQUEST_SIZE 10
#define SOCKS5_IPV6_REQUEST_SIZE 22
#define SOCKS5_DOMAIN_MIN_REQUEST_SIZE 7
#define SOCKS5_RESPONSE_SIZE 10
#define SOCKS5_GREETING_RESPONSE_SIZE 2
#define SOCKS5_AUTH_VERSION 0x01
#define SOCKS5_AUTH_RESPONSE_SIZE 2
#define SOCKS5_AUTH_SUCCESS 0x00
#define SOCKS5_AUTH_FAILURE 0x01
#define SOCKS5_MAX_DOMAIN_LENGTH 255

typedef struct socks5_request {
    uint8_t atyp;
    uint16_t port;
    char host[SOCKS5_MAX_DOMAIN_LENGTH + 1];
    struct sockaddr_storage addr;
    socklen_t addr_len;
} socks5_request_t;

bool socks5_client_offers_no_auth(const uint8_t *methods, size_t nmethods);
bool socks5_client_offers_username_password(const uint8_t *methods, size_t nmethods);

void socks5_prepare_greeting_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t method
);

void socks5_prepare_request_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t reply
);

void socks5_prepare_auth_response(
    uint8_t *buffer,
    size_t *len,
    size_t *off,
    uint8_t status
);

uint8_t socks5_request_reply_for(
    const uint8_t *buffer,
    size_t len
);

bool socks5_request_is_incomplete(
    const uint8_t *buffer,
    size_t len
);

bool socks5_parse_connect_request(
    const uint8_t *buffer,
    size_t len,
    socks5_request_t *request
);

#endif
