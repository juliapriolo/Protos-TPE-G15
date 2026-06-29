#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_METHOD_NO_AUTH 0x00
#define SOCKS5_METHOD_NO_ACCEPTABLE 0xFF
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_IPV4_REQUEST_SIZE 10
#define SOCKS5_RESPONSE_SIZE 10
#define SOCKS5_GREETING_RESPONSE_SIZE 2

bool socks5_client_offers_no_auth(const uint8_t *methods, size_t nmethods);

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

bool socks5_parse_ipv4_connect(
    const uint8_t *buffer,
    size_t len,
    struct sockaddr_in *target_addr
);

#endif
