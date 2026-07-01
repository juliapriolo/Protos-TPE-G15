#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_METHOD_NO_AUTH 0x00
#define SOCKS5_METHOD_USERNAME_PASSWORD 0x02
#define SOCKS5_METHOD_NO_ACCEPTABLE 0xFF
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_REPLY_SUCCESS 0x00
#define SOCKS5_REPLY_GENERAL_FAILURE 0x01
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 0x08
#define SOCKS5_IPV4_REQUEST_SIZE 10
#define SOCKS5_RESPONSE_SIZE 10
#define SOCKS5_GREETING_RESPONSE_SIZE 2
#define SOCKS5_AUTH_VERSION 0x01
#define SOCKS5_AUTH_RESPONSE_SIZE 2
#define SOCKS5_AUTH_SUCCESS 0x00
#define SOCKS5_AUTH_FAILURE 0x01

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

bool socks5_parse_ipv4_connect(
    const uint8_t *buffer,
    size_t len,
    struct sockaddr_in *target_addr
);

#endif
