#include "include/auth.h"
#include "include/socks5.h"
#include "include/users.h"

#include <string.h>

bool auth_is_required(void) {
    return users_are_configured();
}

bool auth_parse_request(client_state_t *state, bool *authenticated) {
    *authenticated = false;

    if (state->read_len < 2) {
        return false;
    }

    if (state->read_buffer[0] != SOCKS5_AUTH_VERSION) {
        return true;
    }

    uint8_t username_len = state->read_buffer[1];
    size_t password_len_index = 2 + (size_t) username_len;

    if (state->read_len < password_len_index + 1) {
        return false;
    }

    uint8_t password_len = state->read_buffer[password_len_index];
    size_t expected_len = password_len_index + 1 + (size_t) password_len;

    if (state->read_len < expected_len) {
        return false;
    }

    *authenticated = users_credentials_are_valid(
        state->read_buffer + 2,
        username_len,
        state->read_buffer + password_len_index + 1,
        password_len
    );

    if (*authenticated) {
        memcpy(state->username, state->read_buffer + 2, username_len);
        state->username[username_len] = '\0';
    }

    return true;
}
