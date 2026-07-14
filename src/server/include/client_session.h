#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include <stddef.h>

#include "server.h"
#include "../../utils/include/selector.h"

void client_session_update_relay_interests(fd_selector selector, client_state_t *state);
void client_session_close_connection(fd_selector selector, client_state_t *state);
size_t client_session_active_count(void);

void client_write(struct selector_key *key);

extern const fd_handler accept_handler;

#endif
