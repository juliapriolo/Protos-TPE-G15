#ifndef TARGET_CONNECTION_H
#define TARGET_CONNECTION_H

#include "server.h"
#include "socks5.h"
#include "../../utils/include/selector.h"

void target_connection_free_addresses(client_state_t *state);
void target_connection_detach_resolver(client_state_t *state);

void target_connection_begin(struct selector_key *key,
                             client_state_t *state,
                             const socks5_request_t *request);

void target_connection_on_resolve(struct selector_key *key);

void target_write(struct selector_key *key);

#endif
