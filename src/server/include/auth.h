#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

#include "server.h"

bool auth_is_required(void);
bool auth_parse_request(client_state_t *state, bool *authenticated);

#endif
