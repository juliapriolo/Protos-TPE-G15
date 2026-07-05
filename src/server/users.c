#include "include/users.h"

#include <stdio.h>
#include <string.h>

#include "../utils/include/args.h"

typedef struct managed_user {
    char username[USERS_FIELD_MAX + 1];
    char password[USERS_FIELD_MAX + 1];
    bool in_use;
} managed_user_t;

static managed_user_t managed_users[USERS_MAX];

static bool field_is_valid(const char *field) {
    size_t len;

    if (field == NULL) {
        return false;
    }

    len = strlen(field);
    return len > 0 && len <= USERS_FIELD_MAX;
}

static int find_user_index(const char *username) {
    for (size_t i = 0; i < USERS_MAX; i++) {
        if (managed_users[i].in_use &&
            strcmp(managed_users[i].username, username) == 0) {
            return (int) i;
        }
    }

    return -1;
}

static int find_free_index(void) {
    for (size_t i = 0; i < USERS_MAX; i++) {
        if (!managed_users[i].in_use) {
            return (int) i;
        }
    }

    return -1;
}

void users_init_from_args(const struct users *initial_users, size_t count) {
    memset(managed_users, 0, sizeof(managed_users));

    if (initial_users == NULL) {
        return;
    }

    for (size_t i = 0; i < count && i < USERS_MAX; i++) {
        users_add(initial_users[i].name, initial_users[i].pass);
    }
}

bool users_are_configured(void) {
    return users_count() > 0;
}

size_t users_count(void) {
    size_t count = 0;

    for (size_t i = 0; i < USERS_MAX; i++) {
        if (managed_users[i].in_use) {
            count++;
        }
    }

    return count;
}

bool users_credentials_are_valid(const uint8_t *username,
                                 uint8_t username_len,
                                 const uint8_t *password,
                                 uint8_t password_len) {
    for (size_t i = 0; i < USERS_MAX; i++) {
        if (!managed_users[i].in_use) {
            continue;
        }

        if (strlen(managed_users[i].username) == username_len &&
            strlen(managed_users[i].password) == password_len &&
            memcmp(managed_users[i].username, username, username_len) == 0 &&
            memcmp(managed_users[i].password, password, password_len) == 0) {
            return true;
        }
    }

    return false;
}

users_result_t users_add(const char *username, const char *password) {
    int index;

    if (!field_is_valid(username) || !field_is_valid(password)) {
        return USERS_RESULT_INVALID;
    }

    if (find_user_index(username) != -1) {
        return USERS_RESULT_EXISTS;
    }

    index = find_free_index();

    if (index == -1) {
        return USERS_RESULT_FULL;
    }

    snprintf(managed_users[index].username, sizeof(managed_users[index].username), "%s", username);
    snprintf(managed_users[index].password, sizeof(managed_users[index].password), "%s", password);
    managed_users[index].in_use = true;

    return USERS_RESULT_OK;
}

users_result_t users_remove(const char *username) {
    int index;

    if (!field_is_valid(username)) {
        return USERS_RESULT_INVALID;
    }

    index = find_user_index(username);

    if (index == -1) {
        return USERS_RESULT_NOT_FOUND;
    }

    memset(&managed_users[index], 0, sizeof(managed_users[index]));
    return USERS_RESULT_OK;
}

void users_format_list(char *buffer, size_t buffer_size) {
    size_t written;

    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    written = (size_t) snprintf(buffer, buffer_size, "users_count=%zu\n", users_count());

    for (size_t i = 0; i < USERS_MAX && written < buffer_size; i++) {
        int n;

        if (!managed_users[i].in_use) {
            continue;
        }

        n = snprintf(
            buffer + written,
            buffer_size - written,
            "user=%s\n",
            managed_users[i].username
        );

        if (n < 0) {
            return;
        }

        written += (size_t) n;
    }
}

const char *users_result_name(users_result_t result) {
    switch (result) {
    case USERS_RESULT_OK:
        return "ok";
    case USERS_RESULT_EXISTS:
        return "exists";
    case USERS_RESULT_NOT_FOUND:
        return "not_found";
    case USERS_RESULT_FULL:
        return "full";
    case USERS_RESULT_INVALID:
        return "invalid";
    default:
        return "unknown";
    }
}
