#ifndef USERS_H
#define USERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define USERS_MAX 10
#define USERS_FIELD_MAX 255

struct users;

typedef enum {
    USERS_RESULT_OK = 0,
    USERS_RESULT_EXISTS,
    USERS_RESULT_NOT_FOUND,
    USERS_RESULT_FULL,
    USERS_RESULT_INVALID,
} users_result_t;

void users_init_from_args(const struct users *initial_users, size_t count);
bool users_are_configured(void);
size_t users_count(void);
bool users_credentials_are_valid(const uint8_t *username,
                                 uint8_t username_len,
                                 const uint8_t *password,
                                 uint8_t password_len);
users_result_t users_add(const char *username, const char *password);
users_result_t users_remove(const char *username);
void users_format_list(char *buffer, size_t buffer_size);
const char *users_result_name(users_result_t result);

#endif
