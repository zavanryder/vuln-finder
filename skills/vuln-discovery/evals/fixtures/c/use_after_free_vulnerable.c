/**
 * Vulnerable: Use-after-free -- pointer used after free, double free.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
    char name[32];
    int role;
};

struct user *create_user(const char *name) {
    struct user *u = malloc(sizeof(struct user));
    strncpy(u->name, name, sizeof(u->name) - 1);
    u->role = 0;
    return u;
}

void process(int should_delete) {
    struct user *u = create_user("alice");
    printf("Created: %s\n", u->name);

    if (should_delete) {
        free(u);
    }

    /* Use after free: u may have been freed above */
    printf("Role: %d\n", u->role);

    /* Double free if should_delete was true */
    free(u);
}

int main() {
    process(1);
    return 0;
}
