/**
 * Safe: Buffer overflow -- bounded copies with snprintf and strncpy.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[32];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("Hello, %s!\n", buf);
}

void format_log(const char *user, const char *action) {
    char log_entry[64];
    snprintf(log_entry, sizeof(log_entry), "User %s performed %s", user, action);
    puts(log_entry);
}

int main(int argc, char **argv) {
    if (argc > 1) greet(argv[1]);
    if (argc > 2) format_log(argv[1], argv[2]);
    return 0;
}
