/**
 * Vulnerable: Stack buffer overflow via strcpy and sprintf.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[32];
    strcpy(buf, name);  /* no bounds check */
    printf("Hello, %s!\n", buf);
}

void format_log(const char *user, const char *action) {
    char log_entry[64];
    sprintf(log_entry, "User %s performed %s", user, action);  /* can overflow */
    puts(log_entry);
}

int main(int argc, char **argv) {
    if (argc > 1) greet(argv[1]);
    if (argc > 2) format_log(argv[1], argv[2]);
    return 0;
}
