/**
 * Vulnerable: Format string -- user input used directly as format string.
 */
#include <stdio.h>
#include <syslog.h>

void log_message(const char *user_input) {
    printf(user_input);          /* user controls format string */
    printf("\n");
}

void log_to_syslog(const char *msg) {
    syslog(LOG_INFO, msg);       /* user controls format string */
}

int main(int argc, char **argv) {
    if (argc > 1) {
        log_message(argv[1]);
        log_to_syslog(argv[1]);
    }
    return 0;
}
