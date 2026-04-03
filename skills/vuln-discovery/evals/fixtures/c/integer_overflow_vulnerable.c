/**
 * Vulnerable: Integer overflow in allocation size leads to heap overflow.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_items(unsigned int count, const char *data, size_t data_len) {
    /* If count is large, count * sizeof(int) wraps to a small value */
    int *items = malloc(count * sizeof(int));
    if (!items) return;

    /* Writes past the undersized allocation */
    memcpy(items, data, data_len);

    free(items);
}

char *read_packet(const unsigned char *raw) {
    unsigned short len = *(unsigned short *)raw;  /* attacker-controlled 16-bit length */
    char *buf = malloc(len + 1);                  /* len=0xFFFF -> 0xFFFF+1 = 0 on 16-bit */
    memcpy(buf, raw + 2, len);
    buf[len] = '\0';
    return buf;
}
