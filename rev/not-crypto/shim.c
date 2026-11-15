#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* LD_PRELOAD hook: dump arguments of memcmp, then pretend success.
 * Used for picoMini "not crypto" (CyLab id 222): the binary computes a fixed
 * 64-byte output (s1) and compares it against our input (s2); dump s1 to get the flag. */
int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = a, *q = b;
    fprintf(stderr, "\n[memcmp n=%zu]\n s1(hex): ", n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n s2(hex): ");
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", q[i]);
    fprintf(stderr, "\n s1(asc): ");
    for (size_t i = 0; i < n; i++) fputc((p[i] >= 32 && p[i] < 127) ? p[i] : '.', stderr);
    fprintf(stderr, "\n s2(asc): ");
    for (size_t i = 0; i < n; i++) fputc((q[i] >= 32 && q[i] < 127) ? q[i] : '.', stderr);
    fprintf(stderr, "\n");
    return 0;
}
