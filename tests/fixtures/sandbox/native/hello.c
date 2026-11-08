/* TC-007 legitimate native build fixture (FR-007). */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "native build %s", "ok");
    printf("%s (%zu)\n", buf, strlen(buf));
    return 0;
}
