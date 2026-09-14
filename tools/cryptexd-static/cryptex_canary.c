#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("codex-cryptex1-canary uid=%u euid=%u\n", getuid(), geteuid());
    return 0;
}
