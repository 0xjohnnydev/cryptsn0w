#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CODEX_CS_OPS_STATUS 0
#define CODEX_CDHASH_SIZE 20U

static const char *const kResultPath =
    "/private/var/tmp/codex-compilation-trust-helper.result";

extern int csops(pid_t pid, unsigned int ops, void *useraddr,
                 size_t usersize);

static int hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static bool parse_cdhash(const char *text,
                         uint8_t cdhash[CODEX_CDHASH_SIZE]) {
    if (text == NULL || strlen(text) != CODEX_CDHASH_SIZE * 2U) {
        return false;
    }
    for (size_t index = 0; index < CODEX_CDHASH_SIZE; ++index) {
        int high = hex_nibble(text[index * 2U]);
        int low = hex_nibble(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        cdhash[index] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static void record_result(const char *phase, kern_return_t open_result,
                          kern_return_t call_result, uint32_t csflags,
                          int exit_code) {
    char line[512];
    int length = snprintf(
        line, sizeof(line),
        "phase=%s pid=%d uid=%u euid=%u csflags=0x%08x "
        "open=0x%08x call=0x%08x exit=%d\n",
        phase, getpid(), getuid(), geteuid(), csflags,
        (uint32_t)open_result, (uint32_t)call_result, exit_code);
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        return;
    }

    (void)write(STDOUT_FILENO, line, (size_t)length);

    int descriptor = open(kResultPath,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) {
        return;
    }
    struct stat attributes;
    if (fstat(descriptor, &attributes) == 0 &&
        S_ISREG(attributes.st_mode) && attributes.st_nlink == 1) {
        (void)fchmod(descriptor, 0600);
        (void)write(descriptor, line, (size_t)length);
        (void)fsync(descriptor);
    }
    (void)close(descriptor);
}

int main(int argc, char **argv) {
    uint32_t csflags = 0;
    (void)csops(getpid(), CODEX_CS_OPS_STATUS, &csflags, sizeof(csflags));

    uint8_t cdhash[CODEX_CDHASH_SIZE];
    if (argc != 2 || !parse_cdhash(argv[1], cdhash)) {
        record_result("parse", KERN_INVALID_ARGUMENT,
                      KERN_INVALID_ARGUMENT, csflags, 64);
        return 64;
    }

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AppleMobileFileIntegrity"));
    if (service == IO_OBJECT_NULL) {
        record_result("service", KERN_NOT_FOUND, KERN_NOT_FOUND,
                      csflags, 70);
        return 70;
    }

    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t open_result =
        IOServiceOpen(service, mach_task_self(), 0, &connection);
    (void)IOObjectRelease(service);
    if (open_result != KERN_SUCCESS) {
        record_result("open", open_result, KERN_FAILURE, csflags, 71);
        return 71;
    }

    kern_return_t call_result = IOConnectCallStructMethod(
        connection, 5, cdhash, sizeof(cdhash), NULL, NULL);
    (void)IOServiceClose(connection);
    if (call_result != KERN_SUCCESS) {
        record_result("selector5", open_result, call_result, csflags, 72);
        return 72;
    }

    record_result("success", open_result, call_result, csflags, 0);
    return 0;
}
