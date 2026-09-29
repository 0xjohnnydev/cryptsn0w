#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static bool simulate;
static int results[8];
static size_t result_index, transferred;
static unsigned char captured[32];

static ssize_t next_result(size_t length) {
    assert(result_index < sizeof(results) / sizeof(results[0]));
    int result = results[result_index++];
    if (result < 0) { errno = -result; return -1; }
    assert((size_t)result <= length);
    return result;
}

static ssize_t test_write(int descriptor, const void *bytes, size_t length) {
    if (!simulate) return write(descriptor, bytes, length);
    ssize_t result = next_result(length);
    if (result > 0) {
        assert(transferred + (size_t)result <= sizeof(captured));
        memcpy(captured + transferred, bytes, (size_t)result);
        transferred += (size_t)result;
    }
    return result;
}

static ssize_t test_read(int descriptor, void *bytes, size_t length) {
    if (!simulate) return read(descriptor, bytes, length);
    ssize_t result = next_result(length);
    if (result > 0) {
        assert(transferred + (size_t)result <= sizeof(captured));
        memcpy(bytes, captured + transferred, (size_t)result);
        transferred += (size_t)result;
    }
    return result;
}

#define read test_read
#define write test_write
#include "io_helpers.h"
#undef read
#undef write

int main(void) {
    simulate = true;
    assert(read_all(-1, NULL, 0) && write_all(-1, NULL, 0));
    assert(result_index == 0);
    for (unsigned writing = 0; writing < 2; ++writing) {
        unsigned char bytes[6] = "abcde";
        memcpy(captured, bytes, sizeof(bytes));
        result_index = transferred = 0;
        results[0] = -EINTR; results[1] = 2;
        results[2] = -EINTR; results[3] = 4;
        if (!writing) memset(bytes, 0, sizeof(bytes));
        assert(writing ? write_all(-1, bytes, sizeof(bytes))
                       : read_all(-1, bytes, sizeof(bytes)));
        assert(result_index == 4 && transferred == sizeof(bytes));
        assert(memcmp(bytes, captured, sizeof(bytes)) == 0);
        for (int failure = 0; failure < 3; ++failure) {
            result_index = transferred = 0;
            results[0] = 2;
            results[1] = failure == 0 ? 0 : failure == 1 ? -EIO : -EAGAIN;
            assert(!(writing ? write_all(-1, bytes, sizeof(bytes))
                             : read_all(-1, bytes, sizeof(bytes))));
            assert(result_index == 2 && transferred == 2);
        }
    }

    simulate = false;
    alarm(10);
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    pid_t child = fork();
    assert(child >= 0);
    unsigned char block[64 * 1024];
    memset(block, 0xa5, sizeof(block));
    if (child == 0) {
        close(descriptors[0]);
        for (int round = 0; round < 16; ++round) {
            if (!write_all(descriptors[1], block, sizeof(block))) _exit(1);
        }
        close(descriptors[1]);
        _exit(0);
    }
    close(descriptors[1]);
    unsigned char received[sizeof(block)];
    for (int round = 0; round < 16; ++round) {
        assert(read_all(descriptors[0], received, sizeof(received)));
        assert(memcmp(block, received, sizeof(block)) == 0);
    }
    assert(!read_all(descriptors[0], received, 1));
    close(descriptors[0]);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    alarm(0);
    puts("Shared I/O tests passed: partial transfers, interruptions, failures, and 1 MiB pipe transfer.");
    return 0;
}
