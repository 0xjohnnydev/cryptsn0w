#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/snapshot.h>
#include <unistd.h>

static int usage(const char *program) {
    fprintf(stderr, "usage: %s create|delete|revert MOUNTPOINT SNAPSHOT_NAME\n", program);
    return 64;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        return usage(argv[0]);
    }

    int fd = open(argv[2], O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", argv[2], strerror(errno));
        return 1;
    }

    int result;
    if (strcmp(argv[1], "create") == 0) {
        result = fs_snapshot_create(fd, argv[3], 0);
    } else if (strcmp(argv[1], "delete") == 0) {
        result = fs_snapshot_delete(fd, argv[3], 0);
    } else if (strcmp(argv[1], "revert") == 0) {
        result = fs_snapshot_revert(fd, argv[3], 0);
    } else {
        close(fd);
        return usage(argv[0]);
    }

    if (result != 0) {
        fprintf(stderr, "%s(%s, %s): errno=%d (%s)\n", argv[1], argv[2], argv[3], errno, strerror(errno));
        close(fd);
        return 1;
    }

    printf("%s succeeded: volume=%s snapshot=%s\n", argv[1], argv[2], argv[3]);
    close(fd);
    return 0;
}
