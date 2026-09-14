#include <os/log.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CRYPTEX_UID_CANARY_MARKER
#define CRYPTEX_UID_CANARY_MARKER "unset-marker"
#endif

int
main(void)
{
	os_log_t log = os_log_create("com.openai.codex.cryptex1.uidcanary", "proof");
	os_log_with_type(log, OS_LOG_TYPE_DEFAULT,
	    "codex-cryptex1-uid-canary marker=%{public}s uid=%{public}u "
	    "euid=%{public}u gid=%{public}u egid=%{public}u pid=%{public}d",
	    CRYPTEX_UID_CANARY_MARKER, getuid(), geteuid(), getgid(), getegid(),
	    getpid());
	return 0;
}
