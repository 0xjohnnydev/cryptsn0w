#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import pathlib


EXPECTED_THREAD_UTILS_SHA256 = (
    "7e95b4f96ff27b07a0007bb3d859c1bd698f6b70df95344d87a41c82e11a2685"
)
EXPECTED_ROP_INJECT_SHA256 = (
    "08bba275bcb1a8b17502dfb1cf6a82ecc8c977f6eee4e50709ebafadda363d74"
)


def checked_text(path: pathlib.Path, expected_sha256: str) -> str:
    source_bytes = path.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    if digest != expected_sha256:
        raise SystemExit(f"unexpected pinned source hash for {path.name}: {digest}")
    return source_bytes.decode("utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one {label} patch site, found {count}")
    return text.replace(old, new, 1)


def patch_thread_utils(text: str) -> str:
    start = text.index("kern_return_t wait_for_thread(")
    end = text.index("\nkern_return_t suspend_threads_except_for", start)
    replacement = r'''kern_return_t wait_for_thread(thread_act_t thread, uint64_t pcToWait, struct arm_unified_thread_state* stateOut)
{
	// A malformed or changed remote call must not spin while the target's
	// remaining threads are suspended. These in-process calls normally finish
	// in milliseconds; three seconds leaves ample scheduling margin.
	static const unsigned int pollLimit = 3000;
	static const useconds_t pollIntervalUs = 1000;
	struct arm_unified_thread_state stateToObserve;
	int errCount = 0;

	for (unsigned int poll = 0; poll < pollLimit; poll++)
	{
		mach_msg_type_number_t stateToObserveCount = ARM_THREAD_STATE64_COUNT;
		kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&stateToObserve.ts_64, &stateToObserveCount);
		if(kr != KERN_SUCCESS)
		{
			if (pcToWait == 0) return kr;

			errCount++;
			if(errCount >= 5)
			{
				return kr;
			}
			usleep(pollIntervalUs);
			continue;
		}

		errCount = 0;
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToObserve.ts_64);
		if(pc == pcToWait) {
			if(stateOut) *stateOut = stateToObserve;
			return KERN_SUCCESS;
		}
		usleep(pollIntervalUs);
	}

	return KERN_OPERATION_TIMED_OUT;
}
'''
    return text[:start] + replacement + text[end:]


def patch_rop_inject(text: str) -> str:
    text = replace_once(
        text,
        '''\tkr = wait_for_thread(bootstrapThread, ropLoop, &outState);
\tif(kr != KERN_SUCCESS)
\t{
\t\tprintf("[createRemotePthread] ERROR: failed to wait for bootstrap thread: %s\\n", mach_error_string(kr));
\t\treturn kr;
\t}
''',
        '''\tkr = wait_for_thread(bootstrapThread, ropLoop, &outState);
\tif(kr != KERN_SUCCESS)
\t{
\t\tthread_terminate(bootstrapThread);
\t\tvm_deallocate(task, remoteStack64, STACK_SIZE);
\t\tprintf("[createRemotePthread] ERROR: failed to wait for bootstrap thread: %s\\n", mach_error_string(kr));
\t\treturn kr;
\t}
''',
        "bootstrap timeout cleanup",
    )
    text = replace_once(
        text,
        '''\tkr = task_threads(task, &cachedThreads, &cachedThreadCount);
\tif (kr != KERN_SUCCESS) return kr;
''',
        '''\tkr = task_threads(task, &cachedThreads, &cachedThreadCount);
\tif (kr != KERN_SUCCESS) {
\t\tvm_deallocate(task, remoteStack, STACK_SIZE);
\t\t(void)thread_restore_state_arm64(targetThread, origThreadFullState);
\t\tthread_resume(targetThread);
\t\treturn kr;
\t}
''',
        "task_threads failure cleanup",
    )
    text = replace_once(
        text,
        '''\t\tif(kr != KERN_SUCCESS)
\t\t{
\t\t\tfree(origThreadFullState);
\t\t\tprintf("[arbCall] ERROR: failed to wait for thread to finish: %s\\n", mach_error_string(kr));
\t\t\treturn kr;
\t\t}
''',
        '''\t\tif(kr != KERN_SUCCESS)
\t\t{
\t\t\t// The target call did not reach the known loop. Restore its saved
\t\t\t// state and, most importantly, resume every other launchd thread.
\t\t\tthread_suspend(targetThread);
\t\t\tthread_abort(targetThread);
\t\t\t(void)thread_restore_state_arm64(targetThread, origThreadFullState);
\t\t\tresume_threads_except_for(cachedThreads, cachedThreadCount, targetThread);
\t\t\tvm_deallocate(mach_task_self(), (vm_offset_t)cachedThreads, sizeof(thread_act_array_t) * cachedThreadCount);
\t\t\tvm_deallocate(task, remoteStack, STACK_SIZE);
\t\t\tthread_resume(targetThread);
\t\t\tprintf("[arbCall] ERROR: failed to wait for thread to finish: %s\\n", mach_error_string(kr));
\t\t\treturn kr;
\t\t}
''',
        "arbCall timeout cleanup",
    )
    text = replace_once(
        text,
        '''\t\tif(!restoreSuccess)
\t\t{
\t\t\tprintf("[arbCall] ERROR: failed to revert to old thread state\\n");
\t\t\treturn kr;
\t\t}
''',
        '''\t\tif(!restoreSuccess)
\t\t{
\t\t\tthread_resume(targetThread);
\t\t\tprintf("[arbCall] ERROR: failed to revert to old thread state\\n");
\t\t\treturn KERN_FAILURE;
\t\t}
''',
        "restore failure resume",
    )
    text = replace_once(
        text,
        '''\t\tvoid* dlopenRet;
\t\tarbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
\t\tvm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

\t\tif (dlopenRet) {
''',
        '''\t\tvoid* dlopenRet = NULL;
\t\tkr = arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
\t\tvm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

\t\tif (kr != KERN_SUCCESS) {
\t\t\tprintf("[injectDylibViaRop] dlopen call failed: %s\\n", mach_error_string(kr));
\t\t}
\t\telse if (dlopenRet) {
''',
        "dlopen status handling",
    )
    start = text.index("bool sandboxFixup(")
    end = text.index("\nvoid injectDylibViaRop", start)
    sandbox_replacement = r'''static bool consumeSandboxExtensionForPath(
	task_t task, thread_act_t pthread, uint64_t consumeAddress,
	const char *extensionClass, const char *path, uint32_t flags)
{
	char *extension = sandbox_extension_issue_file(extensionClass, path, flags);
	if (extension == NULL) {
		printf("[sandboxFixup] failed to issue class=%s path=%s errno=%d (%s)\n",
		       extensionClass, path, errno, strerror(errno));
		return false;
	}

	size_t remoteExtensionSize = 0;
	vm_address_t remoteExtension = writeStringToTask(
		task, extension, &remoteExtensionSize);
	free(extension);
	if (remoteExtension == 0) {
		return false;
	}

	int64_t consumeResult = -1;
	kern_return_t kr = arbCall(
		task, pthread, (uint64_t *)&consumeResult, true, consumeAddress, 1,
		remoteExtension);
	vm_deallocate(task, remoteExtension, remoteExtensionSize);
	printf("[sandboxFixup] consume class=%s path=%s flags=0x%x "
	       "mach=%d handle=%lld\n",
	       extensionClass, path, flags, kr, (long long)consumeResult);
	return kr == KERN_SUCCESS && consumeResult > 0;
}

bool sandboxFixup(task_t task, thread_act_t pthread, pid_t pid,
	const char *dylibPath, vm_address_t allImageInfoAddr)
{
	bool readNeeded = sandbox_check(
		pid, "file-read-data", SANDBOX_FILTER_PATH |
		SANDBOX_CHECK_NO_REPORT, dylibPath);
	bool executableNeeded = sandbox_check(
		pid, "file-map-executable", SANDBOX_FILTER_PATH |
		SANDBOX_CHECK_NO_REPORT, dylibPath);
	bool jailbreakPath = strncmp(dylibPath, "/var/jb/", 8) == 0;
	if (!readNeeded && !executableNeeded && !jailbreakPath) {
		printf("[sandboxFixup] extensions not needed, skipping...\n");
		return true;
	}

	vm_address_t libSystemSandboxAddr = getRemoteImageAddress(
		task, allImageInfoAddr,
		"/usr/lib/system/libsystem_sandbox.dylib");
	uint64_t consumeAddress = remoteDlSym(
		task, libSystemSandboxAddr, "_sandbox_extension_consume");
	if (consumeAddress == 0) {
		printf("[sandboxFixup] sandbox_extension_consume unavailable\n");
		return false;
	}

	bool success = true;
	if (readNeeded) {
		success &= consumeSandboxExtensionForPath(
			task, pthread, consumeAddress, APP_SANDBOX_READ, dylibPath, 0);
	}
	if (executableNeeded) {
		success &= consumeSandboxExtensionForPath(
			task, pthread, consumeAddress, "com.apple.sandbox.executable",
			dylibPath, 0);
	}

	if (jailbreakPath) {
		// ElleKit scans and loads post-bootstrap dylibs and their dependencies
		// after this trusted injector enters the target. A token for only the
		// injector itself leaves that scan sandbox-denied. Grant the target a
		// process-local recursive view of the managed jailbreak root instead.
		success &= consumeSandboxExtensionForPath(
			task, pthread, consumeAddress, APP_SANDBOX_READ, "/var/jb",
			SANDBOX_EXTENSION_PREFIXMATCH);
		success &= consumeSandboxExtensionForPath(
			task, pthread, consumeAddress, "com.apple.sandbox.executable",
			"/var/jb", SANDBOX_EXTENSION_PREFIXMATCH);
	}
	return success;
}
'''
    text = text[:start] + sandbox_replacement + text[end:]
    text = replace_once(
        text,
        '''\tsandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

\tprintf("[injectDylibViaRop] Preparation done, now injecting!\\n");
''',
        '''\tif (!sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr)) {
\t\tprintf("[injectDylibViaRop] sandbox preparation failed; refusing injection\\n");
\t\tthread_terminate(pthread);
\t\treturn;
\t}

\tprintf("[injectDylibViaRop] Preparation done, now injecting!\\n");
''',
        "sandbox failure handling",
    )
    return text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add bounded waits and cleanup to pinned opa334/opainject."
    )
    parser.add_argument("thread_utils_source", type=pathlib.Path)
    parser.add_argument("rop_inject_source", type=pathlib.Path)
    parser.add_argument("destination_directory", type=pathlib.Path)
    args = parser.parse_args()

    thread_utils = patch_thread_utils(
        checked_text(args.thread_utils_source, EXPECTED_THREAD_UTILS_SHA256)
    )
    rop_inject = patch_rop_inject(
        checked_text(args.rop_inject_source, EXPECTED_ROP_INJECT_SHA256)
    )
    args.destination_directory.mkdir(parents=True, exist_ok=True)
    (args.destination_directory / "thread_utils.m").write_text(thread_utils)
    (args.destination_directory / "rop_inject.m").write_text(rop_inject)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
