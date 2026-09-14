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
	// A malformed or changed remote call must not spin forever while launchd's
	// remaining threads are suspended. Fifteen seconds is deliberately much
	// longer than the tiny pthread bootstrap and dlopen calls performed here.
	static const unsigned int pollLimit = 15000;
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
