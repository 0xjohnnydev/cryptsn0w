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
        '''#import "arm64.h"

vm_address_t writeStringToTask''',
        '''#import "arm64.h"

struct codex_cached_injection_primitives {
	bool ready;
	uint64_t sharedCacheBase;
	uint8_t sharedCacheUUID[16];
	vm_address_t libDyld;
	vm_address_t libPthread;
	vm_address_t libSandbox;
	uint64_t ropLoop;
	uint64_t pthreadMainThreadNP;
	uint64_t pthreadSetSelf;
	uint64_t sandboxExtensionConsume;
	uint64_t dlopenAddress;
	uint64_t dlerrorAddress;
};

static struct codex_cached_injection_primitives codexPrimitives;

static uint64_t codexCanonicalAddress(uint64_t address)
{
	return address & 0x0000FFFFFFFFFFFFULL;
}

static bool codexTaskReadExact(task_t task, vm_address_t address,
	void *destination, size_t size)
{
	if (address == 0 || destination == NULL || size == 0 ||
		size > UINT32_MAX) return false;
	vm_size_t copied = 0;
	kern_return_t result = vm_read_overwrite(
		task, address, (vm_size_t)size, (vm_address_t)destination, &copied);
	return result == KERN_SUCCESS && copied == (vm_size_t)size;
}

static bool codexUUIDNonzero(const uint8_t uuid[16])
{
	uint8_t aggregate = 0;
	for (size_t index = 0; index < 16; index++) aggregate |= uuid[index];
	return aggregate != 0;
}

static bool codexTaskBytesMatchSelf(task_t target, vm_address_t address,
	size_t size)
{
	uint8_t targetBytes[16] = { 0 };
	uint8_t selfBytes[16] = { 0 };
	return size != 0 && size <= sizeof(targetBytes) &&
		codexTaskReadExact(target, address, targetBytes, size) &&
		codexTaskReadExact(mach_task_self(), address, selfBytes, size) &&
		memcmp(targetBytes, selfBytes, size) == 0;
}

bool codexPrewarmInjectionPrimitives(task_t task,
	vm_address_t allImageInfoAddr);
bool codexValidateInjectionPrimitives(task_t task,
	vm_address_t allImageInfoAddr);

vm_address_t writeStringToTask''',
        "cached primitive declarations",
    )
    text = replace_once(
        text,
        '''\t// GATHER OFFSETS
\t__unused vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");

\tuint64_t mainThread = 0;
\tif (@available(iOS 12, *)) {
\t\t// TODO: maybe instead of this, allocate our own pthread object?
\t\t// kinda worried about side effects here, but as long our thread doesn't
\t\t// somehow trigger pthread_main_thread modifications, it should be fine
\t\tuint64_t pthread_main_thread_np = remoteDlSym(task, libSystemPthreadAddr, "_pthread_main_thread_np");

\t\tuint32_t instructions[2];
\t\tkr = task_read(task, pthread_main_thread_np, &instructions[0], sizeof(instructions));
\t\tif (kr != KERN_SUCCESS) {
\t\t\tprintf("ERROR: Failed to find main thread (1/3)\\n");
\t\t\treturn kr;
\t\t}

\t\tuint64_t _main_thread_ptr = 0;
\t\tif (!decode_adrp_ldr(instructions[0], instructions[1], pthread_main_thread_np, &_main_thread_ptr)) {
\t\t\tprintf("ERROR: Failed to find main thread (2/3)\\n");
\t\t\treturn 1;
\t\t}

\t\tkr = task_read(task, _main_thread_ptr, &mainThread, sizeof(mainThread));
\t\tif (kr != KERN_SUCCESS) {
\t\t\tprintf("ERROR: Failed to find main thread (3/3)\\n");
\t\t\treturn kr;
\t\t}
\t}
\tuint64_t _pthread_set_self = remoteDlSym(task, libSystemPthreadAddr, "__pthread_set_self");
''',
        '''\tif (!codexValidateInjectionPrimitives(task, allImageInfoAddr)) {
\t\tprintf("[createRemotePthread] ERROR: cached primitives do not match target\\n");
\t\treturn KERN_INVALID_ADDRESS;
\t}

\tuint64_t mainThread = 0;
\tif (@available(iOS 12, *)) {
\t\tuint64_t pthread_main_thread_np =
\t\t\tcodexPrimitives.pthreadMainThreadNP;
\t\tuint32_t instructions[2] = { 0 };
\t\tkr = task_read(task, pthread_main_thread_np, &instructions[0], sizeof(instructions));
\t\tif (kr != KERN_SUCCESS) {
\t\t\tprintf("ERROR: Failed to find main thread (1/3)\\n");
\t\t\treturn kr;
\t\t}

\t\tuint64_t _main_thread_ptr = 0;
\t\tif (!decode_adrp_ldr(instructions[0], instructions[1],
\t\t\tpthread_main_thread_np, &_main_thread_ptr)) {
\t\t\tprintf("ERROR: Failed to find main thread (2/3)\\n");
\t\t\treturn KERN_FAILURE;
\t\t}

\t\tkr = task_read(task, _main_thread_ptr, &mainThread, sizeof(mainThread));
\t\tif (kr != KERN_SUCCESS) {
\t\t\tprintf("ERROR: Failed to find main thread (3/3)\\n");
\t\t\treturn kr;
\t\t}
\t}
\tuint64_t _pthread_set_self = codexPrimitives.pthreadSetSelf;
''',
        "cached pthread primitives",
    )
    text = replace_once(
        text,
        '''\tkr = thread_get_state(allThreadsForFindingValid[0], ARM_THREAD_STATE64, (thread_state_t)&validThreadState.ts_64, &validThreadStateCount);
\tif(kr != KERN_SUCCESS )
\t{
\t\tprintf("[createRemotePthread] ERROR: failed to get valid thread state: %s\\n", mach_error_string(kr));
\t\treturn kr;
\t}
''',
        '''\tkr = thread_get_state(allThreadsForFindingValid[0], ARM_THREAD_STATE64, (thread_state_t)&validThreadState.ts_64, &validThreadStateCount);
\tif(kr != KERN_SUCCESS )
\t{
\t\tvm_deallocate(mach_task_self(), (vm_offset_t)allThreadsForFindingValid, sizeof(thread_act_array_t) * threadCountForFindingValid);
\t\tprintf("[createRemotePthread] ERROR: failed to get valid thread state: %s\\n", mach_error_string(kr));
\t\treturn kr;
\t}
''',
        "valid thread state cleanup",
    )
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
        '''void prepareForMagic(task_t task, vm_address_t allImageInfoAddr)
{
\t// FIND INFINITE LOOP ROP GADGET
\tstatic dispatch_once_t onceToken;
\tdispatch_once (&onceToken, ^{
\t\tfindRopLoop(task, allImageInfoAddr);
\t});
\tprintf("[prepareForMagic] done, ropLoop: 0x%llX\\n", ropLoop);
}
''',
        r'''void prepareForMagic(task_t task, vm_address_t allImageInfoAddr)
{
	// The gated lane primes this against the loader's own stable shared cache
	// before the candidate is allowed to run. Never repeat the full-cache scan
	// inside the candidate's short launch window.
	if (ropLoop == 0) {
		findRopLoop(task, allImageInfoAddr);
	}
	printf("[prepareForMagic] done, ropLoop: 0x%llX\n", ropLoop);
}

bool codexPrewarmInjectionPrimitives(task_t task,
	vm_address_t allImageInfoAddr)
{
	memset(&codexPrimitives, 0, sizeof(codexPrimitives));
	struct dyld_all_image_infos imageInfos = { 0 };
	if (!codexTaskReadExact(task, allImageInfoAddr, &imageInfos,
		sizeof(imageInfos)) || imageInfos.version < 15 ||
		!imageInfos.libSystemInitialized || imageInfos.infoArrayCount == 0) {
		return false;
	}

	codexPrimitives.sharedCacheBase = codexCanonicalAddress(
		(uint64_t)imageInfos.sharedCacheBaseAddress);
	memcpy(codexPrimitives.sharedCacheUUID, imageInfos.sharedCacheUUID,
		sizeof(codexPrimitives.sharedCacheUUID));
	if (codexPrimitives.sharedCacheBase == 0 ||
		!codexUUIDNonzero(codexPrimitives.sharedCacheUUID)) {
		return false;
	}

	codexPrimitives.libDyld = getRemoteImageAddress(
		task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	codexPrimitives.libPthread = getRemoteImageAddress(
		task, allImageInfoAddr,
		"/usr/lib/system/libsystem_pthread.dylib");
	codexPrimitives.libSandbox = getRemoteImageAddress(
		task, allImageInfoAddr,
		"/usr/lib/system/libsystem_sandbox.dylib");
	if (codexPrimitives.libDyld == 0 ||
		codexPrimitives.libPthread == 0 ||
		codexPrimitives.libSandbox == 0) {
		return false;
	}
	codexPrimitives.pthreadMainThreadNP = remoteDlSym(
		task, codexPrimitives.libPthread, "_pthread_main_thread_np");
	codexPrimitives.pthreadSetSelf = remoteDlSym(
		task, codexPrimitives.libPthread, "__pthread_set_self");
	codexPrimitives.sandboxExtensionConsume = remoteDlSym(
		task, codexPrimitives.libSandbox,
		"_sandbox_extension_consume");
	codexPrimitives.dlopenAddress = remoteDlSym(
		task, codexPrimitives.libDyld, "_dlopen");
	codexPrimitives.dlerrorAddress = remoteDlSym(
		task, codexPrimitives.libDyld, "_dlerror");
	prepareForMagic(task, allImageInfoAddr);
	codexPrimitives.ropLoop = ropLoop;
	codexPrimitives.ready =
		codexPrimitives.libDyld != 0 &&
		codexPrimitives.libPthread != 0 &&
		codexPrimitives.libSandbox != 0 &&
		codexPrimitives.ropLoop >= codexPrimitives.sharedCacheBase &&
		codexPrimitives.pthreadMainThreadNP != 0 &&
		codexPrimitives.pthreadSetSelf != 0 &&
		codexPrimitives.sandboxExtensionConsume != 0 &&
		codexPrimitives.dlopenAddress != 0 &&
		codexPrimitives.dlerrorAddress != 0;
	printf("[codexPrewarm] ready=%d cacheBase=0x%llX "
		"libdyld=0x%llX libpthread=0x%llX libsandbox=0x%llX "
		"ropLoop=0x%llX pthreadMain=0x%llX pthreadSetSelf=0x%llX "
		"sandboxConsume=0x%llX dlopen=0x%llX dlerror=0x%llX\n",
		codexPrimitives.ready,
		(unsigned long long)codexPrimitives.sharedCacheBase,
		(unsigned long long)codexPrimitives.libDyld,
		(unsigned long long)codexPrimitives.libPthread,
		(unsigned long long)codexPrimitives.libSandbox,
		(unsigned long long)codexPrimitives.ropLoop,
		(unsigned long long)codexPrimitives.pthreadMainThreadNP,
		(unsigned long long)codexPrimitives.pthreadSetSelf,
		(unsigned long long)codexPrimitives.sandboxExtensionConsume,
		(unsigned long long)codexPrimitives.dlopenAddress,
		(unsigned long long)codexPrimitives.dlerrorAddress);
	return codexPrimitives.ready;
}

bool codexValidateInjectionPrimitives(task_t task,
	vm_address_t allImageInfoAddr)
{
	if (!codexPrimitives.ready) {
		printf("[codexValidate] stage=prewarm ready=0\n");
		return false;
	}
	struct dyld_all_image_infos imageInfos = { 0 };
	bool infosRead = codexTaskReadExact(
		task, allImageInfoAddr, &imageInfos, sizeof(imageInfos));
	bool cacheExact = infosRead && imageInfos.version >= 15 &&
		imageInfos.libSystemInitialized && imageInfos.infoArrayCount != 0 &&
		codexCanonicalAddress((uint64_t)imageInfos.sharedCacheBaseAddress) ==
			codexPrimitives.sharedCacheBase &&
		memcmp(imageInfos.sharedCacheUUID, codexPrimitives.sharedCacheUUID,
			sizeof(codexPrimitives.sharedCacheUUID)) == 0;
	if (!cacheExact) {
		printf("[codexValidate] stage=cache infosRead=%d version=%u "
			"libSystem=%d count=%u base=0x%llX expected=0x%llX uuid=%d\n",
			infosRead, imageInfos.version, imageInfos.libSystemInitialized,
			imageInfos.infoArrayCount,
			(unsigned long long)codexCanonicalAddress(
				(uint64_t)imageInfos.sharedCacheBaseAddress),
			(unsigned long long)codexPrimitives.sharedCacheBase,
			memcmp(imageInfos.sharedCacheUUID, codexPrimitives.sharedCacheUUID,
				sizeof(codexPrimitives.sharedCacheUUID)) == 0);
		return false;
	}

	// Matching UUID+base makes cache VM addresses boot-global. Validate the
	// exact cached addresses directly so repeat remote calls stay bounded.
	vm_address_t targetLibDyld = codexPrimitives.libDyld;
	vm_address_t targetLibPthread = codexPrimitives.libPthread;
	vm_address_t targetLibSandbox = codexPrimitives.libSandbox;

	uint32_t dyldMagic = 0, pthreadMagic = 0, sandboxMagic = 0;
	bool dyldRead = codexTaskReadExact(
		task, targetLibDyld, &dyldMagic, sizeof(dyldMagic));
	bool pthreadRead = codexTaskReadExact(
		task, targetLibPthread, &pthreadMagic, sizeof(pthreadMagic));
	bool sandboxRead = codexTaskReadExact(
		task, targetLibSandbox, &sandboxMagic, sizeof(sandboxMagic));
	if (!dyldRead || dyldMagic != MH_MAGIC_64 ||
		!pthreadRead || pthreadMagic != MH_MAGIC_64 ||
		!sandboxRead || sandboxMagic != MH_MAGIC_64) {
		printf("[codexValidate] stage=images dyld=%d/0x%08X "
			"pthread=%d/0x%08X sandbox=%d/0x%08X\n",
			dyldRead, dyldMagic, pthreadRead, pthreadMagic,
			sandboxRead, sandboxMagic);
		return false;
	}

	uint32_t loopInstruction = 0;
	uint32_t expectedLoopInstruction = CFSwapInt32(0x00000014);
	bool loopRead = codexTaskReadExact(
		task, codexPrimitives.ropLoop, &loopInstruction,
		sizeof(loopInstruction));
	bool loopSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.ropLoop, 4);
	bool pthreadMainSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.pthreadMainThreadNP, 8);
	bool pthreadSetSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.pthreadSetSelf, 16);
	bool sandboxSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.sandboxExtensionConsume, 16);
	bool dlopenSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.dlopenAddress, 16);
	bool dlerrorSelf = codexTaskBytesMatchSelf(
		task, codexPrimitives.dlerrorAddress, 16);
	bool valid = loopRead && loopInstruction == expectedLoopInstruction &&
		loopSelf && pthreadMainSelf && pthreadSetSelf && sandboxSelf &&
		dlopenSelf && dlerrorSelf;
	printf("[codexValidate] stage=bytes loopRead=%d loop=0x%08X "
		"expected=0x%08X loopSelf=%d pthreadMain=%d pthreadSetSelf=%d "
		"sandbox=%d dlopen=%d dlerror=%d valid=%d\n",
		loopRead, loopInstruction, expectedLoopInstruction, loopSelf,
		pthreadMainSelf, pthreadSetSelf, sandboxSelf, dlopenSelf,
		dlerrorSelf, valid);
	if (valid) {
		printf("[codexValidate] exact shared-cache primitives ready\n");
	}
	return valid;
}
''',
        "shared-cache primitive prewarm",
    )
    text = replace_once(
        text,
        '''\t\tvoid* dlopenRet;
\t\tarbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
\t\tvm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

\t\tif (dlopenRet) {
''',
        '''\t\tvoid* dlopenRet = NULL;
\t\t// Injection is process-lifetime state. The dyld admission hook owns
\t\t// live text branches and must never be unmapped under an active call.
\t\tkr = arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW | RTLD_NODELETE);
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

	(void)allImageInfoAddr;
	uint64_t consumeAddress = codexPrimitives.sandboxExtensionConsume;
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
        "\nvoid injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)",
        r'''
static bool codexHeldThreadSuspendCount(thread_act_t thread,
	integer_t *countOut)
{
	thread_basic_info_data_t information = { 0 };
	mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
	kern_return_t result = thread_info(
		thread, THREAD_BASIC_INFO, (thread_info_t)&information, &count);
	if (result != KERN_SUCCESS || count != THREAD_BASIC_INFO_COUNT ||
		information.suspend_count < 0) {
		return false;
	}
	if (countOut != NULL) *countOut = information.suspend_count;
	return true;
}

// Resolve libpthread's exact main pthread object and bind it to the one Mach
// thread whose THREAD_IDENTIFIER_INFO thread ID matches the pthread's cached
// 64-bit thread ID.  The offset is from this exact libsystem_pthread build:
// _pthread_threadid_np reads pthread_t + 0xD8.  Mach port names cannot be used
// here because task_threads returns names in the controller's IPC namespace.
// The external
// controller must already own exactly one hold on every target thread.  This
// avoids repurposing an arbitrary dyld or worker thread which may have been
// stopped while owning the very runtime state needed by dlopen.
bool codexCopyExactMainHeldThread(task_t task, thread_act_t *threadOut)
{
	if (!MACH_PORT_VALID(task) || threadOut == NULL ||
		!codexPrimitives.ready ||
		codexPrimitives.pthreadMainThreadNP == 0) {
		return false;
	}
	*threadOut = MACH_PORT_NULL;

	uint32_t instructions[2] = { 0 };
	kern_return_t result = task_read(
		task, codexPrimitives.pthreadMainThreadNP,
		instructions, sizeof(instructions));
	uint64_t mainThreadSlot = 0;
	if (result != KERN_SUCCESS ||
		!decode_adrp_ldr(instructions[0], instructions[1],
			codexPrimitives.pthreadMainThreadNP, &mainThreadSlot) ||
		mainThreadSlot == 0) {
		printf("[codexMainHeldThread] main slot decode failed mach=%d "
		       "slot=0x%llX\n", result,
		       (unsigned long long)mainThreadSlot);
		return false;
	}

	uint64_t mainPthread = 0;
	result = task_read(task, mainThreadSlot, &mainPthread,
	                   sizeof(mainPthread));
	mainPthread = codexCanonicalAddress(mainPthread);
	if (result != KERN_SUCCESS || mainPthread == 0) {
		printf("[codexMainHeldThread] main pthread read failed mach=%d "
		       "pthread=0x%llX\n", result,
		       (unsigned long long)mainPthread);
		return false;
	}
	uint64_t mainThreadID = 0;
	result = task_read(task, mainPthread + 0xD8ULL, &mainThreadID,
	                   sizeof(mainThreadID));
	if (result != KERN_SUCCESS || mainThreadID == 0) {
		printf("[codexMainHeldThread] main thread-id read failed mach=%d "
		       "pthread=0x%llX threadID=0x%llX\n", result,
		       (unsigned long long)mainPthread,
		       (unsigned long long)mainThreadID);
		return false;
	}

	thread_act_array_t threads = NULL;
	mach_msg_type_number_t count = 0;
	result = task_threads(task, &threads, &count);
	if (result != KERN_SUCCESS || threads == NULL || count == 0 ||
		count > 1024U) {
		if (threads != NULL) {
			vm_deallocate(mach_task_self(), (vm_address_t)threads,
			              (vm_size_t)(sizeof(*threads) * count));
		}
		printf("[codexMainHeldThread] thread inventory failed mach=%d "
		       "count=%u\n", result, count);
		return false;
	}

	bool allHeld = true;
	uint32_t matches = 0;
	thread_act_t selected = MACH_PORT_NULL;
	for (mach_msg_type_number_t index = 0; index < count; ++index) {
		thread_basic_info_data_t basic = { 0 };
		mach_msg_type_number_t basicCount = THREAD_BASIC_INFO_COUNT;
		kern_return_t basicResult = thread_info(
			threads[index], THREAD_BASIC_INFO,
			(thread_info_t)&basic, &basicCount);
		thread_identifier_info_data_t identifier = { 0 };
		mach_msg_type_number_t identifierCount =
			THREAD_IDENTIFIER_INFO_COUNT;
		kern_return_t identifierResult = thread_info(
			threads[index], THREAD_IDENTIFIER_INFO,
			(thread_info_t)&identifier, &identifierCount);
		bool held = basicResult == KERN_SUCCESS &&
			basicCount == THREAD_BASIC_INFO_COUNT &&
			basic.suspend_count >= 1;
		allHeld = allHeld && held;
		bool mainMatch = identifierResult == KERN_SUCCESS &&
			identifierCount == THREAD_IDENTIFIER_INFO_COUNT &&
			identifier.thread_id == mainThreadID;
		if (mainMatch) {
			++matches;
			if (held && basic.suspend_count == 1 &&
				!MACH_PORT_VALID(selected)) {
				selected = threads[index];
				continue;
			}
		}
		(void)mach_port_deallocate(mach_task_self(), threads[index]);
	}
	(void)vm_deallocate(mach_task_self(), (vm_address_t)threads,
	                    (vm_size_t)(sizeof(*threads) * count));

	bool exact = allHeld && matches == 1 && MACH_PORT_VALID(selected);
	printf("[codexMainHeldThread] threads=%u allHeld=%d "
	       "mainPthread=0x%llX mainThreadID=0x%llX matches=%u "
	       "selected=0x%x exact=%d\n", count, allHeld,
	       (unsigned long long)mainPthread,
	       (unsigned long long)mainThreadID, matches, selected, exact);
	if (!exact) {
		if (MACH_PORT_VALID(selected)) {
			(void)mach_port_deallocate(mach_task_self(), selected);
		}
		return false;
	}
	*threadOut = selected;
	return true;
}

// Run one bounded call on a thread which the external candidate controller
// already owns at suspend count one.  The call temporarily consumes exactly
// that hold, restores the complete original state, and returns the thread at
// the same suspend count.  It never creates a kernel thread in the target.
kern_return_t codexArbCallHeldThread(
	task_t task, thread_act_t targetThread, uint64_t *retOut,
	vm_address_t funcPtr, int numArgs, ...)
{
	if (!MACH_PORT_VALID(targetThread) || funcPtr == 0 ||
		numArgs < 0 || numArgs > 8 || !codexPrimitives.ready ||
		codexPrimitives.ropLoop == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	integer_t initialSuspendCount = -1;
	if (!codexHeldThreadSuspendCount(targetThread, &initialSuspendCount) ||
		initialSuspendCount != 1) {
		printf("[codexArbCallHeldThread] rejected suspend count=%d\n",
		       initialSuspendCount);
		return KERN_INVALID_ARGUMENT;
	}

	struct arm64_thread_full_state *original =
		thread_save_state_arm64(targetThread);
	if (original == NULL || !original->thread_valid) {
		free(original);
		return KERN_FAILURE;
	}

	vm_address_t remoteStack = 0;
	kern_return_t result = vm_allocate(
		task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if (result != KERN_SUCCESS) {
		free(original);
		return result;
	}
	result = vm_protect(task, remoteStack, STACK_SIZE, TRUE,
		VM_PROT_READ | VM_PROT_WRITE);
	if (result != KERN_SUCCESS) {
		vm_deallocate(task, remoteStack, STACK_SIZE);
		free(original);
		return result;
	}

	arm_thread_state64_t callState = original->thread;
	uint64_t stackPointer = remoteStack + (STACK_SIZE / 2);
	__darwin_arm_thread_state64_set_sp(
		callState, (void *)stackPointer);
	__darwin_arm_thread_state64_set_pc_fptr(
		callState, make_sym_callable((void *)funcPtr));
	__darwin_arm_thread_state64_set_lr_fptr(
		callState,
		make_sym_callable((void *)codexPrimitives.ropLoop));
	va_list arguments;
	va_start(arguments, numArgs);
	for (int index = 0; index < numArgs; ++index) {
		callState.__x[index] = va_arg(arguments, uint64_t);
	}
	va_end(arguments);

	(void)thread_abort(targetThread);
	result = thread_set_state(
		targetThread, ARM_THREAD_STATE64, (thread_state_t)&callState,
		ARM_THREAD_STATE64_COUNT);
	integer_t beforeRunCount = -1;
	bool beforeRunExact = result == KERN_SUCCESS &&
		codexHeldThreadSuspendCount(targetThread, &beforeRunCount) &&
		beforeRunCount == initialSuspendCount;
	if (!beforeRunExact) {
		bool restored = thread_restore_state_arm64(targetThread, original);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		printf("[codexArbCallHeldThread] setup failed mach=%d "
		       "before=%d restored=%d\n", result, beforeRunCount, restored);
		return result == KERN_SUCCESS ? KERN_FAILURE : result;
	}

	kern_return_t resumeResult = thread_resume(targetThread);
	struct arm_unified_thread_state returnState = { 0 };
	kern_return_t waitResult = resumeResult == KERN_SUCCESS
		? wait_for_thread(targetThread, codexPrimitives.ropLoop,
		                  &returnState)
		: resumeResult;
	// Once resumed, this exact thread must be re-held exactly once on every
	// path before its original state can be restored.
	kern_return_t suspendResult = resumeResult == KERN_SUCCESS
		? thread_suspend(targetThread)
		: KERN_FAILURE;
	if (suspendResult == KERN_SUCCESS) (void)thread_abort(targetThread);
	integer_t finalSuspendCount = -1;
	bool finalCountExact = suspendResult == KERN_SUCCESS &&
		codexHeldThreadSuspendCount(targetThread, &finalSuspendCount) &&
		finalSuspendCount == initialSuspendCount;
	bool restored = suspendResult == KERN_SUCCESS &&
		thread_restore_state_arm64(targetThread, original);
	if (suspendResult != KERN_SUCCESS) free(original);
	vm_deallocate(task, remoteStack, STACK_SIZE);

	bool complete = resumeResult == KERN_SUCCESS &&
		waitResult == KERN_SUCCESS && finalCountExact && restored;
	if (complete && retOut != NULL) *retOut = returnState.ts_64.__x[0];
	printf("[codexArbCallHeldThread] func=0x%llX resume=%d wait=%d "
	       "suspend=%d count=%d restored=%d complete=%d\n",
	       (unsigned long long)funcPtr, resumeResult, waitResult,
	       suspendResult, finalSuspendCount, restored, complete);
	if (!complete) {
		if (resumeResult != KERN_SUCCESS) return resumeResult;
		if (waitResult != KERN_SUCCESS) return waitResult;
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static bool consumeSandboxExtensionForPathHeld(
	task_t task, thread_act_t thread, const char *extensionClass,
	const char *path, uint32_t flags)
{
	char *extension = sandbox_extension_issue_file(
		extensionClass, path, flags);
	if (extension == NULL) return false;
	size_t remoteSize = 0;
	vm_address_t remoteExtension = writeStringToTask(
		task, extension, &remoteSize);
	free(extension);
	if (remoteExtension == 0) return false;
	int64_t handle = -1;
	kern_return_t result = codexArbCallHeldThread(
		task, thread, (uint64_t *)&handle,
		codexPrimitives.sandboxExtensionConsume, 1, remoteExtension);
	vm_deallocate(task, remoteExtension, remoteSize);
	printf("[sandboxFixupHeld] consume class=%s path=%s flags=0x%x "
	       "mach=%d handle=%lld\n", extensionClass, path, flags, result,
	       (long long)handle);
	return result == KERN_SUCCESS && handle > 0;
}

static bool sandboxFixupHeld(task_t task, thread_act_t thread, pid_t pid,
	const char *dylibPath)
{
	bool readNeeded = sandbox_check(
		pid, "file-read-data", SANDBOX_FILTER_PATH |
		SANDBOX_CHECK_NO_REPORT, dylibPath);
	bool executableNeeded = sandbox_check(
		pid, "file-map-executable", SANDBOX_FILTER_PATH |
		SANDBOX_CHECK_NO_REPORT, dylibPath);
	bool jailbreakPath = strncmp(dylibPath, "/var/jb/", 8) == 0;
	bool success = true;
	if (readNeeded) {
		success &= consumeSandboxExtensionForPathHeld(
			task, thread, APP_SANDBOX_READ, dylibPath, 0);
	}
	if (executableNeeded) {
		success &= consumeSandboxExtensionForPathHeld(
			task, thread, "com.apple.sandbox.executable", dylibPath, 0);
	}
	if (jailbreakPath) {
		success &= consumeSandboxExtensionForPathHeld(
			task, thread, APP_SANDBOX_READ, "/var/jb",
			SANDBOX_EXTENSION_PREFIXMATCH);
		success &= consumeSandboxExtensionForPathHeld(
			task, thread, "com.apple.sandbox.executable", "/var/jb",
			SANDBOX_EXTENSION_PREFIXMATCH);
	}
	return success;
}

bool codexInjectDylibViaHeldThread(
	task_t task, thread_act_t thread, pid_t pid, const char *dylibPath,
	vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);
	bool primitivesExact = codexValidateInjectionPrimitives(
		task, allImageInfoAddr);
	printf("[codexInjectHeld] stage=sandbox-begin primitives=%d "
	       "pid=%d path=%s\n", primitivesExact, pid, dylibPath);
	bool sandboxExact = primitivesExact &&
		sandboxFixupHeld(task, thread, pid, dylibPath);
	printf("[codexInjectHeld] stage=sandbox-end exact=%d\n",
	       sandboxExact);
	if (!sandboxExact) {
		printf("[codexInjectHeld] primitive or sandbox preflight failed\n");
		return false;
	}
	size_t remotePathSize = 0;
	vm_address_t remotePath = writeStringToTask(
		task, dylibPath, &remotePathSize);
	printf("[codexInjectHeld] stage=path-write address=0x%llX size=%zu\n",
	       (unsigned long long)remotePath, remotePathSize);
	if (remotePath == 0) return false;
	uint64_t handle = 0;
	printf("[codexInjectHeld] stage=dlopen-begin thread=0x%x "
	       "function=0x%llX\n", thread,
	       (unsigned long long)codexPrimitives.dlopenAddress);
	kern_return_t result = codexArbCallHeldThread(
		task, thread, &handle, codexPrimitives.dlopenAddress, 2,
		remotePath, RTLD_NOW | RTLD_NODELETE);
	vm_deallocate(task, remotePath, remotePathSize);
	printf("[codexInjectHeld] path=%s mach=%d handle=0x%llX\n",
	       dylibPath, result, (unsigned long long)handle);
	if (result == KERN_SUCCESS && handle != 0) return true;
	uint64_t errorAddress = 0;
	if (result == KERN_SUCCESS &&
		codexArbCallHeldThread(
			task, thread, &errorAddress, codexPrimitives.dlerrorAddress,
			0) == KERN_SUCCESS && errorAddress != 0) {
		char *errorString = task_copy_string(task, errorAddress);
		printf("[codexInjectHeld] dlopen error: %s\n",
		       errorString != NULL ? errorString : "<unreadable>");
		free(errorString);
	}
	return false;
}

void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)''',
        "held-thread candidate injection",
    )
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
    text = replace_once(
        text,
        '''\t// FIND OFFSETS
\tvm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
\tuint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");
\tuint64_t dlerrorAddr = remoteDlSym(task, libDyldAddr, "_dlerror");
''',
        '''\t// These were resolved in the loader's identical boot-global
\t// shared cache and byte-validated against this target before thread work.
\tuint64_t dlopenAddr = codexPrimitives.dlopenAddress;
\tuint64_t dlerrorAddr = codexPrimitives.dlerrorAddress;
\tif (dlopenAddr == 0 || dlerrorAddr == 0) {
\t\tprintf("[injectDylibViaRop] cached dyld primitives unavailable\\n");
\t\tthread_terminate(pthread);
\t\treturn;
\t}
''',
        "cached dyld primitives",
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
