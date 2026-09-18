#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CODEX_INTERPOSE_SENTINEL ((pid_t)424242)

struct codex_dyld_interpose_tuple {
    const void *replacement;
    const void *replacee;
};

typedef void (*codex_dyld_dynamic_interpose_fn)(
    const struct mach_header *image,
    const struct codex_dyld_interpose_tuple tuples[], size_t count);

static const char *const kReportPath =
    "/var/mobile/Media/codex-dyld-interpose-report.txt";

static uintptr_t *find_authenticated_getpid_slot(
    const struct mach_header_64 *header, uintptr_t replaceeValue,
    uint64_t *sectionSizeOut, size_t *matchCountOut) {
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return NULL;
    }

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = cursor + header->sizeofcmds;
    const struct section_64 *authGot = NULL;
    uintptr_t slide = 0;
    bool haveSlide = false;

    for (uint32_t index = 0; index < header->ncmds; index++) {
        if ((size_t)(commandsEnd - cursor) < sizeof(struct load_command)) {
            return NULL;
        }
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) ||
            (size_t)(commandsEnd - cursor) < command->cmdsize) {
            return NULL;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) ==
                    0 &&
                segment->fileoff == 0) {
                slide = (uintptr_t)header - (uintptr_t)segment->vmaddr;
                haveSlide = true;
            }

            size_t sectionsBytes =
                (size_t)segment->nsects * sizeof(struct section_64);
            if (sectionsBytes <= command->cmdsize - sizeof(*segment)) {
                const struct section_64 *sections =
                    (const struct section_64 *)(segment + 1);
                for (uint32_t sectionIndex = 0;
                     sectionIndex < segment->nsects; sectionIndex++) {
                    if (strncmp(sections[sectionIndex].segname, "__DATA_CONST",
                                sizeof(sections[sectionIndex].segname)) == 0 &&
                        strncmp(sections[sectionIndex].sectname, "__auth_got",
                                sizeof(sections[sectionIndex].sectname)) == 0) {
                        authGot = &sections[sectionIndex];
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }
    if (!haveSlide || authGot == NULL ||
        authGot->size < sizeof(uintptr_t) ||
        authGot->size % sizeof(uintptr_t) != 0) {
        return NULL;
    }

    uintptr_t target = (uintptr_t)ptrauth_strip(
        (void *)replaceeValue, ptrauth_key_function_pointer);
    uintptr_t *slots = (uintptr_t *)(slide + (uintptr_t)authGot->addr);
    size_t slotCount = (size_t)(authGot->size / sizeof(uintptr_t));
    uintptr_t *firstMatch = NULL;
    size_t matchCount = 0;
    for (size_t index = 0; index < slotCount; index++) {
        uintptr_t candidate = (uintptr_t)ptrauth_strip(
            (void *)slots[index], ptrauth_key_function_pointer);
        if (candidate == target) {
            if (firstMatch == NULL) {
                firstMatch = &slots[index];
            }
            matchCount++;
        }
    }
    if (sectionSizeOut != NULL) {
        *sectionSizeOut = authGot->size;
    }
    if (matchCountOut != NULL) {
        *matchCountOut = matchCount;
    }
    return firstMatch;
}

__attribute__((noinline)) static pid_t imported_getpid_call(void) {
    __asm__ volatile("" ::: "memory");
    pid_t result = getpid();
    __asm__ volatile("" ::: "memory");
    return result;
}

__attribute__((noinline)) static pid_t replacement_getpid(void) {
    return CODEX_INTERPOSE_SENTINEL;
}

int main(int argc, char **argv) {
    const char *mode = argc == 2 ? argv[1] : "standard";
    bool reversed = strcmp(mode, "reversed") == 0 ||
                    strcmp(mode, "stripped-reversed") == 0;
    bool stripped = strcmp(mode, "stripped") == 0 ||
                    strcmp(mode, "stripped-reversed") == 0;
    if (argc > 2 || (strcmp(mode, "standard") != 0 && !reversed &&
                     !stripped)) {
        return 69;
    }
    int report = open(kReportPath,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (report < 0) {
        return 70;
    }

    pid_t processPid = getpid();
    pid_t before = imported_getpid_call();
    Dl_info imageInfo = {0};
    int imageResult = dladdr((const void *)(uintptr_t)&main, &imageInfo);
    void *symbol = dlsym(RTLD_DEFAULT, "dyld_dynamic_interpose");
    const char *symbolError = dlerror();
    void *replacee = dlsym(RTLD_DEFAULT, "getpid");
    const char *replaceeError = dlerror();
    uintptr_t replacementValue =
        (uintptr_t)(const void *)(uintptr_t)&replacement_getpid;
    uintptr_t replaceeValue = (uintptr_t)replacee;
    if (stripped) {
        replacementValue = (uintptr_t)ptrauth_strip(
            (void *)replacementValue, ptrauth_key_function_pointer);
        replaceeValue = (uintptr_t)ptrauth_strip(
            (void *)replaceeValue, ptrauth_key_function_pointer);
    }
    uint64_t authGotSize = 0;
    size_t getpidSlotMatches = 0;
    uintptr_t *getpidSlot = find_authenticated_getpid_slot(
        (const struct mach_header_64 *)imageInfo.dli_fbase,
        (uintptr_t)replacee, &authGotSize, &getpidSlotMatches);
    uintptr_t slotBefore = getpidSlot != NULL ? *getpidSlot : 0;
    uintptr_t slotBeforeStripped = (uintptr_t)ptrauth_strip(
        (void *)slotBefore, ptrauth_key_function_pointer);

    dprintf(report,
            "magic=codex-dyld-dynamic-interpose-v1\nprocessPid=%d\n"
            "mode=%s\nreversed=%d\nstripped=%d\nbefore=%d\n"
            "imageResult=%d\nimageBase=%p\nimagePath=%s\n"
            "interposeSymbol=%p\ninterposeError=%s\nreplacee=%p\n"
            "replaceeError=%s\nreplacement=%p\nreplaceeValue=%p\n"
            "replacementValue=%p\nauthGotSize=%llu\n"
            "getpidSlotMatches=%zu\ngetpidSlot=%p\nslotBefore=0x%llx\n"
            "slotBeforeStripped=0x%llx\n",
            processPid, mode, reversed, stripped, before, imageResult,
            imageInfo.dli_fbase,
            imageInfo.dli_fname != NULL ? imageInfo.dli_fname : "",
            symbol, symbolError != NULL ? symbolError : "",
            replacee, replaceeError != NULL ? replaceeError : "",
            (const void *)(uintptr_t)&replacement_getpid,
            (const void *)replaceeValue, (const void *)replacementValue,
            (unsigned long long)authGotSize, getpidSlotMatches,
            (void *)getpidSlot, (unsigned long long)slotBefore,
            (unsigned long long)slotBeforeStripped);
    (void)fsync(report);

    if (imageResult == 0 || imageInfo.dli_fbase == NULL || symbol == NULL ||
        replacee == NULL || getpidSlot == NULL || getpidSlotMatches != 1) {
        close(report);
        return 71;
    }

    struct codex_dyld_interpose_tuple tuple = {
        .replacement = (const void *)(reversed ? replaceeValue
                                              : replacementValue),
        .replacee = (const void *)(reversed ? replacementValue
                                          : replaceeValue),
    };
    ((codex_dyld_dynamic_interpose_fn)symbol)(
        (const struct mach_header *)imageInfo.dli_fbase, &tuple, 1);

    pid_t after = imported_getpid_call();
    uintptr_t slotAfter = *getpidSlot;
    uintptr_t slotAfterStripped = (uintptr_t)ptrauth_strip(
        (void *)slotAfter, ptrauth_key_function_pointer);
    dprintf(report,
            "slotAfter=0x%llx\nslotAfterStripped=0x%llx\n"
            "slotChanged=%d\nafter=%d\ninterposed=%d\n"
            "processStillExact=%d\n",
            (unsigned long long)slotAfter,
            (unsigned long long)slotAfterStripped, slotAfter != slotBefore,
            after, after == CODEX_INTERPOSE_SENTINEL,
            processPid > 1 && before == processPid);
    bool reportOk = fsync(report) == 0;
    close(report);
    return processPid > 1 && before == processPid && reportOk ? 0 : 72;
}
