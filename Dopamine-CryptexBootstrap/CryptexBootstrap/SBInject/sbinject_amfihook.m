#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#include "litehook_rebind.h"
#include "sbinject_protocol.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CODEX_CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CODEX_CSMAGIC_CODEDIRECTORY 0xfade0c02U
#define CODEX_CSSLOT_CODEDIRECTORY 0U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000U
#define CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005U
#define CODEX_CDHASH_LENGTH 20U
#define CODEX_MAX_SIGNATURE_SIZE (16U * 1024U * 1024U)
#define CODEX_CS_OPS_STATUS 0U
#define CODEX_CS_DEBUGGED 0x10000000U

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t offset;
} codex_blob_index_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    codex_blob_index_t index[];
} codex_superblob_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hash_offset;
    uint32_t identifier_offset;
    uint32_t special_slots;
    uint32_t code_slots;
    uint32_t code_limit;
    uint8_t hash_size;
    uint8_t hash_type;
    uint8_t platform;
    uint8_t page_size;
} codex_code_directory_t;

typedef int (*mis_validate_signature_t)(NSString *, NSDictionary *,
                                        NSMutableDictionary **);
typedef BOOL (*validator_computed_cdhash_t)(id, SEL, uint8_t *, uint8_t *);
typedef int (*validator_integer_getter_t)(id, SEL);
typedef BOOL (*validator_bool_getter_t)(id, SEL);
typedef id (*validator_object_getter_t)(id, SEL);

extern int csops(pid_t pid, unsigned int operation, void *user_address,
                 size_t user_size);

static mis_validate_signature_t g_original_validate;
static id (*g_original_validator_init)(id, SEL, NSURL *, uint64_t, uint64_t);
static BOOL (*g_original_validator_validate)(id, SEL, NSError **);
static validator_computed_cdhash_t g_original_validator_computed_cdhash;
static validator_integer_getter_t g_original_validator_signer_type;
static validator_bool_getter_t g_original_validator_is_valid;
static validator_bool_getter_t g_original_validator_entitlements_validated;
static validator_object_getter_t g_original_validator_profile_data;
static char g_validator_path_key;
static char g_validator_offset_key;

static bool managed_application_path(NSString *path);
static NSData *cdhash_for_file(NSString *path, NSDictionary *options);

static void amfi_file_log(const char *format, ...) {
    int descriptor = open(CODEX_SBINJECT_AMFID_LOG,
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (descriptor < 0) return;
    char line[2048];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length > 0) {
        size_t amount = (size_t)length < sizeof(line) - 1U
                            ? (size_t)length
                            : sizeof(line) - 1U;
        line[amount++] = '\n';
        (void)write(descriptor, line, amount);
    }
    (void)fchown(descriptor, 0, 0);
    (void)fchmod(descriptor, 0600);
    close(descriptor);
}

static os_log_t amfi_log(void) {
    static os_log_t log;
    if (log == NULL) {
        log = os_log_create("com.openai.codex.sbinject", "amfid-hook");
    }
    return log;
}

static bool exact_candidate(void) {
    uint32_t size = 0;
    (void)_NSGetExecutablePath(NULL, &size);
    char *path = calloc((size_t)size + 1U, 1U);
    if (path == NULL || _NSGetExecutablePath(path, &size) != 0) {
        free(path);
        return false;
    }
    char observed[PATH_MAX] = {0};
    char candidate[PATH_MAX] = {0};
    char stock[PATH_MAX] = {0};
    bool resolved = realpath(path, observed) != NULL;
    bool exact = resolved &&
        ((realpath(CODEX_SBINJECT_AMFID, candidate) != NULL &&
          strcmp(observed, candidate) == 0) ||
         (realpath(CODEX_SBINJECT_STOCK_AMFID, stock) != NULL &&
          strcmp(observed, stock) == 0));
    free(path);
    return exact;
}

static bool jit_ready_marker_matches_self(void) {
    struct stat status = {0};
    if (lstat(CODEX_SBINJECT_AMFID_JIT_READY_MARKER, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
        status.st_size <= 1 || status.st_size >= 32 ||
        (status.st_mode & 07777) != 0644) {
        return false;
    }
    int descriptor = open(CODEX_SBINJECT_AMFID_JIT_READY_MARKER,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return false;
    char contents[32] = {0};
    ssize_t amount = read(descriptor, contents, sizeof(contents) - 1U);
    close(descriptor);
    if (amount <= 1 || amount >= (ssize_t)sizeof(contents)) return false;
    char *end = NULL;
    errno = 0;
    long marker_pid = strtol(contents, &end, 10);
    return errno == 0 && marker_pid == (long)getpid() && end != contents &&
           end + 1 == contents + amount && *end == '\n';
}

static bool wait_until_debugged(uint32_t *flags_out, int *error_out) {
    uint32_t flags = 0;
    int status_error = 0;
    for (unsigned int attempt = 0; attempt < 3000U; ++attempt) {
        if (!jit_ready_marker_matches_self()) {
            usleep(10U * 1000U);
            continue;
        }
        errno = 0;
        if (csops(getpid(), CODEX_CS_OPS_STATUS, &flags, sizeof(flags)) == 0 &&
            (flags & CODEX_CS_DEBUGGED) != 0) {
            if (flags_out != NULL) *flags_out = flags;
            if (error_out != NULL) *error_out = 0;
            return true;
        }
        status_error = errno;
        usleep(10U * 1000U);
    }
    if (flags_out != NULL) *flags_out = flags;
    if (error_out != NULL) *error_out = status_error;
    return false;
}

static void write_failure_marker(NSString *reason) {
    NSData *contents = [[reason stringByAppendingString:@"\n"]
        dataUsingEncoding:NSUTF8StringEncoding];
    int descriptor = open(CODEX_SBINJECT_AMFID_FAILURE_MARKER,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0644);
    if (descriptor < 0) return;
    if (contents.length != 0) {
        (void)write(descriptor, contents.bytes, contents.length);
    }
    (void)fchown(descriptor, 0, 0);
    (void)fchmod(descriptor, 0644);
    (void)fsync(descriptor);
    close(descriptor);
}

static id hooked_validator_init(id object, SEL selector, NSURL *url,
                                uint64_t file_offset, uint64_t flags) {
    id result = g_original_validator_init(object, selector, url, file_offset,
                                          flags);
    NSString *path = [url isKindOfClass:NSURL.class] ? url.path : nil;
    if (result != nil && path.length != 0) {
        objc_setAssociatedObject(result, &g_validator_path_key, path.copy,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(result, &g_validator_offset_key,
                                 @(file_offset),
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (managed_application_path(path)) {
            amfi_file_log("validator-init pid=%d offset=%llu flags=0x%llx "
                          "path=%s",
                          getpid(), (unsigned long long)file_offset,
                          (unsigned long long)flags,
                          path.fileSystemRepresentation);
        }
    }
    return result;
}

static NSString *managed_validator_path(id object) {
    NSString *path = objc_getAssociatedObject(object, &g_validator_path_key);
    return managed_application_path(path) ? path : nil;
}

static NSDictionary *validator_cdhash_options(id object) {
    NSNumber *offset = objc_getAssociatedObject(object,
                                                &g_validator_offset_key);
    return [offset isKindOfClass:NSNumber.class]
               ? @{ @"UniversalFileOffset" : offset }
               : @{};
}

static BOOL hooked_validator_computed_cdhash(id object, SEL selector,
                                             uint8_t *output,
                                             uint8_t *output_length) {
    BOOL original = g_original_validator_computed_cdhash(
        object, selector, output, output_length);
    NSString *path = managed_validator_path(object);
    if (path == nil) return original;
    NSData *hash = cdhash_for_file(path, validator_cdhash_options(object));
    if (output == NULL || output_length == NULL ||
        hash.length != CODEX_CDHASH_LENGTH) {
        amfi_file_log("validator-cdhash pid=%d ready=false original=%d "
                      "path=%s",
                      getpid(), original,
                      path.fileSystemRepresentation);
        return original;
    }
    memcpy(output, hash.bytes, CODEX_CDHASH_LENGTH);
    *output_length = CODEX_CDHASH_LENGTH;
    amfi_file_log("validator-cdhash pid=%d ready=true original=%d length=%u "
                  "path=%s",
                  getpid(), original, (unsigned int)*output_length,
                  path.fileSystemRepresentation);
    return YES;
}

static int hooked_validator_signer_type(id object, SEL selector) {
    int original = g_original_validator_signer_type(object, selector);
    NSString *path = managed_validator_path(object);
    if (path == nil) return original;
    // AppSync reports fakesigned applications as App Store (2), not
    // developer-signed (3).  The latter requires a provisioning-profile
    // payload in amfid's reply and is rejected as "empty profile" before the
    // process reaches userspace, even when every other validation field is
    // populated correctly.
    amfi_file_log("validator-signer pid=%d original=%d forced=2 path=%s",
                  getpid(), original, path.fileSystemRepresentation);
    return 2;
}

static BOOL hooked_validator_is_valid(id object, SEL selector) {
    BOOL original = g_original_validator_is_valid(object, selector);
    NSString *path = managed_validator_path(object);
    if (path == nil) return original;
    amfi_file_log("validator-is-valid pid=%d original=%d forced=1 path=%s",
                  getpid(), original, path.fileSystemRepresentation);
    return YES;
}

static BOOL hooked_validator_entitlements_validated(id object, SEL selector) {
    BOOL original =
        g_original_validator_entitlements_validated(object, selector);
    NSString *path = managed_validator_path(object);
    if (path == nil) return original;
    amfi_file_log("validator-entitlements pid=%d original=%d forced=1 "
                  "path=%s",
                  getpid(), original, path.fileSystemRepresentation);
    return YES;
}

static NSData *scoped_profile_data(void) {
    struct stat status = {0};
    if (lstat(CODEX_SBINJECT_AMFID_PROFILE, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        status.st_size <= 0 || status.st_size > 4 * 1024 * 1024) {
        return nil;
    }
    int descriptor = open(CODEX_SBINJECT_AMFID_PROFILE,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)status.st_size];
    bool complete = data != nil;
    uint8_t *cursor = data.mutableBytes;
    size_t remaining = (size_t)status.st_size;
    while (complete && remaining != 0) {
        ssize_t amount = read(descriptor, cursor, remaining);
        if (amount <= 0) {
            complete = false;
            break;
        }
        cursor += amount;
        remaining -= (size_t)amount;
    }
    close(descriptor);
    return complete ? data : nil;
}

static id hooked_validator_profile_data(id object, SEL selector) {
    id original = g_original_validator_profile_data(object, selector);
    NSString *path = managed_validator_path(object);
    if (path == nil || original != nil) return original;
    NSData *profile = scoped_profile_data();
    amfi_file_log("validator-profile pid=%d original=false bytes=%lu path=%s",
                  getpid(), (unsigned long)profile.length,
                  path.fileSystemRepresentation);
    return profile;
}

static BOOL hooked_validator_validate(id object, SEL selector,
                                      NSError **error) {
    BOOL original_result =
        g_original_validator_validate(object, selector, error);
    NSString *path = objc_getAssociatedObject(object, &g_validator_path_key);
    if (!managed_application_path(path)) return original_result;
    NSInteger original_code = error != NULL && *error != nil
                                  ? (*error).code
                                  : 0;
    BOOL original_valid = g_original_validator_is_valid(object,
                                                        @selector(isValid));
    BOOL original_entitlements =
        g_original_validator_entitlements_validated(
            object, @selector(areEntitlementsValidated));
    int original_signer = g_original_validator_signer_type(
        object, @selector(signerType));
    amfi_file_log("validator-result pid=%d validate=%d isValid=%d "
                  "entitlements=%d signer=%d error=%ld path=%s",
                  getpid(), original_result, original_valid,
                  original_entitlements, original_signer,
                  (long)original_code, path.fileSystemRepresentation);
    if (original_result) return YES;
    if (error != NULL) *error = nil;
    os_log_with_type(amfi_log(), OS_LOG_TYPE_DEFAULT,
                     "scoped path-validator override error=%{public}ld "
                     "path=%{public}@",
                     (long)original_code, path);
    return YES;
}

static bool install_path_validator_hook(void) {
    Class validator = objc_getClass("AMFIPathValidator_ios");
    SEL init_selector =
        sel_registerName("initWithURL:withFileOffset:withFlags:");
    SEL validate_selector = sel_registerName("validateWithError:");
    SEL cdhash_selector =
        sel_registerName("computedCdHash:withLength:");
    SEL signer_selector = sel_registerName("signerType");
    SEL valid_selector = sel_registerName("isValid");
    SEL entitlements_selector =
        sel_registerName("areEntitlementsValidated");
    SEL profile_selector = sel_registerName("profileData");
    Method init_method = class_getInstanceMethod(validator, init_selector);
    Method validate_method =
        class_getInstanceMethod(validator, validate_selector);
    Method cdhash_method = class_getInstanceMethod(validator, cdhash_selector);
    Method signer_method = class_getInstanceMethod(validator, signer_selector);
    Method valid_method = class_getInstanceMethod(validator, valid_selector);
    Method entitlements_method =
        class_getInstanceMethod(validator, entitlements_selector);
    Method profile_method = class_getInstanceMethod(validator,
                                                    profile_selector);
    if (validator == Nil || init_method == NULL || validate_method == NULL ||
        cdhash_method == NULL || signer_method == NULL ||
        valid_method == NULL || entitlements_method == NULL) {
        amfi_file_log("path-validator methods missing init=%d validate=%d "
                      "cdhash=%d signer=%d valid=%d entitlements=%d",
                      init_method != NULL, validate_method != NULL,
                      cdhash_method != NULL, signer_method != NULL,
                      valid_method != NULL, entitlements_method != NULL);
        return false;
    }
    IMP old_init = method_setImplementation(
        init_method, (IMP)(void *)&hooked_validator_init);
    IMP old_validate = method_setImplementation(
        validate_method, (IMP)(void *)&hooked_validator_validate);
    IMP old_cdhash = method_setImplementation(
        cdhash_method, (IMP)(void *)&hooked_validator_computed_cdhash);
    IMP old_signer = method_setImplementation(
        signer_method, (IMP)(void *)&hooked_validator_signer_type);
    IMP old_valid = method_setImplementation(
        valid_method, (IMP)(void *)&hooked_validator_is_valid);
    IMP old_entitlements = method_setImplementation(
        entitlements_method,
        (IMP)(void *)&hooked_validator_entitlements_validated);
    IMP old_profile = profile_method != NULL
                          ? method_setImplementation(
                                profile_method,
                                (IMP)(void *)&hooked_validator_profile_data)
                          : NULL;
    g_original_validator_init =
        (id (*)(id, SEL, NSURL *, uint64_t, uint64_t))(void *)old_init;
    g_original_validator_validate =
        (BOOL (*)(id, SEL, NSError **))(void *)old_validate;
    g_original_validator_computed_cdhash =
        (validator_computed_cdhash_t)(void *)old_cdhash;
    g_original_validator_signer_type =
        (validator_integer_getter_t)(void *)old_signer;
    g_original_validator_is_valid =
        (validator_bool_getter_t)(void *)old_valid;
    g_original_validator_entitlements_validated =
        (validator_bool_getter_t)(void *)old_entitlements;
    g_original_validator_profile_data =
        (validator_object_getter_t)(void *)old_profile;
    bool ready = old_init != NULL && old_validate != NULL &&
                 old_cdhash != NULL && old_signer != NULL &&
                 old_valid != NULL && old_entitlements != NULL;
    os_log_with_type(
        amfi_log(), ready ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
        "path-validator hook ready=%{public}s initType=%{public}s "
        "validateType=%{public}s",
        ready ? "true" : "false",
        method_getTypeEncoding(init_method) != NULL
            ? method_getTypeEncoding(init_method)
            : "missing",
        method_getTypeEncoding(validate_method) != NULL
            ? method_getTypeEncoding(validate_method)
            : "missing");
    amfi_file_log("path-validator ready=%d init=%s validate=%s cdhash=%s "
                  "signer=%s valid=%s entitlements=%s profile=%s",
                  ready,
                  method_getTypeEncoding(init_method),
                  method_getTypeEncoding(validate_method),
                  method_getTypeEncoding(cdhash_method),
                  method_getTypeEncoding(signer_method),
                  method_getTypeEncoding(valid_method),
                  method_getTypeEncoding(entitlements_method),
                  profile_method != NULL
                      ? method_getTypeEncoding(profile_method)
                      : "missing");
    return ready;
}

static bool read_exact(int descriptor, void *buffer, size_t size,
                       off_t offset) {
    uint8_t *cursor = buffer;
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t amount = pread(descriptor, cursor, remaining, offset);
        if (amount <= 0) return false;
        cursor += amount;
        remaining -= (size_t)amount;
        offset += amount;
    }
    return true;
}

static unsigned int hash_rank(uint8_t hash_type) {
    switch (hash_type) {
    case 1: return 1;
    case 3: return 2;
    case 2: return 3;
    case 4: return 4;
    default: return 0;
    }
}

static bool code_directory_hash(const codex_code_directory_t *directory,
                                size_t available,
                                uint8_t output[CODEX_CDHASH_LENGTH]) {
    if (available < sizeof(*directory) ||
        ntohl(directory->magic) != CODEX_CSMAGIC_CODEDIRECTORY) {
        return false;
    }
    size_t length = ntohl(directory->length);
    if (length < sizeof(*directory) || length > available) return false;

    uint8_t digest[CC_SHA512_DIGEST_LENGTH] = {0};
    switch (directory->hash_type) {
    case 1:
        CC_SHA1(directory, (CC_LONG)length, digest);
        break;
    case 2:
    case 3:
        CC_SHA256(directory, (CC_LONG)length, digest);
        break;
    case 4:
        CC_SHA384(directory, (CC_LONG)length, digest);
        break;
    default:
        return false;
    }
    memcpy(output, digest, CODEX_CDHASH_LENGTH);
    return true;
}

static NSData *cdhash_for_file(NSString *path, NSDictionary *options) {
    NSNumber *offset_value = options[@"UniversalFileOffset"];
    uint64_t slice_offset = [offset_value isKindOfClass:NSNumber.class]
                                ? offset_value.unsignedLongLongValue
                                : 0;
    int descriptor = open(path.fileSystemRepresentation,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return nil;

    struct stat status = {0};
    struct mach_header_64 header = {0};
    NSData *result = nil;
    if (fstat(descriptor, &status) != 0 || slice_offset >= (uint64_t)status.st_size ||
        !read_exact(descriptor, &header, sizeof(header), (off_t)slice_offset) ||
        header.magic != MH_MAGIC_64 || header.ncmds == 0 ||
        header.ncmds > 4096U || header.sizeofcmds > 32U * 1024U * 1024U ||
        slice_offset + sizeof(header) + header.sizeofcmds >
            (uint64_t)status.st_size) {
        close(descriptor);
        return nil;
    }

    uint8_t *commands = malloc(header.sizeofcmds);
    if (commands == NULL ||
        !read_exact(descriptor, commands, header.sizeofcmds,
                    (off_t)(slice_offset + sizeof(header)))) {
        free(commands);
        close(descriptor);
        return nil;
    }

    uint32_t signature_offset = 0;
    uint32_t signature_size = 0;
    uint8_t *cursor = commands;
    uint8_t *end = commands + header.sizeofcmds;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) break;
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (uint32_t)(end - cursor)) break;
        if (command->cmd == LC_CODE_SIGNATURE &&
            command->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *signature =
                (const struct linkedit_data_command *)cursor;
            signature_offset = signature->dataoff;
            signature_size = signature->datasize;
            break;
        }
        cursor += command->cmdsize;
    }
    free(commands);

    uint64_t absolute_signature_offset = slice_offset + signature_offset;
    if (signature_size < sizeof(codex_superblob_t) ||
        signature_size > CODEX_MAX_SIGNATURE_SIZE ||
        absolute_signature_offset + signature_size >
            (uint64_t)status.st_size) {
        close(descriptor);
        return nil;
    }
    uint8_t *signature_data = malloc(signature_size);
    if (signature_data == NULL ||
        !read_exact(descriptor, signature_data, signature_size,
                    (off_t)absolute_signature_offset)) {
        free(signature_data);
        close(descriptor);
        return nil;
    }
    close(descriptor);

    const codex_superblob_t *superblob =
        (const codex_superblob_t *)signature_data;
    uint32_t superblob_length = ntohl(superblob->length);
    uint32_t count = ntohl(superblob->count);
    if (ntohl(superblob->magic) != CODEX_CSMAGIC_EMBEDDED_SIGNATURE ||
        superblob_length > signature_size || count > 64U ||
        sizeof(*superblob) + (size_t)count * sizeof(codex_blob_index_t) >
            superblob_length) {
        free(signature_data);
        return nil;
    }

    unsigned int best_rank = 0;
    uint8_t best_hash[CODEX_CDHASH_LENGTH] = {0};
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t type = ntohl(superblob->index[index].type);
        uint32_t offset = ntohl(superblob->index[index].offset);
        if (type != CODEX_CSSLOT_CODEDIRECTORY &&
            (type < CODEX_CSSLOT_ALTERNATE_CODEDIRECTORIES ||
             type >= CODEX_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            continue;
        }
        if (offset > superblob_length ||
            superblob_length - offset < sizeof(codex_code_directory_t)) {
            continue;
        }
        const codex_code_directory_t *directory =
            (const codex_code_directory_t *)(signature_data + offset);
        unsigned int rank = hash_rank(directory->hash_type);
        uint8_t candidate[CODEX_CDHASH_LENGTH] = {0};
        if (rank > best_rank &&
            code_directory_hash(directory, superblob_length - offset,
                                candidate)) {
            memcpy(best_hash, candidate, sizeof(best_hash));
            best_rank = rank;
        }
    }
    if (best_rank != 0) {
        result = [NSData dataWithBytes:best_hash length:sizeof(best_hash)];
    }
    free(signature_data);
    return result;
}

static bool secure_application_marker(NSString *path, bool broker_marker) {
    struct stat status = {0};
    if (lstat(path.fileSystemRepresentation, &status) != 0 ||
        !S_ISREG(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_nlink != 1 ||
        (broker_marker ? status.st_uid != 0
                       : (status.st_uid != 0 && status.st_uid != 501)) ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
    return broker_marker ? status.st_size > 0 && status.st_size <= 64 * 1024
                         : status.st_size == 0;
}

static bool managed_application_path(NSString *path) {
    if (![path isKindOfClass:NSString.class]) return false;
    NSString *standardized = path.stringByStandardizingPath;
    if ([standardized containsString:
            @"/procursus/Applications/TrollStoreLite.app/"] ||
        [standardized hasPrefix:@"/var/jb/Applications/TrollStoreLite.app/"]) {
        return true;
    }
    bool app_container =
        [standardized hasPrefix:@"/var/containers/Bundle/Application/"] ||
        [standardized hasPrefix:@"/private/var/containers/Bundle/Application/"];
    if (!app_container) return false;

    NSString *cursor = standardized.stringByDeletingLastPathComponent;
    for (unsigned int depth = 0; depth < 12U; ++depth) {
        NSString *trollStoreMarker =
            [cursor stringByAppendingPathComponent:@"_TrollStore"];
        NSString *trollStoreLiteMarker =
            [cursor stringByAppendingPathComponent:@"_TrollStoreLite"];
        NSString *brokerMarker = [cursor
            stringByAppendingPathComponent:@"_SBInjectManagedApp.plist"];
        if (secure_application_marker(trollStoreMarker, false) ||
            secure_application_marker(trollStoreLiteMarker, false) ||
            secure_application_marker(brokerMarker, true)) {
            return true;
        }
        NSString *parent = cursor.stringByDeletingLastPathComponent;
        if ([parent isEqualToString:cursor] ||
            !([parent hasPrefix:@"/var/containers/Bundle/Application"] ||
              [parent hasPrefix:@"/private/var/containers/Bundle/Application"])) {
            break;
        }
        cursor = parent;
    }
    return false;
}

static int hooked_validate(NSString *file, NSDictionary *options,
                           NSMutableDictionary **information) {
    int original_result = g_original_validate(file, options, information);
    if (original_result == 0 || !managed_application_path(file)) {
        return original_result;
    }

    NSMutableDictionary *mutable_information =
        information != NULL && *information != nil
            ? [*information mutableCopy]
            : [NSMutableDictionary dictionary];
    if (mutable_information[@"CdHash"] == nil) {
        NSData *cdhash = cdhash_for_file(file, options);
        if (cdhash == nil) {
            os_log_error(amfi_log(),
                         "scoped validation retained failure=%{public}d "
                         "path=%{public}@ reason=cdhash-unavailable",
                         original_result, file);
            return original_result;
        }
        mutable_information[@"CdHash"] = cdhash;
    }
    if (information != NULL) *information = mutable_information;
    os_log_with_type(amfi_log(), OS_LOG_TYPE_DEFAULT,
                     "scoped validation override original=%{public}d "
                     "path=%{public}@",
                     original_result, file);
    return 0;
}

static bool install_legacy_validation_hook(void) {
    void *libmis = dlopen("/usr/lib/libmis.dylib", RTLD_NOW | RTLD_LOCAL);
    if (libmis == NULL) return false;
    void *validate = dlsym(libmis, "MISValidateSignatureAndCopyInfo");
    if (validate == NULL) return false;
    g_original_validate = (mis_validate_signature_t)validate;
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    litehook_rebind_result_t result = litehook_rebind_symbol(
        header, validate, (void *)(uintptr_t)&hooked_validate);
    bool ready = result.matches > 0 && result.writes == result.matches;
    os_log_with_type(amfi_log(),
                     ready ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_ERROR,
                     "MIS hook ready=%{public}s matches=%{public}lu "
                     "writes=%{public}lu tpro=%{public}lu kr=%{public}d",
                     ready ? "true" : "false",
                     (unsigned long)result.matches,
                     (unsigned long)result.writes,
                     (unsigned long)result.tpro_writes,
                     result.first_error);
    return ready;
}

__attribute__((constructor)) static void initialize_amfid_hook(void) {
    if (!exact_candidate()) return;
    amfi_file_log("constructor pid=%d entered", getpid());
    os_log_with_type(amfi_log(), OS_LOG_TYPE_DEFAULT,
                     "resigned amfid hook entered pid=%{public}d", getpid());
    uint32_t code_signing_flags = 0;
    int status_error = 0;
    bool validation_ready = install_path_validator_hook();
    if (!validation_ready) {
        os_log_with_type(amfi_log(), OS_LOG_TYPE_DEFAULT,
                         "path-validator unavailable; trying legacy libmis");
        if (!wait_until_debugged(&code_signing_flags, &status_error)) {
            amfi_file_log(
                "constructor pid=%d jit=false flags=0x%08x error=%d",
                getpid(), code_signing_flags, status_error);
            write_failure_marker([NSString
                stringWithFormat:@"jit-status:flags=0x%08x,error=%d",
                                 code_signing_flags, status_error]);
            os_log_fault(
                amfi_log(),
                "resigned amfid was not debugged flags=0x%08x error=%d",
                code_signing_flags, status_error);
            return;
        }
        validation_ready = install_legacy_validation_hook();
    }
    if (!validation_ready) {
        write_failure_marker(@"validation-hook");
        os_log_fault(amfi_log(), "amfid validation import was not patched");
        return;
    }
    (void)unlink(CODEX_SBINJECT_AMFID_FAILURE_MARKER);
    int marker = open(CODEX_SBINJECT_AMFID_READY_MARKER,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0644);
    if (marker >= 0) {
        (void)fchown(marker, 0, 0);
        (void)fchmod(marker, 0644);
        (void)fsync(marker);
        close(marker);
    }
}
