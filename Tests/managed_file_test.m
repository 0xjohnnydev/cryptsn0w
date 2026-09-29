#import <Foundation/Foundation.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Only ownership is simulated. All file operations use a temporary directory.
static NSDictionary *host_attributes(NSDictionary *attributes) {
    assert([attributes[NSFileOwnerAccountID] isEqual:@0]);
    assert([attributes[NSFileGroupOwnerAccountID] isEqual:@0]);
    NSMutableDictionary *result = [attributes mutableCopy];
    result[NSFileOwnerAccountID] = @(geteuid());
    result[NSFileGroupOwnerAccountID] = @(getegid());
    return result;
}

@interface TestFileManager : NSFileManager
@end
@implementation TestFileManager
+ (instancetype)defaultManager { return [[self alloc] init]; }
- (BOOL)setAttributes:(NSDictionary *)attributes ofItemAtPath:(NSString *)path error:(NSError **)error {
    return [[NSFileManager defaultManager] setAttributes:host_attributes(attributes)
                                           ofItemAtPath:path error:error];
}
- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)parents
                  attributes:(NSDictionary *)attributes error:(NSError **)error {
    return [[NSFileManager defaultManager] createDirectoryAtPath:path
                                   withIntermediateDirectories:parents
                                                    attributes:host_attributes(attributes) error:error];
}
@end

static int host_lstat(const char *path, struct stat *info) {
    int result = lstat(path, info);
    if (result == 0) { info->st_uid = 0; info->st_gid = 0; }
    return result;
}
static int host_fchown(int descriptor, uid_t user, gid_t group) {
    assert(user == 0 && group == 0);
    return fchown(descriptor, geteuid(), getegid());
}
static bool failRename;
static unsigned renameCalls, failRenameOnCall;
static int test_rename(const char *from, const char *to) {
    if (failRename || ++renameCalls == failRenameOnCall) {
        errno = EACCES;
        return -1;
    }
    return rename(from, to);
}
static void log_message(const char *format, ...) { (void)format; }
#define NSFileManager TestFileManager
#define lstat host_lstat
#define fchown host_fchown
#define rename test_rename
// PRODUCTION_FUNCTIONS
#undef NSFileManager
#undef lstat
#undef fchown
#undef rename

int main(int argc, char **argv) {
    assert(argc == 2);
    @autoreleasepool {
        NSFileManager *manager = [NSFileManager defaultManager];
        NSString *root = [NSString stringWithUTF8String:argv[1]];
        NSString *source = [root stringByAppendingPathComponent:@"source"];
        NSString *directory = [root stringByAppendingPathComponent:@"installed"];
        NSString *name = @"dopamine-default.sources";
        NSString *destination = [directory stringByAppendingPathComponent:name];
        NSData *data = [@"Types: deb\n" dataUsingEncoding:NSUTF8StringEncoding];
        assert([data writeToFile:source atomically:YES]);
        bool updated = false;
        NSString *error = nil;
        assert(install_managed_apt_file(source, directory, name, 64 * 1024, 0644,
                                       "test", &updated, &error) && updated);
        assert(files_are_equal(source, destination));
        struct stat initial, current;
        assert(lstat(destination.fileSystemRepresentation, &initial) == 0);
        assert((initial.st_mode & 07777) == 0644);

        // Repeated checks must not replace an unchanged file.
        for (int iteration = 0; iteration < 30; ++iteration) {
            updated = true;
            assert(install_managed_apt_file(source, directory, name, 64 * 1024, 0644,
                                           "test", &updated, &error) && !updated);
        }
        assert(lstat(destination.fileSystemRepresentation, &current) == 0);
        assert(initial.st_ino == current.st_ino);
        assert(chmod(destination.fileSystemRepresentation, 0600) == 0);
        assert(install_managed_apt_file(source, directory, name, 64 * 1024, 0644,
                                       "test", &updated, &error) && !updated);
        assert(lstat(destination.fileSystemRepresentation, &current) == 0);
        assert((current.st_mode & 07777) == 0644);

        NSData *replacement = [@"Types: deb deb-src\n" dataUsingEncoding:NSUTF8StringEncoding];
        assert([replacement writeToFile:source atomically:YES]);
        failRename = true;
        assert(!install_managed_apt_file(source, directory, name, 64 * 1024, 0644,
                                        "test", &updated, &error) && !updated);
        assert([[NSData dataWithContentsOfFile:destination] isEqualToData:data]);
        assert([manager contentsOfDirectoryAtPath:directory error:nil].count == 1);
        failRename = false;
        assert(install_managed_apt_file(source, directory, name, 64 * 1024, 0644,
                                       "test", &updated, &error) && updated);
        assert(files_are_equal(source, destination));

        // Invalid inputs must preserve the installed file.
        for (NSUInteger size = 0; size <= 65537; size += 65537) {
            assert([[NSMutableData dataWithLength:size] writeToFile:source atomically:YES]);
            assert(!install_managed_apt_file(source, directory, name, 65536, 0644,
                                            "test", &updated, &error) && !updated);
            assert([[NSData dataWithContentsOfFile:destination] isEqualToData:replacement]);
        }
        assert([manager removeItemAtPath:source error:nil]);
        assert(!install_managed_apt_file(source, directory, name, 65536, 0644,
                                        "test", &updated, &error));
        assert(symlink(destination.fileSystemRepresentation, source.fileSystemRepresentation) == 0);
        assert(!install_managed_apt_file(source, directory, name, 65536, 0644,
                                        "test", &updated, &error));
        assert(unlink(source.fileSystemRepresentation) == 0);
        assert([data writeToFile:source atomically:YES]);
        assert(!install_managed_apt_file(source, directory, @"../escape", 65536, 0644,
                                        "test", &updated, &error));
        assert([manager removeItemAtPath:destination error:nil]);
        assert(symlink(source.fileSystemRepresentation, destination.fileSystemRepresentation) == 0);
        assert(!install_managed_apt_file(source, directory, name, 65536, 0644,
                                        "test", &updated, &error));
        assert([[NSData dataWithContentsOfFile:source] isEqualToData:data]);
        assert(unlink(destination.fileSystemRepresentation) == 0);
        assert(mkdir(destination.fileSystemRepresentation, 0700) == 0);
        assert(!install_managed_apt_file(source, directory, name, 65536, 0644,
                                        "test", &updated, &error));
        assert(rmdir(destination.fileSystemRepresentation) == 0);
        assert([[NSMutableData dataWithLength:65536] writeToFile:source atomically:YES]);
        assert(install_managed_apt_file(source, directory, name, 65536, 0644,
                                       "test", &updated, &error) && updated);
        assert(files_are_equal(source, destination));
        NSString *cache = [root stringByAppendingPathComponent:@"backups"];
        for (NSString *tool in @[@"launchctl", @"uiopen", @"uicache"]) {
            NSString *target = [directory stringByAppendingPathComponent:tool];
            assert([data writeToFile:target atomically:YES]);
            assert(chmod(target.fileSystemRepresentation, 0755) == 0);
            assert([replacement writeToFile:source atomically:YES]);
            NSString *backup = nil;
            assert(restore_packaged_tool(source, target, cache, &backup, &error));
            assert([backup.lastPathComponent hasPrefix:[tool stringByAppendingString:@"-backup-"]]);
            assert([[NSData dataWithContentsOfFile:backup] isEqualToData:data]);
            assert(files_are_equal(source, target));
            assert(lstat(target.fileSystemRepresentation, &current) == 0);
            assert((current.st_mode & 07777) == 0755);
            for (int iteration = 0; iteration < 10; ++iteration) {
                assert(restore_packaged_tool(source, target, cache, &backup, &error));
                assert(backup == nil);
            }
            assert([data writeToFile:source atomically:YES]);
            NSUInteger backupCount = [manager contentsOfDirectoryAtPath:cache error:nil].count;
            failRename = true;
            assert(!restore_packaged_tool(source, target, cache, &backup, &error));
            failRename = false;
            assert([[NSData dataWithContentsOfFile:target] isEqualToData:replacement]);
            assert([manager contentsOfDirectoryAtPath:cache error:nil].count == backupCount);
            renameCalls = 0;
            failRenameOnCall = 2;
            assert(!restore_packaged_tool(source, target, cache, &backup, &error));
            failRenameOnCall = 0;
            assert([[NSData dataWithContentsOfFile:target] isEqualToData:replacement]);
            assert([manager contentsOfDirectoryAtPath:cache error:nil].count == backupCount);
        }
        puts("File installation and backup tests passed, including 60 repeated checks.");
    }
    return 0;
}
