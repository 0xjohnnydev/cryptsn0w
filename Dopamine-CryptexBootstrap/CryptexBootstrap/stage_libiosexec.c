#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void ie_endgrent(void) { endgrent(); }
void ie_endpwent(void) { endpwent(); }
struct group *ie_getgrgid(gid_t gid) { return getgrgid(gid); }
struct group *ie_getgrnam(const char *name) { return getgrnam(name); }

static bool stage_account_paths(char home[PATH_MAX], char shell[PATH_MAX]) {
    Dl_info image = {0};
    if (dladdr((const void *)&stage_account_paths, &image) == 0 ||
        image.dli_fname == NULL) {
        return false;
    }
    static const char library_suffix[] = "/usr/lib/libiosexec.1.dylib";
    size_t image_length = strlen(image.dli_fname);
    size_t suffix_length = strlen(library_suffix);
    if (image_length <= suffix_length ||
        strcmp(image.dli_fname + image_length - suffix_length,
               library_suffix) != 0) {
        return false;
    }
    int root_length = (int)(image_length - suffix_length);
    int home_length = snprintf(home, PATH_MAX, "%.*s/var/root", root_length,
                               image.dli_fname);
    int shell_length = snprintf(shell, PATH_MAX, "%.*s/usr/bin/zsh",
                                root_length, image.dli_fname);
    return home_length > 0 && home_length < PATH_MAX && shell_length > 0 &&
           shell_length < PATH_MAX;
}

static struct passwd *stage_passwd(struct passwd *account) {
    static struct passwd root;
    static char home[PATH_MAX];
    static char shell[PATH_MAX];
    if (account == NULL || account->pw_uid != 0) return account;
    if (!stage_account_paths(home, shell)) return account;
    root = *account;
    root.pw_dir = home;
    root.pw_shell = shell;
    return &root;
}

struct passwd *ie_getpwent(void) { return stage_passwd(getpwent()); }
struct passwd *ie_getpwnam(const char *name) {
    return stage_passwd(getpwnam(name));
}
struct passwd *ie_getpwuid(uid_t uid) {
    return stage_passwd(getpwuid(uid));
}
void ie_setpwent(void) { setpwent(); }
char *ie_group_from_gid(gid_t gid, int nouser) {
    return group_from_gid(gid, nouser);
}
char *ie_user_from_uid(uid_t uid, int nouser) {
    return user_from_uid(uid, nouser);
}

int ie_execv(const char *path, char *const arguments[]) {
    return execv(path, arguments);
}

int ie_execve(const char *path, char *const arguments[],
              char *const environment[]) {
    return execve(path, arguments, environment);
}

static char **arguments_from_varargs(const char *first, va_list values) {
    va_list count_values;
    va_copy(count_values, values);
    size_t count = 1;
    while (va_arg(count_values, const char *) != NULL) ++count;
    va_end(count_values);

    char **arguments = calloc(count + 1U, sizeof(*arguments));
    if (arguments == NULL) return NULL;
    arguments[0] = (char *)first;
    for (size_t index = 1; index < count; ++index) {
        arguments[index] = va_arg(values, char *);
    }
    (void)va_arg(values, char *);
    return arguments;
}

int ie_execl(const char *path, const char *first, ...) {
    va_list values;
    va_start(values, first);
    char **arguments = arguments_from_varargs(first, values);
    va_end(values);
    if (arguments == NULL) return -1;
    int result = execv(path, arguments);
    int saved_errno = errno;
    free(arguments);
    errno = saved_errno;
    return result;
}

int ie_execlp(const char *file, const char *first, ...) {
    va_list values;
    va_start(values, first);
    char **arguments = arguments_from_varargs(first, values);
    va_end(values);
    if (arguments == NULL) return -1;
    int result = execvp(file, arguments);
    int saved_errno = errno;
    free(arguments);
    errno = saved_errno;
    return result;
}
