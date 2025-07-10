#define _GNU_SOURCE
#define _ATFILE_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>      // O_RDONLY, O_CREAT etc.
#include <sys/stat.h>   // STATX_* macros
#include <unistd.h>     // AT_FDCWD
#include <stddef.h>
#include "translator.h"

void traduzir_flags_open(int flags, char *buf, size_t size) {
    buf[0] = '\0';

    if (flags == 0) {
        strncat(buf, "O_RDONLY", size - 1);
        return;
    }

    if (flags & O_WRONLY)      strncat(buf, "O_WRONLY|",      size - strlen(buf) - 1);
    if (flags & O_RDWR)        strncat(buf, "O_RDWR|",        size - strlen(buf) - 1);
    if (flags & O_CREAT)       strncat(buf, "O_CREAT|",       size - strlen(buf) - 1);
    if (flags & O_EXCL)        strncat(buf, "O_EXCL|",        size - strlen(buf) - 1);
    if (flags & O_NOCTTY)      strncat(buf, "O_NOCTTY|",      size - strlen(buf) - 1);
    if (flags & O_TRUNC)       strncat(buf, "O_TRUNC|",       size - strlen(buf) - 1);
    if (flags & O_APPEND)      strncat(buf, "O_APPEND|",      size - strlen(buf) - 1);
    if (flags & O_NONBLOCK)    strncat(buf, "O_NONBLOCK|",    size - strlen(buf) - 1);
#ifdef O_CLOEXEC
    if (flags & O_CLOEXEC)     strncat(buf, "O_CLOEXEC|",     size - strlen(buf) - 1);
#endif
#ifdef O_DIRECTORY
    if (flags & O_DIRECTORY)   strncat(buf, "O_DIRECTORY|",   size - strlen(buf) - 1);
#endif
#ifdef O_NOFOLLOW
    if (flags & O_NOFOLLOW)    strncat(buf, "O_NOFOLLOW|",    size - strlen(buf) - 1);
#endif

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}

void traduzir_flags_statx(int flags, char *buf, size_t size) {
    buf[0] = '\0';

    if (flags == 0) {
        strncat(buf, "0", size - 1);
        return;
    }

#ifdef AT_EMPTY_PATH
    if (flags & AT_EMPTY_PATH)         strncat(buf, "AT_EMPTY_PATH|",        size - strlen(buf) - 1);
#endif
#ifdef AT_SYMLINK_NOFOLLOW
    if (flags & AT_SYMLINK_NOFOLLOW)   strncat(buf, "AT_SYMLINK_NOFOLLOW|",  size - strlen(buf) - 1);
#endif
#ifdef AT_NO_AUTOMOUNT
    if (flags & AT_NO_AUTOMOUNT)       strncat(buf, "AT_NO_AUTOMOUNT|",      size - strlen(buf) - 1);
#endif
#ifdef AT_STATX_SYNC_AS_STAT
    if (flags & AT_STATX_SYNC_AS_STAT) strncat(buf, "AT_STATX_SYNC_AS_STAT|",size - strlen(buf) - 1);
#endif
#ifdef AT_STATX_FORCE_SYNC
    if (flags & AT_STATX_FORCE_SYNC)   strncat(buf, "AT_STATX_FORCE_SYNC|",  size - strlen(buf) - 1);
#endif

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}

void traduzir_mask_statx(unsigned int mask, char *buf, size_t size) {
    buf[0] = '\0';

    if (mask == 0) {
        strncat(buf, "0", size - 1);
        return;
    }

    if (mask & STATX_TYPE)         strncat(buf, "STATX_TYPE|",     size - strlen(buf) - 1);
    if (mask & STATX_MODE)         strncat(buf, "STATX_MODE|",     size - strlen(buf) - 1);
    if (mask & STATX_NLINK)        strncat(buf, "STATX_NLINK|",    size - strlen(buf) - 1);
    if (mask & STATX_UID)          strncat(buf, "STATX_UID|",      size - strlen(buf) - 1);
    if (mask & STATX_GID)          strncat(buf, "STATX_GID|",      size - strlen(buf) - 1);
    if (mask & STATX_ATIME)        strncat(buf, "STATX_ATIME|",    size - strlen(buf) - 1);
    if (mask & STATX_MTIME)        strncat(buf, "STATX_MTIME|",    size - strlen(buf) - 1);
    if (mask & STATX_CTIME)        strncat(buf, "STATX_CTIME|",    size - strlen(buf) - 1);
    if (mask & STATX_INO)          strncat(buf, "STATX_INO|",      size - strlen(buf) - 1);
    if (mask & STATX_SIZE)         strncat(buf, "STATX_SIZE|",     size - strlen(buf) - 1);
    if (mask & STATX_BLOCKS)       strncat(buf, "STATX_BLOCKS|",   size - strlen(buf) - 1);
    if (mask & STATX_BASIC_STATS)  strncat(buf, "STATX_BASIC_STATS|", size - strlen(buf) - 1);
    if (mask & STATX_BTIME)        strncat(buf, "STATX_BTIME|",    size - strlen(buf) - 1);
    if (mask & STATX_ALL)          strncat(buf, "STATX_ALL|",      size - strlen(buf) - 1);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}

const char *traduzir_dirfd(long dirfd) {
#ifdef AT_FDCWD
    if ((int)dirfd == AT_FDCWD) return "AT_FDCWD";
#endif
    static char buf[32];
    snprintf(buf, sizeof(buf), "%ld", dirfd);
    return buf;
}
