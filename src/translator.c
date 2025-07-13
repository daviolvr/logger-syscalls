#define _GNU_SOURCE
#define _ATFILE_SOURCE

#include <stdio.h>
#include <string.h>
#include <fcntl.h>      // O_RDONLY, O_CREAT etc.
#include <sys/stat.h>   // STATX_* macros
#include <unistd.h>     // AT_FDCWD
#include <stddef.h>
#include "translator.h"
#include <sys/socket.h> // Para os macros NSG_*
#include <sys/ptrace.h>

// Traduz flags de abertura de arquivo (open) para uma string legível
void translate_flags_open(int flags, char *buf, size_t size) {
    buf[0] = '\0';

    // Caso especial para nenhuma flag (apenas leitura)
    if (flags == 0) {
        strncat(buf, "O_RDONLY", size - 1);
        return;
    }

    // Verifica cada flag possível e concatena ao buffer
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

    // Remove o último caractere '|' se existir
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}


// Traduz flags da chamada statx para uma string legível
void translate_flags_statx(int flags, char *buf, size_t size) {
    buf[0] = '\0';

    // Caso sem flags
    if (flags == 0) {
        strncat(buf, "0", size - 1);
        return;
    }

    // Flags condicionais do statx
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

    // Remove o último '|'
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}


// Traduz a máscara de campos solicitados do statx
void translate_mask_statx(unsigned int mask, char *buf, size_t size) {
    buf[0] = '\0';

    // Caso sem máscara
    if (mask == 0) {
        strncat(buf, "0", size - 1);
        return;
    }

    // Verifica cada bit da máscara possível
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

    // Remove o último '|'
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}


// Traduz um descritor de diretório para string
const char *translate_dirfd(long dirfd) {
#ifdef AT_FDCWD
    // Caso especial para o descritor "current working directory"
    if ((int)dirfd == AT_FDCWD) return "AT_FDCWD";
#endif
    // Para outros casos, retorna o número como string
    static char buf[32];
    snprintf(buf, sizeof(buf), "%ld", dirfd);
    return buf;
}

// Traduz flags do recvmsg para string legível
void translate_recvmsg_flags(int flags, char *buf, size_t size) {
    buf[0] = '\0';
    
    if (flags == 0) {
        strncat(buf, "0", size - 1);
        return;
    }

    if (flags & MSG_OOB) strncat(buf, "MSG_OOB|", size - strlen(buf) - 1);
    if (flags & MSG_PEEK) strncat(buf, "MSG_PEEK|", size - strlen(buf) - 1);
    if (flags & MSG_DONTROUTE) strncat(buf, "MSG_DONTROUTE|", size - strlen(buf) - 1);
    if (flags & MSG_CTRUNC) strncat(buf, "MSG_CTRUNC|", size - strlen(buf) - 1);
    if (flags & MSG_TRUNC) strncat(buf, "MSG_TRUNC|", size - strlen(buf) - 1);
    if (flags & MSG_WAITALL) strncat(buf, "MSG_WAITALL|", size - strlen(buf) - 1);
    
    // Remove o último '|' se existir
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}

// Traduz a estrutura msghdr para string legível
void translate_msghdr(pid_t pid, unsigned long addr, char *buf, size_t size) {
    buf[0] = '\0';
    
    if (addr == 0) {
        strncat(buf, "NULL", size - 1);
        return;
    }

    struct msghdr msg;
    if (ptrace(PTRACE_PEEKDATA, pid, addr, &msg) == -1) {
        strncat(buf, "(erro ao ler msghdr)", size - 1);
        return;
    }

    char flags_buf[128];
    translate_recvmsg_flags(msg.msg_flags, flags_buf, sizeof(flags_buf));
    
    snprintf(buf, size,
            "{msg_name=%p, msg_namelen=%u, msg_iov=%p, msg_iovlen=%lu, "
            "msg_control=%p, msg_controllen=%lu, msg_flags=%s}",
            msg.msg_name, msg.msg_namelen, msg.msg_iov, msg.msg_iovlen,
            msg.msg_control, msg.msg_controllen, flags_buf);
}
