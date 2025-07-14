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
#include <poll.h>       // Para POLLIN, POLLOUT, etc
#include <sys/uio.h>    // Para struct iovec
#include <linux/futex.h> // Para FUTEX_* flags
#include <stdlib.h>
#include "util.h"

// Função auxiliar para formatar tamanhos em bytes
static void format_size(unsigned long size, char *buf, size_t buf_size) {
    snprintf(buf, buf_size, "%lu", size);
}

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

    // Usa read_process_memory para ler a estrutura msghdr
    char *data = read_process_memory(pid, addr, sizeof(struct msghdr));
    if (!data) {
        strncat(buf, "(erro ao ler msghdr)", size - 1);
        return;
    }
    
    struct msghdr msg;
    memcpy(&msg, data, sizeof(struct msghdr));
    free(data);

    char flags_buf[128];
    translate_recvmsg_flags(msg.msg_flags, flags_buf, sizeof(flags_buf));
    
    char namelen_buf[32], controllen_buf[32], iovlen_buf[32];
    format_size(msg.msg_namelen, namelen_buf, sizeof(namelen_buf));
    format_size(msg.msg_controllen, controllen_buf, sizeof(controllen_buf));
    format_size(msg.msg_iovlen, iovlen_buf, sizeof(iovlen_buf));
    
    // Traduz msg_iov
    char iov_buf[1024];
    translate_iovec(pid, (unsigned long)msg.msg_iov, msg.msg_iovlen, iov_buf, sizeof(iov_buf));
    
    snprintf(buf, size,
            "{msg_name=%p, msg_namelen=%s, msg_iov=%s, msg_iovlen=%s%s%s%s%s, msg_flags=%s}",
            msg.msg_name, namelen_buf, iov_buf, iovlen_buf,
            msg.msg_control ? ", msg_control=" : "",
            msg.msg_control ? (msg.msg_controllen > 0 ? "" : "0") : "",
            msg.msg_control ? (msg.msg_controllen > 0 ? controllen_buf : "") : "",
            msg.msg_flags ? ", " : "",
            flags_buf);
}

// Traduz a operação futex para string legível
void translate_futex_op(int op, char *buf, size_t size) {
    buf[0] = '\0';
    
    // Flags de operação
    if (op & FUTEX_PRIVATE_FLAG) strncat(buf, "FUTEX_PRIVATE_FLAG|", size - strlen(buf) - 1);
    if (op & FUTEX_CLOCK_REALTIME) strncat(buf, "FUTEX_CLOCK_REALTIME|", size - strlen(buf) - 1);
    
    // Operação base
    int base_op = op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    
    switch (base_op) {
        case FUTEX_WAIT: strncat(buf, "FUTEX_WAIT", size - strlen(buf) - 1); break;
        case FUTEX_WAKE: strncat(buf, "FUTEX_WAKE", size - strlen(buf) - 1); break;
        case FUTEX_FD: strncat(buf, "FUTEX_FD", size - strlen(buf) - 1); break;
        case FUTEX_REQUEUE: strncat(buf, "FUTEX_REQUEUE", size - strlen(buf) - 1); break;
        case FUTEX_CMP_REQUEUE: strncat(buf, "FUTEX_CMP_REQUEUE", size - strlen(buf) - 1); break;
        case FUTEX_WAKE_OP: strncat(buf, "FUTEX_WAKE_OP", size - strlen(buf) - 1); break;
        case FUTEX_LOCK_PI: strncat(buf, "FUTEX_LOCK_PI", size - strlen(buf) - 1); break;
        case FUTEX_UNLOCK_PI: strncat(buf, "FUTEX_UNLOCK_PI", size - strlen(buf) - 1); break;
        case FUTEX_TRYLOCK_PI: strncat(buf, "FUTEX_TRYLOCK_PI", size - strlen(buf) - 1); break;
        case FUTEX_WAIT_BITSET: strncat(buf, "FUTEX_WAIT_BITSET", size - strlen(buf) - 1); break;
        case FUTEX_WAKE_BITSET: strncat(buf, "FUTEX_WAKE_BITSET", size - strlen(buf) - 1); break;
        default: {
            char num[16];
            snprintf(num, sizeof(num), "%d", op);
            strncat(buf, num, size - strlen(buf) - 1);
        }
    }
}

// Traduz os modos de acesso (access/faccessat)
void translate_access_mode(int mode, char *buf, size_t size) {
    buf[0] = '\0';
    
    if (mode == F_OK) {
        strncat(buf, "F_OK", size - 1);
        return;
    }

    if (mode & R_OK) strncat(buf, "R_OK|", size - strlen(buf) - 1);
    if (mode & W_OK) strncat(buf, "W_OK|", size - strlen(buf) - 1);
    if (mode & X_OK) strncat(buf, "X_OK|", size - strlen(buf) - 1);
    
    // Remove o último '|' se existir
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '|') buf[len - 1] = '\0';
}

// Traduz a estrutura pollfd para string legível
void translate_pollfd(pid_t pid, unsigned long addr, nfds_t nfds, char *buf, size_t size) {
    buf[0] = '\0';
    
    if (addr == 0) {
        strncat(buf, "NULL", size - 1);
        return;
    }

    // Limita o número de estruturas a serem lidas para evitar buffer overflow
    if (nfds > 16) nfds = 16;
    
    strncat(buf, "[", size - strlen(buf) - 1);
    
    for (nfds_t i = 0; i < nfds; i++) {
        struct pollfd pfd;
        unsigned long current_addr = addr + i * sizeof(struct pollfd);
        
        // Usa read_process_memory para ler a estrutura pollfd corretamente
        char *data = read_process_memory(pid, current_addr, sizeof(struct pollfd));
        if (!data) {
            strncat(buf, "(erro ao ler pollfd)", size - strlen(buf) - 1);
            return;
        }
        memcpy(&pfd, data, sizeof(struct pollfd));
        free(data);

        char events_buf[64];
        char revents_buf[64];
        
        // Traduz eventos
        events_buf[0] = '\0';
        if (pfd.events & POLLIN) strncat(events_buf, "POLLIN|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (pfd.events & POLLPRI) strncat(events_buf, "POLLPRI|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (pfd.events & POLLOUT) strncat(events_buf, "POLLOUT|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (pfd.events & POLLERR) strncat(events_buf, "POLLERR|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (pfd.events & POLLHUP) strncat(events_buf, "POLLHUP|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (pfd.events & POLLNVAL) strncat(events_buf, "POLLNVAL|", sizeof(events_buf) - strlen(events_buf) - 1);
        if (events_buf[0] == '\0') strncat(events_buf, "0", sizeof(events_buf) - strlen(events_buf) - 1);
        else events_buf[strlen(events_buf)-1] = '\0'; // Remove último '|'
        
        // Traduz revents (mesmos flags que events)
        revents_buf[0] = '\0';
        if (pfd.revents & POLLIN) strncat(revents_buf, "POLLIN|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (pfd.revents & POLLPRI) strncat(revents_buf, "POLLPRI|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (pfd.revents & POLLOUT) strncat(revents_buf, "POLLOUT|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (pfd.revents & POLLERR) strncat(revents_buf, "POLLERR|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (pfd.revents & POLLHUP) strncat(revents_buf, "POLLHUP|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (pfd.revents & POLLNVAL) strncat(revents_buf, "POLLNVAL|", sizeof(revents_buf) - strlen(revents_buf) - 1);
        if (revents_buf[0] == '\0') strncat(revents_buf, "0", sizeof(revents_buf) - strlen(revents_buf) - 1);
        else revents_buf[strlen(revents_buf)-1] = '\0'; // Remove último '|'
        
        char entry[256];
        snprintf(entry, sizeof(entry), "{fd=%d, events=%s, revents=%s}", 
                pfd.fd, events_buf, revents_buf);
                
        strncat(buf, entry, size - strlen(buf) - 1);
        
        if (i < nfds - 1) strncat(buf, ", ", size - strlen(buf) - 1);
    }
    
    strncat(buf, "]", size - strlen(buf) - 1);
}

// Traduz a estrutura iovec para string legível
void translate_iovec(pid_t pid, unsigned long addr, int iovcnt, char *buf, size_t size) {
    buf[0] = '\0';
    
    if (addr == 0) {
        strncat(buf, "NULL", size - 1);
        return;
    }

    if (iovcnt > 16) iovcnt = 16;
    
    strncat(buf, "[", size - strlen(buf) - 1);
    
    for (int i = 0; i < iovcnt; i++) {
        struct iovec iov;
        unsigned long current_addr = addr + i * sizeof(struct iovec);
        
        // Usa read_process_memory para ler a estrutura iovec
        char *data = read_process_memory(pid, current_addr, sizeof(struct iovec));
        if (!data) {
            strncat(buf, "(erro ao ler iovec)", size - strlen(buf) - 1);
            return;
        }
        memcpy(&iov, data, sizeof(struct iovec));
        free(data);

        char size_buf[32];
        format_size(iov.iov_len, size_buf, sizeof(size_buf));
        
        char *content = NULL;
        if (iov.iov_len > 0 && iov.iov_len <= 1024) {
            content = read_process_memory(pid, (unsigned long)iov.iov_base, iov.iov_len);
        }
        
        char entry[512];
        snprintf(entry, sizeof(entry), "{iov_base=%p, iov_len=%s%s%s}", 
                (void*)iov.iov_base, size_buf,
                content ? ", content=\"" : "",
                content ? content : "");
                
        strncat(buf, entry, size - strlen(buf) - 1);
        
        if (content) free(content);
        if (i < iovcnt - 1) strncat(buf, ", ", size - strlen(buf) - 1);
    }
    
    strncat(buf, "]", size - strlen(buf) - 1);
}
