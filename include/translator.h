#ifndef TRANSLATOR_H
#define TRANSLATOR_H

#include <sys/types.h>
#include <stddef.h>
#include <poll.h>       // Para nfds_t
#include <sys/uio.h>    // Para struct iovec

void translate_flags_open(int flags, char *buf, size_t size);
void translate_flags_statx(int flags, char *buf, size_t size);
void translate_mask_statx(unsigned int mask, char *buf, size_t size);
const char *translate_dirfd(long dirfd);
void translate_recvmsg_flags(int flags, char *buf, size_t size);
void translate_msghdr(pid_t pid, unsigned long addr, char *buf, size_t size);
void translate_futex_op(int op, char *buf, size_t size);
void translate_access_mode(int mode, char *buf, size_t size);
void translate_pollfd(pid_t pid, unsigned long addr, nfds_t nfds, char *buf, size_t size);
void translate_iovec(pid_t pid, unsigned long addr, int iovcnt, char *buf, size_t size);

#endif