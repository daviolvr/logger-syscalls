#include <seccomp.h>
#include <stddef.h> // para o NULL
#include "syscall.h"

// Traduz número da syscall para nome usando a libseccomp
const char* syscall_name(long syscall_number) {
    const char* name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, syscall_number);
    return (name != NULL) ? name : "syscall_desconhecida";
}
