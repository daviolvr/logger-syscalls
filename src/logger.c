#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h> 
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "logger.h"
#include "processo.h"
#include "util.h"
#include "syscall.h"
#include <asm-generic/unistd.h>
#include <asm/unistd_64.h>

void iniciar_monitoramento(int pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("Erro ao atacar com ptrace");
        return;
    }

    char nome_processo[256];
    get_process_name(pid, nome_processo, sizeof(nome_processo));

    const char *nome_arquivo = "outputs/syscalls.csv";
    
    // Abre o arquivo em modo "w" para recriá-lo do zero
    FILE *csv = fopen(nome_arquivo, "w");
    if (!csv) {
        perror("Erro ao abrir o arquivo CSV");
        return;
    } else {
        printf("Arquivo CSV reiniciado: %s\n", nome_arquivo);
    }

    printf("Monitorando o processo: %s (PID: %d)\n", nome_processo, pid);

    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

    int in_syscall = 0;
    struct user_regs_struct regs;
    long syscall_num = 0;

    while (1) {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        if (!in_syscall) {
            syscall_num = regs.orig_rax;
            in_syscall = 1;
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            char timestamp_formatado[64];
            formatar_timestamp_legivel(ts, timestamp_formatado, sizeof(timestamp_formatado));

            const char *nome = syscall_name(syscall_num);
            if (!nome) {
                in_syscall = 0;
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                continue;
            }

            // Buffer para formatar a mensagem uma só vez
            char log_line[1024];
            int len = 0;

            switch (syscall_num) {
                case __NR_read: {
                    char *buf = NULL;
                    if (regs.rax > 0 && regs.rax <= 1024) {
                        buf = read_process_memory(pid, regs.rsi, regs.rax);
                    }
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(fd=%llu, buf=%p%s%s, count=%llu) = %lld [%s] [PID: %d]\n",
                        nome, regs.rdi, (void*)regs.rsi,
                        buf ? ", content=\"" : "",
                        buf ? buf : "",
                        regs.rdx, regs.rax, timestamp_formatado, pid);
                    free(buf);
                    break;
                }

                case __NR_writev: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(fd=%llu, iov=%p, iovcnt=%llu) = %lld [%s] [PID: %d]\n",
                        nome, regs.rdi, (void*)regs.rsi, regs.rdx,
                        regs.rax, timestamp_formatado, pid);
                    break;
                }

                case __NR_poll: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(fds=%p, nfds=%llu, timeout=%lld) = %lld [%s] [PID: %d]\n",
                        nome, (void*)regs.rdi, regs.rsi, (long long)regs.rdx,
                        regs.rax, timestamp_formatado, pid);
                    break;
                }

                case __NR_statx: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(dirfd=%lld, pathname=%p, flags=%llu, mask=%llu, statxbuf=%p) = %lld [%s] [PID: %d]\n",
                        nome, (long long)regs.rdi, (void*)regs.rsi,
                        regs.rdx, regs.r10, (void*)regs.r8,
                        regs.rax, timestamp_formatado, pid);
                    break;
                }

                case __NR_close: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(fd=%llu) = %lld [%s] [PID: %d]\n",
                        nome, regs.rdi, regs.rax, timestamp_formatado, pid);
                    break;
                }

                case __NR_futex: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(uaddr=%p, op=%llu, val=%llu) = %lld [%s] [PID: %d]\n",
                        nome, (void*)regs.rdi, regs.rsi, regs.rdx,
                        regs.rax, timestamp_formatado, pid);
                    break;
                }

                case __NR_openat: {
                    char *path = read_process_memory(pid, regs.rsi, 256);
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(dirfd=%lld, pathname=\"%s\", flags=%llu, mode=%llu) = %lld [%s] [PID: %d]\n",
                        nome, (long long)regs.rdi, path ? path : "NULL",
                        regs.rdx, regs.r10, regs.rax, timestamp_formatado, pid);
                    free(path);
                    break;
                }

                case __NR_recvmsg: {
                    len = snprintf(log_line, sizeof(log_line),
                        "%s(sockfd=%llu, msg=%p, flags=%llu) = %lld [%s] [PID: %d]\n",
                        nome, regs.rdi, (void*)regs.rsi, regs.rdx,
                        regs.rax, timestamp_formatado, pid);
                    break;
                }

                default:
                    // Ignorar outras syscalls
                    in_syscall = 0;
                    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                    continue;
            }

            // Escreve no console e no CSV
            printf("%s", log_line);
            fprintf(csv, "%s", log_line);
            fflush(csv);

            in_syscall = 0;
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }

    fclose(csv);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("Monitoramento do PID %d finalizado\n", pid);
}