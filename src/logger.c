#define _POSIX_C_SOURCE 199309L 

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include "logger.h"
#include "processo.h"
#include "util.h"
#include "syscall.h"

// Inicia monitoramento de syscalls do processo com PID
void iniciar_monitoramento(int pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { // Anexa o tracer ao processo alvo, se falhar exibe erro e retorna
        perror("Erro ao atacar com ptrace");
        return;
    }

    // Obtém o nome do processo monitorado lendo /proc/[pid]/comm
    char nome_processo[256];
    get_process_name(pid, nome_processo, sizeof(nome_processo));

    // Define o arquivo CSV de saída
    const char *nome_arquivo = "outputs/syscalls.csv";
    int precisa_cabecalho = !file_exist(nome_arquivo); // Verifica se existe pra saber se precisa add cabeçalho

    // Abre o arquivo CSV para dar append
    FILE *csv = fopen(nome_arquivo, "a");
    if (!csv) {
        perror("Erro ao abrir o arquivo CSV");
        return;
    } else {
        printf("Arquivo criado: %s\n", nome_arquivo);
    }

    // Se o arquivo não existia antes, escreve o cabeçalho CSV
    if (precisa_cabecalho) {
        fprintf(csv, "Nome da chamada,rdi,rsi,rdx,r10,r8,r9,retorno,timestamp,PID\n");
        fflush(csv);
    }

    // Imprime no terminal o processo que será monitorado
    printf("Atacando o processo: %s (PID: %d)\n", nome_processo, pid);


    /* Espera o processo alvo parar (após o attach).
    Depois, pede para o processo prar sempre que uma syscall for chamada ou finalizada */
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);


    /*
    Espera o processo continuar e parar novamente no próximo evento de syscall.
    Se o processo finalizou, sai do loop
    */
    while (1) {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) break;

        // Lê os registradores do processo monitorado (que contém os argumentos da syscall)
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        // Obtém o número da syscall chamada (em orig_rax)
        long syscall = regs.orig_rax;
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

        waitpid(pid, &status, 0);         // Espera a syscall terminar
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs); // Lê novamente os registradores, agora para pegar o valor de retorno da syscall em rax

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts); // Obtém o timestamp atual com precisão de nanosegundos

        char timestamp_formatado[64];
        formatar_timestamp_legivel(ts, timestamp_formatado, sizeof(timestamp_formatado)); // Formata timestamp para string legível


        // Imprime no terminal os dados da syscall (nome, argumentos, valor de retorno, timestamp e PID)
        printf("%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
            syscall_name(syscall),
            regs.rdi, regs.rsi, regs.rdx,
            regs.r10, regs.r8, regs.r9,
            regs.rax,
            timestamp_formatado,
            pid
        );

        // Grava os mesmos dados impressos no terminal no arquivo CSV
        fprintf(csv, "%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
            syscall_name(syscall),
            regs.rdi, regs.rsi, regs.rdx,
            regs.r10, regs.r8, regs.r9,
            regs.rax,
            timestamp_formatado,
            pid
        );
        fflush(csv); // Garante que o buffer seja escrito no disco

        // Continua o monitoramento para a pŕoxima syscall
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }

    // Ao fim do processo, desanexa o tracer e imprime a mensagem
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("Saindo de %d\n", pid);
}
