#define _POSIX_C_SOURCE 199309L
#define MAX_BUF_DUMP 256

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "util.h"
#include <sys/ptrace.h>  
#include <sys/types.h>
#include <errno.h>     
#include <stdlib.h>

// Recebe um timespec e formata em string legível
void format_readable_timestamp(const struct timespec *ts, char *buffer, size_t size) {
    struct tm tempo_local;
    localtime_r(&ts->tv_sec, &tempo_local);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tempo_local);

    char nanos[16];
    snprintf(nanos, sizeof(nanos), ".%09ld", ts->tv_nsec);
    strncat(buffer, nanos, size - strlen(buffer) - 1);
}

// Função pra checar se o arquivo passado existe, retornando 1 se sim, 0 se não
int file_exist(const char *nome) {
    struct stat buffer;
    return (stat(nome, &buffer) == 0);
}

// Le a memoria de um processo a partir do espaço de endereçamento dele
char *read_process_memory(pid_t pid, unsigned long address, size_t size) {
    // Verifica se o tamanho é válido (entre 1 e 4096 bytes)
    if (size == 0 || size > 4096) {
        return NULL;
    }

    // Aloca buffer com tamanho solicitado + 1 para o null terminator
    char *buffer = malloc(size + 1); 
    if (!buffer) {
        return NULL;
    }

    // Lê a memória palavra por palavra (tamanho de long)
    for (size_t i = 0; i < size; i += sizeof(long)) {
        // Usa ptrace para ler uma palavra da memória do processo
        long word = ptrace(PTRACE_PEEKDATA, pid, address + i, NULL);
        if (errno != 0) {  // Verifica se houve erro na leitura
            free(buffer);
            return NULL;
        }

        // Calcula quantos bytes ainda faltam ler e quantos copiar nesta iteração
        size_t remaining_bytes = size - i;
        size_t bytes_to_copy = remaining_bytes > sizeof(long) ? sizeof(long) : remaining_bytes;
        
        // Copia os bytes lidos para o buffer
        memcpy(buffer + i, &word, bytes_to_copy);
    }

    // Adiciona null terminator no final do buffer
    buffer[size] = '\0'; 
    return buffer;
}

// Função para exibir ajuda
void show_help(void) {
    printf("\nUso: sudo ./build/syscall_monitor <PID> [OPÇÕES]\n\n");
    printf("Argumentos:\n");
    printf("  <PID>       ID do processo a ser monitorado (obrigatório)\n\n");
    printf("Opções:\n");
    printf("  -f          Monitora também processos filhos e threads\n");
    printf("  -h, --help  Mostra esta mensagem de ajuda\n\n");
    printf("Exemplos:\n");
    printf("  sudo ./build/syscall_monitor 1234       # Monitora apenas o processo 1234\n");
    printf("  sudo ./build/syscall_monitor 1234 -f    # Monitora 1234 e seus filhos/threads\n");
    printf("  sudo ./build/syscall_monitor --help     # Mostra esta ajuda\n\n");
    printf("Saída:\n");
    printf("  Os logs são salvos em outputs/syscalls.csv e exibidos no terminal.\n");
}
