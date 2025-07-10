#define _POSIX_C_SOURCE 199309L

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "util.h"

// Recebe um timespec e formata em string legível
void format_readable_timestamp(const struct timespec *ts, char *buffer, size_t size) {
    struct tm tempo_local;
    localtime_r(&ts->tv_sec, &tempo_local);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tempo_local);

    char nanos[16];
    snprintf(nanos, sizeof(nanos), ".%09ld", ts->tv_nsec);
    strncat(buffer, nanos, size - strlen(buffer) - 1);
}

// Função pra chgecar se o arquivo passado existe, retornando 1 se sim, 0 se não
int file_exist(const char *nome) {
    struct stat buffer;
    return (stat(nome, &buffer) == 0);
}

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
