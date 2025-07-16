#include <stdio.h>
#include <string.h>
#include "processo.h"

/*
Lê o nome do processo diretamente do arquivo /proc/[pid/comm.
Se falhar, define como desconhecido
*/
void get_process_name(int pid, char *buffer, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid); 

    FILE *file = fopen(path, "r");
    if (file) {
        fgets(buffer, size, file);
        buffer[strcspn(buffer, "\n")] = 0; // Remove o \n final
        fclose(file);
    } else {
        snprintf(buffer, size, "desconhecido");
    }
}
