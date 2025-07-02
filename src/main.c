#include <stdio.h>
#include <stdlib.h>
#include "logger.h"
#include "processo.h"

// Recebe o PID para monitorar através da linha de comando e chama a função pra monitorar
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Comando correto: %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    iniciar_monitoramento(pid);
    return 0;
}
