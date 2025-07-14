#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include "logger.h"
#include "processo.h"
#include "util.h"

int main(int argc, char *argv[]) {
    int monitorar_filhos = 0;
    int pid = 0;
    int help_requested = 0;
    
    // Processa todos os argumentos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            help_requested = 1;
        }
        else if (strcmp(argv[i], "-f") == 0) {
            monitorar_filhos = 1;
        }
        else if (pid == 0) { // Se ainda não encontramos o PID
            pid = atoi(argv[i]);
            if (pid <= 0) {
                fprintf(stderr, "Erro: PID deve ser um número positivo\n");
                return 1;
            }
        }
        else {
            fprintf(stderr, "Argumento inválido: %s\n", argv[i]);
            fprintf(stderr, "Uso: %s <PID> [-f] [-h|--help]\n", argv[0]);
            return 1;
        }
    }
    
    // Se for pedido de ajuda, mostra e sai
    if (help_requested) {
        show_help();
        return 0;
    }
    
    // Validação do PID
    if (pid == 0) {
        fprintf(stderr, "Erro: PID não especificado\n");
        fprintf(stderr, "Uso: %s <PID> [-f] [-h|--help]\n", argv[0]);
        return 1;
    }
    
    start_monitoring(pid, monitorar_filhos);
    return 0;
}