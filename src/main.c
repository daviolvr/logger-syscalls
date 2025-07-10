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
    
    // Verifica se há pedido de ajuda em qualquer argumento
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help();
            return 0;
        }
    }
    
    // Validação do número de argumentos
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Uso: %s <PID> [-f]\n", argv[0]);
        fprintf(stderr, "Use %s --help para mais informações\n", argv[0]);
        return 1;
    }
    
    // Verifica argumentos quando temos 3 (PID + opção)
    if (argc == 3) {
        if (strcmp(argv[2], "-f") != 0) {
            fprintf(stderr, "Argumento inválido: %s\n", argv[2]);
            fprintf(stderr, "Opções válidas: -f para monitorar filhos, -h/--help para ajuda\n");
            return 1;
        }
        monitorar_filhos = 1;
    }
    
    // Validação do PID
    pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Erro: PID deve ser um número positivo\n");
        return 1;
    }
    
    start_monitoring(pid, monitorar_filhos);
    return 0;
}