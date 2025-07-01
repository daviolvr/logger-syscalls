#define _POSIX_C_SOURCE 199309L // Habilita clock_gettime() e outras funções POSIX

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>   // Para monitorar processos
#include <sys/wait.h>     // Para waitpid()
#include <sys/user.h>     // Para acessar registradores (struct user_regs_struct)
#include <unistd.h>       // Para funções do POSIX como close(), read(), etc
#include <errno.h>        // Para tratamento de erros do sistema
#include <time.h>         // Para timestamp com clock_gettime()
#include <seccomp.h>      // Para resolver número de syscall -> nome
#include <string.h>
#include <sys/stat.h>     // Para verificar existência de arquivos com stat()

/*  Lê o nome do processo alvo a partir de /proc/%d/comm,
usa fgets pra ler a string e remove o \n.
Se não conseguir abrir, define desconhecido como fallback
*/
void get_process_name(int pid, char *buffer, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid); // Caminho para o nome do processo

    FILE *file = fopen(path, "r");
    if (file) {
        fgets(buffer, size, file); // Lê o nome
        buffer[strcspn(buffer, "\n")] = 0; // Remove o '\n'
        fclose(file);
    } else {
        snprintf(buffer, size, "desconhecido");
    }
}

// Captura timestamp com precisão de nanosegundos
void get_timestamp(struct timespec* ts) {
    clock_gettime(CLOCK_REALTIME, ts); 
}

// Verifica se o arquivo existe usando stat()
int file_exist(const char *nome) {
    struct stat buffer;
    return (stat(nome, &buffer) == 0);
}

// Traduz o número da syscall para o nome em texto via libseccomp
const char* syscall_name(long syscall_number) {
    const char* name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, syscall_number); 
    if (name != NULL){
        return name;
    } else {
        return "syscall_desconhecida";
    }
}

// A main exige um argumento: o PID do processo a ser monitorado
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Comando correto: %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { // Anexa ao processo alvo, e imprime erro em caso de falha
        perror("Erro ao atacar com ptrace");
        return 1;
    }

    char nome_processo[256];
    get_process_name(pid, nome_processo, sizeof(nome_processo)); // Usa o nome  do processo como nome do CSV de saida

    char nome_arquivo[300];
    snprintf(nome_arquivo, sizeof(nome_arquivo), "../outputs/%s.csv", nome_processo);

    
    if (file_exist(nome_arquivo)) {
        time_t agora = time(NULL); 
        snprintf(nome_arquivo, sizeof(nome_arquivo), "../outputs/%s_%ld.csv", nome_processo, agora);
    }

    FILE *csv = fopen(nome_arquivo, "w"); // ABre o CSV para escrita, e imprime erro em caso de falha
    if (!csv) {
        perror("Erro ao abrir o arquivo CSV");
        return 1;
    } else {
        printf("Arquivo criado: %s\n", nome_arquivo);
    }
    
    
    printf("Atacando o processo: %s (PID: %d)\n", nome_processo, pid);

    int status;
    waitpid(pid, &status, 0); // Aguarda o processo parar e prepara para interceptar syscalls

    ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 

    while (1) {
        waitpid(pid, &status, 0); // Espera a próxima parada com waitpid
        if (WIFEXITED(status)) break; // Se o processo terminou, sai do laço

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs); // Usa PTRACE_GETREGS para ler os registradores da syscall

        // Extrai número da syscall e os argumentos (rdi, rsi, rdx)
        long syscall = regs.orig_rax; 
        printf("Nome da chamada: %s - args: (arg1=%lld, arg2=%lld, arg3=%lld) ",
            syscall_name(syscall), regs.rdi, regs.rsi, regs.rdx);
        
        fprintf(csv, "Nome da chamada: %s - args: (arg1=%lld, arg2=%lld, arg3=%lld) ", // Escreve no csv
            syscall_name(syscall), regs.rdi, regs.rsi, regs.rdx);


        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); // Executa a syscall

        waitpid(pid, &status, 0); // Espera o retorno
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        printf("- retorno: %lld ", regs.rax); // Lê o valor de retorno
        fprintf(csv, "- retorno: %lld ", regs.rax);
        
        struct timespec ts;
        get_timestamp(&ts);  
        
        // Registra timestamp e PID
        printf("- TimeStamp: [%ld.%09ld] - PID %d\n", ts.tv_sec, ts.tv_nsec, pid); 
        fprintf(csv, "- TimeStamp: [%ld.%09ld] - PID %d\n", ts.tv_sec, ts.tv_nsec, pid);

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL); // Desanexa o processo e finaliza
    printf("Saindo de %d\n", pid);
    return 0;
}
