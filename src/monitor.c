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

// Gera timestamp com formato legível
void formatar_timestamp_legivel(struct timespec ts, char *buffer, size_t size) {
    struct tm tempo_local;
    localtime_r(&ts.tv_sec, &tempo_local); // Converte pra horário local

    // Escreve a data e hora base (até os segundos)
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tempo_local);

    // Adiciona os nanosegundos
    char nanos[16];
    snprintf(nanos, sizeof(nanos), ".%09ld", ts.tv_nsec);
    strncat(buffer, nanos, size - strlen(buffer) - 1);
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
    get_process_name(pid, nome_processo, sizeof(nome_processo));

    // CSV para análise posterior
    const char *nome_arquivo = "outputs/syscalls.csv";
    int precisa_cabecalho = !file_exist(nome_arquivo);


    FILE *csv = fopen(nome_arquivo, "a"); // ABre o CSV para escrita, e imprime erro em caso de falha
    if (!csv) {
        perror("Erro ao abrir o arquivo CSV");
        return 1;
    } else {
        printf("Arquivo criado: %s\n", nome_arquivo);
    }

    // Escreve cabeçalho do CSV (apenas se ainda não tiver)
    if (precisa_cabecalho) {
        fprintf(csv, "Nome da chamada,rdi,rsi,rdx,r10,r8,r9,retorno,timestamp,PID\n");
        fflush(csv);
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

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); // Executa a syscall

        waitpid(pid, &status, 0); // Espera o retorno
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        
        char timestamp_formatado[64];
        formatar_timestamp_legivel(ts, timestamp_formatado, sizeof(timestamp_formatado));
        
        // Exibir no terminal
        printf("%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
            syscall_name(syscall),
            regs.rdi,
            regs.rsi,
            regs.rdx,
            regs.r10,
            regs.r8,
            regs.r9,
            regs.rax,
            timestamp_formatado,
            pid
        );


        // Escreve no csv
        fprintf(csv, "%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
            syscall_name(syscall),
            regs.rdi,
            regs.rsi,
            regs.rdx,
            regs.r10,
            regs.r8,
            regs.r9,
            regs.rax,
            timestamp_formatado,
            pid
        );
        fflush(csv); // Garantir escrita de cada linha em tempo real


        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL); // Desanexa o processo e finaliza
    printf("Saindo de %d\n", pid);
    return 0;
}
