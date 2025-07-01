#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <seccomp.h> // mto foda essa lib pedi pro gpt achar alguma que ja fizesse essa traducao do num pra nome pq se nao ia se a porra de sw case de 1k de linhas kk
#include <string.h>
#include <sys/stat.h>

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

void get_timestamp(struct timespec* ts) {
    clock_gettime(CLOCK_REALTIME, ts); 
}

int file_exist(const char *nome) {
    struct stat buffer;
    return (stat(nome, &buffer) == 0);
}

const char* syscall_name(long syscall_number) {
    const char* name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, syscall_number); 
    if (name != NULL){
        return name;
    }else {return "syscall_desconhecida"; }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("o comando eh: %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { 
        perror("Erro ao atacar com ptrace");
        return 1;
    }

    char nome_processo[256];
    get_process_name(pid, nome_processo, sizeof(nome_processo));

    char nome_arquivo[300];
    snprintf(nome_arquivo, sizeof(nome_arquivo), "../outputs/%s.csv", nome_processo);

    
    if (file_exist(nome_arquivo)) {
        time_t agora = time(NULL); 
        snprintf(nome_arquivo, sizeof(nome_arquivo), "../outputs/%s_%ld.csv", nome_processo, agora);
    }

    FILE *csv = fopen(nome_arquivo, "w");
    if (!csv) {
        perror("Erro ao abrir o arquivo CSV");
        return 1;
    } else {
        printf("Arquivo criado: %s\n", nome_arquivo);
    }
    
    
    printf("Atacando o processo: %s (PID: %d)\n", nome_processo, pid);

    int status;
    waitpid(pid, &status, 0); 

    ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 

    while (1) {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) break;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);


        long syscall = regs.orig_rax; 
        printf("Nome da chamada: %s - args: (arg1=%lld, arg2=%lld, arg3=%lld) ", 
            syscall_name(syscall), regs.rdi, regs.rsi, regs.rdx);

        fprintf(csv, "Nome da chamada: %s - args: (arg1=%lld, arg2=%lld, arg3=%lld) ", 
            syscall_name(syscall), regs.rdi, regs.rsi, regs.rdx);



        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        printf("- retorno: %lld ", regs.rax);
        fprintf(csv, "- retorno: %lld ", regs.rax);
        
        struct timespec ts;
        get_timestamp(&ts);  
        
        printf("- TimeStamp: [%ld.%09ld] - PID %d\n", ts.tv_sec, ts.tv_nsec, pid); 
        fprintf(csv, "- TimeStamp: [%ld.%09ld] - PID %d\n", ts.tv_sec, ts.tv_nsec, pid);

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL); 
    printf("Saindo de %d\n", pid);
    return 0;
}
