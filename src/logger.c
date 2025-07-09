/* 
Define _GNU_SOURCE para habilitar extensões GNU, necessárias para algumas funções
Inclui todos os headers necessários
 */
#define _GNU_SOURCE
#include <stdio.h>      // Para entrada/saída
#include <stdlib.h>     // Para funções padrão
#include <sys/ptrace.h> // Para ptrace - monitoramento de processos
#include <sys/wait.h>   // Para waitpid - esperar por processos
#include <sys/user.h>   // Para user_regs_struct - registradores do usuário
#include <errno.h>      // Para tratamento de erros
#include <time.h>       // Para manipulação de tempo
#include <string.h>     // Para manipulação de strings
#include <signal.h>     // Para tratamento de sinais
#include <unistd.h>     // Para chamadas POSIX (fork, sleep, etc)
#include <sys/prctl.h>  // Para prctl - operações de controle de processo
#include <dirent.h>     // Para leitura de diretórios
#include <limits.h>     // Para constantes como PATH_MAX
#include <stdatomic.h>  // Para operações atômicas (thread-safe)
#include <sys/types.h>  // Para tipos de dados como pid_t
#include <sys/stat.h>   // Para operações com arquivos
#include <fcntl.h>      // Para operações com arquivos
#include "logger.h"     // Headers personalizados
#include "util.h"
#include "syscall.h"

// Define o número máximo de processos filhos que podem ser monitorados
#define MAX_CHILDREN 1024

/* 
Variáveis globais:
- csv_file: ponteiro para o arquivo CSV de saída
- should_stop: flag atômica para controle de parada
- monitored_pids: array de PIDs sendo monitorados
- num_monitored: contador de PIDs monitorados
*/
static FILE *csv_file = NULL;
static atomic_int should_stop = 0;
static int monitored_pids[MAX_CHILDREN];
static int num_monitored = 0;

/*
Trata sinais SIGINT (Ctrl+C) e SIGTERM para parada graciosa
sig: número do sinal recebido (não utilizado)
 */
void signal_handler(int sig) {
    (void)sig; // Evita warning de variável não usada
    atomic_store(&should_stop, 1); // Sinaliza para parar o monitoramento
}

/*
Imprime informações da syscall no terminal e grava no arquivo CSV
syscall_num: número da syscall
regs: registradores contendo argumentos e retorno
timestamp: string com timestamp formatado
pid: PID do processo que fez a syscall
*/
void print_syscall_info(long syscall_num, struct user_regs_struct regs,
                       const char* timestamp, int pid) {
    // Imprime no terminal
    printf("%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
           syscall_name(syscall_num),  // Nome da syscall
           regs.rdi, regs.rsi, regs.rdx,  // Argumentos 1-3
           regs.r10, regs.r8, regs.r9,    // Argumentos 4-6
           (unsigned long long)regs.rax,  // Valor de retorno
           timestamp,                     // Quando ocorreu
           pid);                          // PID do processo

    // Grava no arquivo CSV (se aberto)
    if (csv_file) {
        fprintf(csv_file, "%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%d\n",
               syscall_name(syscall_num),
               regs.rdi, regs.rsi, regs.rdx,
               regs.r10, regs.r8, regs.r9,
               (unsigned long long)regs.rax,
               timestamp,
               pid);
        fflush(csv_file); // Garante que os dados são escritos imediatamente
    }
}

/*
Adiciona um PID à lista de processos monitorados, evitando duplicatas
pid: PID do processo a ser adicionado
*/
void add_pid(int pid) {
    // Verifica se há espaço no array
    if (num_monitored >= MAX_CHILDREN) return;
    
    // Verifica se o PID já está sendo monitorado
    for (int i = 0; i < num_monitored; i++) {
        if (monitored_pids[i] == pid) return;
    }
    
    // Adiciona o PID e incrementa o contador
    monitored_pids[num_monitored++] = pid;
    printf("Monitorando PID: %d\n", pid); // Log informativo
}

/*
Função: find_all_children
Encontra todos os processos filhos e threads de um processo pai
parent_pid: PID do processo pai
*/
void find_all_children(int parent_pid) {
    // Primeiro procura por threads (dentro de /proc/[pid]/task)
    char task_path[PATH_MAX];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", parent_pid);
    
    DIR *task_dir = opendir(task_path);
    if (task_dir) {
        struct dirent *task_entry;
        while ((task_entry = readdir(task_dir)) != NULL) {
            if (task_entry->d_type != DT_DIR) continue; // Ignora o que não for diretório
            int tid = atoi(task_entry->d_name);
            if (tid <= 0) continue; // Ignora entradas inválidas
            
            add_pid(tid); // Adiciona o TID (Thread ID)
        }
        closedir(task_dir);
    }

    // Depois procura por processos filhos (em /proc)
    DIR *proc_dir;
    struct dirent *proc_entry;
    char proc_path[PATH_MAX];
    char buf[512];
    
    if (!(proc_dir = opendir("/proc"))) return; // Abre /proc
    
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_type != DT_DIR) continue; // Ignora não-diretórios
        
        int pid = atoi(proc_entry->d_name);
        if (pid <= 0) continue; // Ignora entradas inválidas
        
        // Lê o arquivo stat do processo para obter o PPID (Parent PID)
        snprintf(proc_path, sizeof(proc_path), "/proc/%s/stat", proc_entry->d_name);
        FILE *fp = fopen(proc_path, "r");
        if (!fp) continue;
        
        if (fgets(buf, sizeof(buf), fp)) {
            int ppid;
            sscanf(buf, "%*d %*s %*c %d", &ppid); // Extrai o PPID
            if (ppid == parent_pid) {
                add_pid(pid); // Adiciona se for filho direto
                find_all_children(pid); // Busca recursiva para netos
            }
        }
        fclose(fp);
    }
    closedir(proc_dir);
}

/*
Tenta anexar a um processo com ptrace, com múltiplas tentativas
pid: PID do processo a ser anexado
Retorna: 0 em sucesso, -1 em falha
*/
int attach_to_process(int pid) {
    // Configura para permitir ptrace de qualquer processo
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == -1) {
        perror("prctl falhou");
    }

    // Tenta anexar 3 vezes com pequeno delay entre tentativas
    for (int attempt = 0; attempt < 3; attempt++) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0) {
            return 0; // Sucesso
        }
        usleep(100000); // Espera 100ms entre tentativas
    }
    
    // Se falhar após 3 tentativas, loga o erro
    fprintf(stderr, "Falha ao anexar ao PID %d: %s\n", pid, strerror(errno));
    return -1;
}

/*
Monitora um processo específico, capturando suas syscalls
pid: PID do processo a ser monitorado
*/
void monitor_process(int pid) {
    // Tenta anexar ao processo
    if (attach_to_process(pid) != 0) {
        return; // Falha ao anexar
    }

    // Espera o processo parar
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "PID %d não parou corretamente\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    /* Configura opções de ptrace:
    - TRACESYSGOOD: melhora identificação de syscalls
    - TRACEFORK/VFORK/CLONE: captura criação de novos processos
    - TRACEEXEC: captura execução de novos programas
    - TRACEEXIT: captura término do processo
     */
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, 
              PTRACE_O_TRACESYSGOOD |
              PTRACE_O_TRACEFORK |
              PTRACE_O_TRACEVFORK |
              PTRACE_O_TRACECLONE |
              PTRACE_O_TRACEEXEC |
              PTRACE_O_TRACEEXIT) == -1) {
        perror("ptrace setoptions falhou");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    // Começa a monitorar syscalls
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

    // Loop principal de monitoramento
    while (!atomic_load(&should_stop)) {
        // Espera por qualquer evento nos processos monitorados
        int wpid = waitpid(-1, &status, __WALL);
        if (wpid == -1) {
            if (errno == ECHILD) break; // Nenhum filho restante
            perror("waitpid falhou");
            continue;
        }

        // Verifica se é um evento de criação de novo processo
        if (WIFSTOPPED(status) && 
            ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
            (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
            (status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))) {
            
            // Obtém o PID do novo processo
            unsigned long new_pid;
            ptrace(PTRACE_GETEVENTMSG, wpid, NULL, &new_pid);
            add_pid(new_pid);
            
            // Tenta anexar ao novo processo
            if (attach_to_process(new_pid) == 0) {
                waitpid(new_pid, &status, 0);
                ptrace(PTRACE_SETOPTIONS, new_pid, NULL, 
                      PTRACE_O_TRACESYSGOOD |
                      PTRACE_O_TRACEFORK |
                      PTRACE_O_TRACEVFORK |
                      PTRACE_O_TRACECLONE);
                ptrace(PTRACE_SYSCALL, new_pid, NULL, NULL);
            }
            continue;
        }

        // Processo terminou
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("PID %d encerrado\n", wpid);
            continue;
        }

        // Verifica se é uma syscall
        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            // Obtém os registradores na entrada da syscall
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, wpid, NULL, &regs) == -1) {
                perror("ptrace getregs falhou");
                continue;
            }

            long syscall_num = regs.orig_rax;

            // Continua para a saída da syscall
            ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
            if (waitpid(wpid, &status, __WALL) == -1) {
                perror("waitpid após syscall falhou");
                continue;
            }

            if (WIFEXITED(status)) continue;

            // Obtém os registradores na saída da syscall (com retorno)
            if (ptrace(PTRACE_GETREGS, wpid, NULL, &regs) == -1) {
                perror("ptrace getregs na saída falhou");
                continue;
            }

            // Obtém timestamp atual
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            char timestamp[64];
            formatar_timestamp_legivel(ts, timestamp, sizeof(timestamp));

            // Imprime/grava as informações da syscall
            print_syscall_info(syscall_num, regs, timestamp, wpid);
        }

        // Continua a execução do processo
        ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
    }

    // Desanexa do processo antes de terminar
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/*
Função principal que inicia o monitoramento de um processo e seus filhos
parent_pid: PID do processo principal a ser monitorado
*/
void iniciar_monitoramento(int parent_pid) {
    // Configura tratadores para SIGINT (Ctrl+C) e SIGTERM
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Configura para permitir ptrace mesmo em processos protegidos
    if (prctl(PR_SET_DUMPABLE, 1) == -1) {
        perror("Falha ao configurar a flag dumpable");
    }

    // Cria diretório de saída se não existir
    mkdir("outputs", 0755);
    
    // Abre arquivo CSV para gravação (modo append)
    csv_file = fopen("outputs/syscalls.csv", "a");
    if (!csv_file) {
        perror("Falha ao abrir arquivo CSV");
        return;
    }

    // Escreve cabeçalho se for um arquivo novo
    if (ftell(csv_file) == 0) {
        fprintf(csv_file, "syscall,arg1,arg2,arg3,arg4,arg5,arg6,retorno,timestamp,pid\n");
        fflush(csv_file);
    }

    // Imprime cabeçalho no terminal também
    printf("syscall,arg1,arg2,arg3,arg4,arg5,arg6,retorno,timestamp,pid\n");

    // Adiciona o processo principal e busca todos os filhos/threads
    add_pid(parent_pid);
    find_all_children(parent_pid);

    // Para cada PID monitorado, cria um processo filho para monitorá-lo
    for (int i = 0; i < num_monitored; i++) {
        pid_t child_pid = fork();
        if (child_pid == 0) {
            // Processo filho - monitora o PID atribuído
            monitor_process(monitored_pids[i]);
            exit(0); // Termina após o monitoramento
        }
        else if (child_pid < 0) {
            perror("Falha no fork");
            continue;
        }
    }

    // Processo pai - espera todos os filhos terminarem
    int child_status;
    while (wait(&child_status) > 0 && !atomic_load(&should_stop)) {
        if (WIFEXITED(child_status) || WIFSIGNALED(child_status)) {
            continue;
        }
    }

    // Fecha o arquivo CSV se estiver aberto
    if (csv_file) {
        fclose(csv_file);
        csv_file = NULL;
    }
    
    // Mensagem final
    printf("\nMonitoramento completo\n");
}