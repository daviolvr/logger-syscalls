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
#include "translator.h" 
#include <asm-generic/unistd.h>
#include <asm/unistd_64.h>
#include <poll.h>       // Para POLLIN, POLLOUT, etc
#include <sys/uio.h>    // Para struct iovec
#include <linux/futex.h> // Para FUTEX_* flags

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
Formata os detalhes de uma syscall com informações específicas para certas chamadas
*/
void format_syscall_details(long syscall_num, const struct user_regs_struct *regs, 
                          int pid, char *buffer, size_t size) {
    // Inicializa o buffer vazio
    buffer[0] = '\0';
    
    // Verifica o tipo de syscall
    switch (syscall_num) {
        // Trata syscall read()
        case __NR_read: {
            char *content = NULL;
            // Se tiver conteúdo válido (no caso, 1-1024 bytes), lê da memória
            if (regs->rax > 0 && regs->rax <= 1024) {
                content = read_process_memory(pid, regs->rsi, regs->rax);
            }
            
            // Formata os detalhes: fd, buffer, conteúdo e tamanho
            snprintf(buffer, size, "fd=%llu, buf=%p%s%s, count=%llu",
                    regs->rdi, (void*)regs->rsi,
                    content ? ", content=\"" : "",
                    content ? content : "",
                    regs->rdx);
            free(content);
            break;
        }

        // Trata syscalls writev() e readv()
        case __NR_writev:
        case __NR_readv: {
            char iov_buf[4096];
            // Traduz a estrutura iovec para string
            translate_iovec(pid, regs->rsi, regs->rdx, iov_buf, sizeof(iov_buf));
            
            // Formata: fd, iov e contagem
            snprintf(buffer, size, "fd=%llu, iov=%s, iovcnt=%llu",
                    regs->rdi, iov_buf, regs->rdx);
            break;
        }

        // Trata syscall poll()
        case __NR_poll: {
            char fds_buf[1024];
            // Traduz estrutura pollfd
            translate_pollfd(pid, regs->rdi, regs->rsi, fds_buf, sizeof(fds_buf));
            
            // Formata timeout (-1 = INFTIM)
            char timeout_str[32];
            if (regs->rdx == (unsigned long long)-1) {
                strcpy(timeout_str, "INFTIM");
            } else {
                snprintf(timeout_str, sizeof(timeout_str), "%lld", (long long)regs->rdx);
            }
            
            // Formata: descritores, contagem e timeout
            snprintf(buffer, size, "fds=%s, nfds=%llu, timeout=%s",
                    fds_buf, regs->rsi, timeout_str);
            break;
        }

        // Trata syscall statx()
        case __NR_statx: {
            char flags_buf[128];
            char mask_buf[128];
            char *path = NULL;
            
            // Traduz flags e máscara
            translate_flags_statx(regs->rdx, flags_buf, sizeof(flags_buf));
            translate_mask_statx(regs->r10, mask_buf, sizeof(mask_buf));
            
            // Lê pathname se não for vazio
            if (!(regs->rdx & AT_EMPTY_PATH)) {
                path = read_process_memory(pid, regs->rsi, 256);
            }
            
            // Formata: dirfd, pathname, flags, mask e buffer
            snprintf(buffer, size,
                    "dirfd=%s, pathname=%s, flags=%s, mask=%s, statxbuf=%p",
                    translate_dirfd(regs->rdi),
                    path ? path : (regs->rdx & AT_EMPTY_PATH) ? "(AT_EMPTY_PATH)" : "(NULL)",
                    flags_buf, mask_buf, (void*)regs->r8);
            
            if (path) free(path);
            break;
        }

        // Trata syscall close()
        case __NR_close: {
            // Formata apenas o file descriptor
            snprintf(buffer, size, "fd=%llu", regs->rdi);
            break;
        }

        // Trata syscall futex()
        case __NR_futex: {
            char op_buf[128];
            // Traduz operação futex
            translate_futex_op(regs->rsi, op_buf, sizeof(op_buf));
            
            // Formata: endereço, operação e valor
            snprintf(buffer, size, "uaddr=%p, op=%s, val=%llu",
                    (void*)regs->rdi, op_buf, regs->rdx);
            break;
        }

        // Trata syscall openat()
        case __NR_openat: {
            char *path = read_process_memory(pid, regs->rsi, 256);
            char flags_buf[256];
            
            // Traduz flags de abertura
            translate_flags_open(regs->rdx, flags_buf, sizeof(flags_buf));
            
            // Formata: dirfd, pathname, flags e modo
            snprintf(buffer, size,
                    "dirfd=%s, pathname=\"%s\", flags=%s, mode=%llo",
                    translate_dirfd(regs->rdi), path ? path : "NULL",
                    flags_buf, regs->r10);
            free(path);
            break;
        }

        // Trata syscall recvmsg()
        case __NR_recvmsg: {
            char flags_buf[128];
            char msghdr_buf[2048]; 
            
            // Traduz flags e estrutura msghdr
            translate_recvmsg_flags(regs->rdx, flags_buf, sizeof(flags_buf));
            translate_msghdr(pid, regs->rsi, msghdr_buf, sizeof(msghdr_buf));
            
            // Formata: socket fd, mensagem e flags
            snprintf(buffer, size,
                    "sockfd=%llu, msg=%s, flags=%s",
                    regs->rdi, msghdr_buf, flags_buf);
            break;
        }

        // Trata syscall newfstatat()
        case __NR_newfstatat: {
            char *path = NULL;
            char flags_buf[128] = "0";
            
            const char *dirfd_str = translate_dirfd(regs->rdi);
            
            // Lê pathname se não for NULL
            if (regs->rsi != 0) {
                path = read_process_memory(pid, regs->rsi, 256);
            }
            
            // Traduz flags
            translate_flags_statx(regs->r10, flags_buf, sizeof(flags_buf));
            
            // Formata: dirfd, pathname, buffer e flags
            snprintf(buffer, size,
                    "dirfd=%s, pathname=%s, buf=%p, flags=%s",
                    dirfd_str,
                    path ? path : regs->rsi == 0 ? "NULL" : "(erro)",
                    (void*)regs->rdx,
                    flags_buf);
            
            if (path) free(path);
            break;
        }

        // Trata syscall access()
        case __NR_access: {
            // Lê pathname
            char *path = read_process_memory(pid, regs->rdi, 256);
            char mode_buf[32];
            // Traduz modo de acesso
            translate_access_mode(regs->rsi, mode_buf, sizeof(mode_buf));
            
            // Formata: pathname e modo
            snprintf(buffer, size, "pathname=\"%s\", mode=%s",
                    path ? path : "NULL", mode_buf);
            
            if (path) free(path);
            break;
        }

        // Trata syscall write()
        case __NR_write: {
            char *content = NULL;
            // Se tiver conteúdo válido (1-1024 bytes), lê da memória
            if (regs->rdx > 0 && regs->rdx <= 1024) {  
                content = read_process_memory(pid, regs->rsi, regs->rdx);  
            }
            
            // Formata: fd, buffer, conteúdo e tamanho
            snprintf(buffer, size,
                    "fd=%llu, buf=%p%s%s, count=%llu",
                    regs->rdi,  
                    (void*)regs->rsi,
                    content ? ", content=\"" : "",
                    content ? content : "",
                    regs->rdx);
            free(content);
            break;
        }

        // Caso padrão para syscalls não tratadas especificamente
        default:
            snprintf(buffer, size,
                    "arg1=%llu, arg2=%llu, arg3=%llu, arg4=%llu, arg5=%llu, arg6=%llu",
                    regs->rdi, regs->rsi, regs->rdx,
                    regs->r10, regs->r8, regs->r9);
            break;
    }
}

// Função para gerar print no terminal e exportação para o CSV
void print_syscall_info(long syscall_num, const struct user_regs_struct *regs,
                       const char* timestamp, int pid) {
    long long retorno = (long long)regs->rax;
    const char *nome_syscall = syscall_name(syscall_num);
    
    char details[512];
    format_syscall_details(syscall_num, regs, pid, details, sizeof(details));

    // Saída para o terminal 
    printf("[PID %d] %s(%s) = %lld [%s]\n",
           pid, 
           nome_syscall,
           details,
           retorno,
           timestamp);

    // Saída para o CSV
    if (csv_file) {
        char arg1[256] = "", arg2[256] = "", arg3[256] = "", arg4[256] = "", arg5[256] = "", arg6[256] = "";
        
        switch (syscall_num) {
            case __NR_read:
                sscanf(details, "fd=%255[^,], buf=%255[^,], count=%255s", arg1, arg2, arg3);
                break;
            case __NR_writev:
            case __NR_readv: {
                // Encontra a posição da string "iov=" dentro dos details
                char *iov_start = strstr(details, "iov=");

                // Encontra a posição da string ", iovcnt=" dentro dos details
                char *iovcnt_start = strstr(details, ", iovcnt=");

                // Se ambas as strings forem encontradas
                if (iov_start && iovcnt_start) {
                    sscanf(details, "fd=%255[^,]", arg1); // Extrai o fd que vem antes do "iov="
                    size_t iov_len = iovcnt_start - (iov_start + 4); // Calcula o tamanho da string que representa a estrutura iov
                    strncpy(arg2, iov_start + 4, iov_len); // Copia a parte da string que representa a estrutura iov para arg2
                    arg2[iov_len] = '\0';
                    strncpy(arg3, iovcnt_start + 9, sizeof(arg3) - 1); // Copia o valor do iovcnt para arg3
                }
                break;
            }
            case __NR_poll: {
                // Extrai toda a string de fds como um único campo
                char *fds_start = strstr(details, "fds=");
                char *nfds_start = strstr(details, ", nfds=");
                char *timeout_start = strstr(details, ", timeout=");

                if (fds_start && nfds_start && timeout_start) {
                    // Copia toda a parte dos fds
                    size_t fds_len = nfds_start - (fds_start + 4);
                    strncpy(arg1, fds_start + 4, fds_len);
                    arg1[fds_len] = '\0';

                    // Copia nfds
                    size_t nfds_len = timeout_start - (nfds_start + 7);
                    strncpy(arg2, nfds_start + 7, nfds_len);
                    arg2[nfds_len] = '\0';

                    // Copia timeout
                    strncpy(arg3, timeout_start + 10, sizeof(arg3) - 1);
                }
                break;
            }
            case __NR_statx:
                sscanf(details, "dirfd=%255[^,], pathname=%255[^,], flags=%255[^,], mask=%255[^,], statxbuf=%255s", 
                       arg1, arg2, arg3, arg4, arg5);
                break;
            case __NR_close:
                sscanf(details, "fd=%255s", arg1);
                break;
            case __NR_futex:
                sscanf(details, "uaddr=%255[^,], op=%255[^,], val=%255s", arg1, arg2, arg3);
                break;
            case __NR_openat:
                sscanf(details, "dirfd=%255[^,], pathname=%255[^,], flags=%255[^,], mode=%255s", 
                       arg1, arg2, arg3, arg4);
                break;
            case __NR_recvmsg: {
                // Extrai toda a estrutura msg como um único campo
                char *msg_start = strstr(details, "msg=");
                char *flags_start = strstr(details, ", flags=");

                if (msg_start && flags_start) {
                    // Copia sockfd
                    sscanf(details, "sockfd=%255[^,]", arg1);

                    // Copia toda a parte da msg
                    size_t msg_len = flags_start - (msg_start + 4);
                    strncpy(arg2, msg_start + 4, msg_len);
                    arg2[msg_len] = '\0';

                    // Copia flags
                    strncpy(arg3, flags_start + 8, sizeof(arg3) - 1);
                }
                break;
            }
            case __NR_newfstatat:
                sscanf(details, "dirfd=%255[^,], pathname=%255[^,], buf=%255[^,], flags=%255s",
                    arg1, arg2, arg3, arg4);
                break;
            case __NR_access:
                sscanf(details, "pathname=%255[^,], mode=%255s", arg1, arg2);
                break;
            case __NR_write: {
                // Extrai fd e buf normalmente
                sscanf(details, "fd=%255[^,], buf=%255[^,]", arg1, arg2);

                // Pula o content, procurando pelo count (assim como o strace faz)
                char *count_start = strstr(details, "count=");
                if (count_start) {
                    sscanf(count_start, "count=%255s", arg3);
                }
                break;
            }
            default:
                snprintf(arg1, sizeof(arg1), "%llu", regs->rdi);
                snprintf(arg2, sizeof(arg2), "%llu", regs->rsi);
                snprintf(arg3, sizeof(arg3), "%llu", regs->rdx);
                snprintf(arg4, sizeof(arg4), "%llu", regs->r10);
                snprintf(arg5, sizeof(arg5), "%llu", regs->r8);
                snprintf(arg6, sizeof(arg6), "%llu", regs->r9);
                break;
        }

        // Limpa aspas e substitui vírgulas internas por ponto-e-vírgula
        char *args[] = {arg1, arg2, arg3, arg4, arg5, arg6};
        for (int i = 0; i < 6; i++) {
            // Remove aspas existentes
            char *p = args[i];
            while (*p) {
                if (*p == '"') *p = '\'';
                p++;
            }
            
            // Substitui vírgulas por ponto-e-vírgula
            p = args[i];
            while (*p) {
                if (*p == ',') *p = ';';
                p++;
            }
        }

        // Escreve no CSV com tratamento seguro para strings
        fprintf(csv_file, "%s,", nome_syscall);
        for (int i = 0; i < 6; i++) {
            if (strchr(args[i], ';') || strchr(args[i], ' ')) {
                fprintf(csv_file, "\"%s\",", args[i]);
            } else {
                fprintf(csv_file, "%s,", args[i]);
            }
        }
        fprintf(csv_file, "%lld,%s,%d\n", retorno, timestamp, pid);
        fflush(csv_file);
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
    printf("Monitorando PID: %d\n", pid);
}

/*
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
        printf("Processo %d desanexado\n", pid);
        return;
    }

    // Configura opções de ptrace
    int options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1) {
        perror("ptrace setoptions falhou");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        printf("Processo %d desanexado", pid);
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
            format_readable_timestamp(&ts, timestamp, sizeof(timestamp));

            // Imprime/grava as informações da syscall
            print_syscall_info(syscall_num, &regs, timestamp, wpid);
        }

        // Continua a execução do processo
        ptrace(PTRACE_SYSCALL, wpid, NULL, NULL);
    }

    // Desanexa do processo antes de terminar
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("Processo %d desanexado", pid);
}

/*
Função principal que inicia o monitoramento de um processo e seus filhos
parent_pid: PID do processo principal a ser monitorado
*/
void start_monitoring(int parent_pid, int monitorar_filhos) {
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

    // Adiciona o processo principal
    add_pid(parent_pid);
    
    // Se a flag -f estiver ativada, busca todos os filhos/threads
    if (monitorar_filhos) {
        find_all_children(parent_pid);
    }

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