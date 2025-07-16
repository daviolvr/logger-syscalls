#ifndef LOGGER_H
#define LOGGER_H

#include <stdatomic.h>
#include <sys/types.h>
#include <sys/user.h>  

void start_monitoring(int pid, int monitorar_filhos);
void signal_handler(int sig);
void format_syscall_details(long syscall_num, const struct user_regs_struct *regs, 
    int pid, char *buffer, size_t size);
void print_syscall_info(long syscall_num, const struct user_regs_struct *regs,
                       const char* timestamp, int pid);
void add_pid(int pid);
void find_all_children(int parent_pid);
int attach_to_process(int pid);
void monitor_process(int pid);

#endif