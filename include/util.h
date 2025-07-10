#ifndef UTIL_H
#define UTIL_H

#include <time.h>
#include <sys/types.h>     
#include <time.h>          
#include <stddef.h>       

void formatar_timestamp_legivel(struct timespec ts, char *buffer, size_t size);
int file_exist(const char *nome);
char* read_process_memory(pid_t pid, unsigned long address, size_t size);

#endif
