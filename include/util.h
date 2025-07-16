#ifndef UTIL_H
#define UTIL_H

#include <time.h>
#include <sys/types.h>     
#include <time.h>          
#include <stddef.h>       
#include <time.h> 
#include <stddef.h>

void format_readable_timestamp(const struct timespec *ts, char *buffer, size_t size);
char* read_process_memory(pid_t pid, unsigned long address, size_t size);
void show_help(void);

#endif