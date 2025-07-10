#ifndef UTIL_H
#define UTIL_H

#include <time.h> 
#include <stddef.h>

void format_readable_timestamp(const struct timespec *ts, char *buffer, size_t size);
int file_exist(const char *nome);
void show_help(void);

#endif