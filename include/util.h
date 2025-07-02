#ifndef UTIL_H
#define UTIL_H

#include <time.h>

void formatar_timestamp_legivel(struct timespec ts, char *buffer, size_t size);
int file_exist(const char *nome);

#endif
