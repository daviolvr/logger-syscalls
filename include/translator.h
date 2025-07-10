#ifndef TRANSLATOR_H
#define TRANSLATOR_H

void traduzir_flags_open(int flags, char *buf, size_t size);
void traduzir_flags_statx(int flags, char *buf, size_t size);
void traduzir_mask_statx(unsigned int mask, char *buf, size_t size);
const char *traduzir_dirfd(long dirfd);

#endif
