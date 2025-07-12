#ifndef TRANSLATOR_H
#define TRANSLATOR_H

void translate_flags_open(int flags, char *buf, size_t size);
void translate_flags_statx(int flags, char *buf, size_t size);
void translate_mask_statx(unsigned int mask, char *buf, size_t size);
const char *translate_dirfd(long dirfd);

#endif
