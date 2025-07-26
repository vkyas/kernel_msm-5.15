#ifndef COMPAT_H
#define COMPAT_H

#include <linux/compat.h>

typedef struct _COPY_MEMORY32 {
    pid_t pid;
    compat_uptr_t addr;
    compat_uptr_t buffer;
    compat_size_t size;
} COPY_MEMORY32;

typedef struct _MODULE_BASE32 {
    pid_t pid;
    compat_uptr_t name;
    compat_uptr_t base;
} MODULE_BASE32;

typedef struct _PROCESS_PIDS32 {
    compat_size_t total_count;
    compat_size_t array_size;
    compat_size_t copied_count;
    compat_uptr_t pids;
} PROCESS_PIDS32;

typedef struct _PROCESS_PID32 {
    compat_uptr_t name;
    pid_t pid;
} PROCESS_PID32;

long dispatch_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

#endif // COMPAT_H