#ifndef _COMM_H
#define _COMM_H

#include <linux/types.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _PROCESS_PIDS {
    size_t total_count;
    size_t array_size;
    size_t copied_count;
    pid_t *pids;
} PROCESS_PIDS, *PPROCESS_PIDS;

typedef struct _PROCESS_PID {
    char *name;
    pid_t pid;
} PROCESS_PID, *PPROCESS_PID;

enum OPERATIONS {
    OP_INIT_KEY         = 0x800,
    OP_READ_MEM         = 0x801,
    OP_WRITE_MEM        = 0x802,
    OP_MODULE_BASE      = 0x803,
    OP_HIDE_PROCESS     = 0x804,
    OP_UNHIDE_PROCESS   = 0x805,
    OP_GET_PROCESS_PID  = 0x806,
    OP_GET_PID_BY_NAME  = 0x807,
};

#endif // _COMM_H