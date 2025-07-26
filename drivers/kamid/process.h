#ifndef _PROCESS_H
#define _PROCESS_H

#include <linux/kernel.h>

uintptr_t get_module_base(pid_t pid, char *name);
pid_t get_process_pid(const char *name);

#endif // _PROCESS_H