#include <linux/slab.h>
#include <linux/compat.h>
#include "comm.h"
#include "compat.h"
#include "memory.h"
#include "process.h"

extern bool is_driver_verified(void);
extern long handle_module_base(unsigned long arg);
extern long handle_hide_process(pid_t pid);
extern long handle_unhide_process(pid_t pid);
extern long handle_get_process_pids(unsigned long arg);

long dispatch_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    if (cmd != OP_INIT_KEY && !is_driver_verified()) {
        return -EPERM;
    }

    switch (cmd) {
        case OP_INIT_KEY: {
            return filp->f_op->unlocked_ioctl(filp, cmd, arg);
        }
        case OP_READ_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64;
            compat_uptr_t buffer_ptr32;

            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;

            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);
            
            if (!read_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size)) 
                return -EFAULT;
            break;
        }
        case OP_WRITE_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64;
            compat_uptr_t buffer_ptr32;

            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;
            
            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);

            if (!write_process_memory(cm64.pid, cm64.addr, cm64.buffer, cm64.size)) 
                return -EFAULT;
            break;
        }
        case OP_MODULE_BASE: {
            MODULE_BASE32 __user *p32 = compat_ptr(arg);
            MODULE_BASE mb64;
            compat_uptr_t name_ptr32;
            char name_buffer[256];

            if (get_user(mb64.pid, &p32->pid)) return -EFAULT;
            if (get_user(name_ptr32, &p32->name)) return -EFAULT;
            mb64.name = compat_ptr(name_ptr32);

            if (copy_from_user(name_buffer, mb64.name, sizeof(name_buffer) - 1) != 0) 
                return -EFAULT;
            name_buffer[sizeof(name_buffer) - 1] = '\0';

            mb64.base = get_module_base(mb64.pid, name_buffer);

            if (put_user(mb64.base, &p32->base)) 
                return -EFAULT;
            break;
        }
        case OP_HIDE_PROCESS: {
            pid_t pid;
            if (copy_from_user(&pid, compat_ptr(arg), sizeof(pid_t)))
                return -EFAULT;
            return handle_hide_process(pid);
        }
        case OP_UNHIDE_PROCESS: {
            pid_t pid;
            if (copy_from_user(&pid, compat_ptr(arg), sizeof(pid_t)))
                return -EFAULT;
            return handle_unhide_process(pid);
        }
        case OP_GET_PROCESS_PID: {
            PROCESS_PIDS32 pp32;
            PROCESS_PIDS pp64;
            
            if (copy_from_user(&pp32, compat_ptr(arg), sizeof(pp32)))
                return -EFAULT;

            pp64.total_count = pp32.total_count;
            pp64.array_size = pp32.array_size;
            pp64.copied_count = pp32.copied_count;
            pp64.pids = compat_ptr(pp32.pids);
            
            long ret = handle_get_process_pids((unsigned long)&pp64);
            if (ret)
                return ret;
                
            pp32.total_count = pp64.total_count;
            pp32.copied_count = pp64.copied_count;
            
            if (copy_to_user(compat_ptr(arg), &pp32, sizeof(pp32)))
                return -EFAULT;
                
            break;
        }
        case OP_GET_PID_BY_NAME: {
            PROCESS_PID32 __user *p32 = compat_ptr(arg);
            PROCESS_PID pp64;
            compat_uptr_t name_ptr32;
            char name_buffer[TASK_COMM_LEN];

            if (get_user(name_ptr32, &p32->name)) 
                return -EFAULT;
            
            pp64.name = compat_ptr(name_ptr32);
            
            if (copy_from_user(name_buffer, pp64.name, sizeof(name_buffer) - 1))
                return -EFAULT;
            
            name_buffer[sizeof(name_buffer) - 1] = '\0';
            
            pp64.pid = get_process_pid(name_buffer);
            
            if (pp64.pid == 0)
                return -ESRCH;
                
            if (put_user(pp64.pid, &p32->pid))
                return -EFAULT;
                
            break;
        }
        default:
            return -EINVAL;
    }
    return 0;
}