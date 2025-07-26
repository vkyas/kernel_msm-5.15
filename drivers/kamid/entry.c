#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/version.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "compat.h"

#define DEVICE_NAME "kamid"

static const char g_secret_key[] = "O4K48z4LOz7WwslW";
static bool g_is_verified = false;

struct hidden_pid {
    pid_t pid;
    struct list_head list;
};
static LIST_HEAD(hidden_pid_list);
static DEFINE_MUTEX(hidden_pid_mutex);

bool is_driver_verified(void) {
    return g_is_verified;
}

int dispatch_open(struct inode *node, struct file *file) { return 0; }
int dispatch_close(struct inode *node, struct file *file) { return 0; }

long handle_module_base(unsigned long arg) {
    MODULE_BASE mb;
    char name_buffer[256];
    if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0) return -EFAULT;
    if (copy_from_user(name_buffer, (void __user *)mb.name, sizeof(name_buffer) - 1) != 0) return -EFAULT;
    name_buffer[sizeof(name_buffer) - 1] = '\0';
    mb.base = get_module_base(mb.pid, name_buffer);
    if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0) return -EFAULT;
    return 0;
}

long handle_hide_process(pid_t pid) {
    struct hidden_pid *new, *pos;
    
    mutex_lock(&hidden_pid_mutex);
    
    list_for_each_entry(pos, &hidden_pid_list, list) {
        if (pos->pid == pid) {
            mutex_unlock(&hidden_pid_mutex);
            return 0;
        }
    }
    
    new = kmalloc(sizeof(struct hidden_pid), GFP_KERNEL);
    if (!new) {
        mutex_unlock(&hidden_pid_mutex);
        return -ENOMEM;
    }
    
    new->pid = pid;
    INIT_LIST_HEAD(&new->list);
    list_add_tail(&new->list, &hidden_pid_list);
    
    mutex_unlock(&hidden_pid_mutex);
    return 0;
}

long handle_unhide_process(pid_t pid) {
    struct hidden_pid *pos, *tmp;
    bool found = false;
    
    mutex_lock(&hidden_pid_mutex);
    
    list_for_each_entry_safe(pos, tmp, &hidden_pid_list, list) {
        if (pos->pid == pid) {
            list_del(&pos->list);
            kfree(pos);
            found = true;
            break;
        }
    }
    
    mutex_unlock(&hidden_pid_mutex);
    return found ? 0 : -ESRCH;
}

long handle_get_process_pids(unsigned long arg) {
    PROCESS_PIDS pp;
    struct task_struct *task;
    
    if (copy_from_user(&pp, (void __user *)arg, sizeof(pp))) 
        return -EFAULT;
    
    pp.total_count = 0;
    pp.copied_count = 0;
    
    rcu_read_lock();
    for_each_process(task) {
        pid_t pid = task->pid;
        bool hidden = false;
        
        mutex_lock(&hidden_pid_mutex);
        struct hidden_pid *pos;
        list_for_each_entry(pos, &hidden_pid_list, list) {
            if (pos->pid == pid) {
                hidden = true;
                break;
            }
        }
        mutex_unlock(&hidden_pid_mutex);
        
        if (hidden) continue;
        
        pp.total_count++;
        
        if (pp.copied_count < pp.array_size) {
            if (copy_to_user(&pp.pids[pp.copied_count], &pid, sizeof(pid_t))) {
                rcu_read_unlock();
                return -EFAULT;
            }
            pp.copied_count++;
        }
    }
    rcu_read_unlock();
    
    if (copy_to_user((void __user *)arg, &pp, sizeof(pp)))
        return -EFAULT;
    
    return 0;
}

long handle_get_pid_by_name(unsigned long arg) {
    PROCESS_PID pp;
    char name_buffer[TASK_COMM_LEN];
    
    if (copy_from_user(&pp, (void __user *)arg, sizeof(pp)))
        return -EFAULT;
    
    if (copy_from_user(name_buffer, (void __user *)pp.name, sizeof(name_buffer) - 1))
        return -EFAULT;
    
    name_buffer[sizeof(name_buffer) - 1] = '\0';
    
    pp.pid = get_process_pid(name_buffer);
    
    if (pp.pid == 0) {
        printk(KERN_WARNING "[+] Driver kamid: Process '%s' not found\n", name_buffer);
        return -ESRCH;
    }
    
    if (copy_to_user((void __user *)arg, &pp, sizeof(pp)))
        return -EFAULT;
    
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    if (!capable(CAP_SYS_ADMIN)) 
        return -EPERM;

    if (cmd != OP_INIT_KEY && !g_is_verified) {
        printk(KERN_WARNING "[+] Driver kamid: Access denied. Not authenticated.\n");
        return -EPERM;
    }

    switch (cmd) {
        case OP_INIT_KEY: {
            char user_key[sizeof(g_secret_key)];
            if (copy_from_user(user_key, (void __user *)arg, sizeof(user_key)) != 0) 
                return -EFAULT;
            if (strncmp(user_key, g_secret_key, sizeof(g_secret_key)) == 0) {
                g_is_verified = true;
                printk(KERN_INFO "[+] Driver kamid: Authentication successful.\n");
            } else {
                g_is_verified = false;
                printk(KERN_ERR "[+] Driver kamid: Authentication failed.\n");
                return -EACCES;
            }
            break;
        }
        case OP_READ_MEM: {
            COPY_MEMORY cm;
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) 
                return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) 
                return -EFAULT;
            break;
        }
        case OP_WRITE_MEM: {
            COPY_MEMORY cm;
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) 
                return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) 
                return -EFAULT;
            break;
        }
        case OP_MODULE_BASE: {
            return handle_module_base(arg);
        }
        case OP_HIDE_PROCESS: {
            pid_t pid;
            if (copy_from_user(&pid, (void __user *)arg, sizeof(pid_t))) 
                return -EFAULT;
            return handle_hide_process(pid);
        }
        case OP_UNHIDE_PROCESS: {
            pid_t pid;
            if (copy_from_user(&pid, (void __user *)arg, sizeof(pid_t))) 
                return -EFAULT;
            return handle_unhide_process(pid);
        }
        case OP_GET_PROCESS_PID: {
            return handle_get_process_pids(arg);
        }
        case OP_GET_PID_BY_NAME: {
            return handle_get_pid_by_name(arg);
        }
        default:
            return -EINVAL;
    }
    return 0;
}

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
#if defined(CONFIG_COMPAT)
    .compat_ioctl = dispatch_compat_ioctl,
#endif
};

struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

int __init driver_entry(void) {
    int ret;
    printk(KERN_INFO "[+] Driver kamid: Loading...\n");
    INIT_LIST_HEAD(&hidden_pid_list);
    ret = misc_register(&misc);
    if (ret) {
        printk(KERN_ERR "[+] Driver kamid: Failed to register misc device, error %d\n", ret);
    } else {
        printk(KERN_INFO "[+] Driver kamid: Successfully loaded. Device: /dev/%s\n", DEVICE_NAME);
    }
    return ret;
}

void __exit driver_unload(void) {
    struct hidden_pid *pos, *tmp;
    
    printk(KERN_INFO "[+] Driver kamid: Unloading...\n");
    misc_deregister(&misc);
    
    mutex_lock(&hidden_pid_mutex);
    list_for_each_entry_safe(pos, tmp, &hidden_pid_list, list) {
        list_del(&pos->list);
        kfree(pos);
    }
    mutex_unlock(&hidden_pid_mutex);
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_DESCRIPTION("Secure Memory Access Driver with Process Control");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamid");