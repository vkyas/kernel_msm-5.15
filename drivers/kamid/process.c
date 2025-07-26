#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/mmap_lock.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/dcache.h>
#include "process.h"

#define ARC_PATH_MAX 256

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    char buf[ARC_PATH_MAX];
    char *path_nm;
    char *base_name;

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) return 0;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return 0;
    }

    mmap_read_lock(mm);

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
            if (IS_ERR(path_nm)) continue;

            base_name = strrchr(path_nm, '/');
            base_name = base_name ? base_name + 1 : path_nm;

            if (!strcmp(base_name, name)) {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);

    return base_addr;
}

pid_t get_process_pid(const char *name)
{
    struct task_struct *task;
    pid_t found_pid = 0;
    
    rcu_read_lock();
    for_each_process(task) {
        if (strncmp(task->comm, name, TASK_COMM_LEN) == 0) {
            found_pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    return found_pid;
}