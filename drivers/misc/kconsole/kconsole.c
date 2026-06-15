#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "kconsole"

// Обробник команд, які ти будеш надсилати з Termux
static ssize_t kconsole_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    char k_buf[128];
    
    if (count > sizeof(k_buf) - 1) return -EINVAL;
    if (copy_from_user(k_buf, buffer, count)) return -EFAULT;
    k_buf[count] = '\0';

    printk(KERN_INFO "[KConsole] Отримано команду з Termux: %s\n", k_buf);

    // СЮДИ МИ БУДЕМО ДОПИСУВАТИ ХАКИ (обхід просторів імен, видача root тощо)

    return count;
}

static const struct file_operations kconsole_fops = {
    .owner = THIS_MODULE,
    .write = kconsole_write,
};

static int __init kconsole_init(void) {
    // Створюємо файл у /proc з правами 0666, щоб його бачили всі додатки в Android
    proc_create(PROC_NAME, 0666, NULL, &kconsole_fops);
    printk(KERN_INFO "[KConsole] Модуль успішно завантажено в Kernel Space!\n");
    return 0;
}

static void __exit kconsole_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "[KConsole] Модуль вивантажено з пам'яті.\n");
}

module_init(kconsole_init);
module_exit(kconsole_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marik");
MODULE_DESCRIPTION("Dynamic Kernel Space Console");
