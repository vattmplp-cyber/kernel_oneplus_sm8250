#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/init.h>

// Нова функція, яка викликається ядром при налаштуванні лімітів
static void cpufreq_gov_hardlock_limits(struct cpufreq_policy *policy)
{
    unsigned int target_freq;

    // Жорстко прописуємо максимальні частоти для Snapdragon 865 (OnePlus 8T)
    if (policy->cpu == 7) { 
        target_freq = 2841600; // Prime-ядро (макс)
    } else if (policy->cpu >= 4) {
        target_freq = 2419200; // Gold-ядра (макс)
    } else {
        target_freq = 1804800; // Silver-ядра (макс)
    }

    // Блокуємо рамки політики, щоб Meteoric/OxygenOS не скидали частоту
    policy->min = target_freq;
    policy->max = target_freq;

    // Наказуємо залізу виставити цю частоту
    __cpufreq_driver_target(policy, target_freq, CPUFREQ_RELATION_H);
}

// Реєструємо планувальник за новим стандартом ядра Android 13
static struct cpufreq_governor cpufreq_gov_hardlock = {
    .name		= "hardlock",
    .owner		= THIS_MODULE,
    .limits		= cpufreq_gov_hardlock_limits, // Використовуємо .limits замість старого .governor
};

static int __init cpufreq_gov_hardlock_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_hardlock);
}

static void __exit cpufreq_gov_hardlock_exit(void)
{
    cpufreq_unregister_governor(&cpufreq_gov_hardlock);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marik");
MODULE_DESCRIPTION("Hardlock CPUFreq Governor for Android 13");

fs_initcall(cpufreq_gov_hardlock_init);
module_exit(cpufreq_gov_hardlock_exit);
