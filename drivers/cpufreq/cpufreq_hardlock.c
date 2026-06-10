#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/init.h>

// Головна функція, яка керує частотами
static int cpufreq_governor_hardlock(struct cpufreq_policy *policy, unsigned int event)
{
    unsigned int target_freq;

    switch (event) {
    case CPUFREQ_GOV_START:
    case CPUFREQ_GOV_LIMITS:
        // Жорстко прописуємо частоти для Snapdragon 865 (OnePlus 8T)
        if (policy->cpu == 7) { 
            target_freq = 2841600; // Prime-ядро (макс)
        } else if (policy->cpu >= 4) {
            target_freq = 2419200; // Gold-ядра (макс)
        } else {
            target_freq = 1804800; // Silver-ядра (макс)
        }

        // Блокуємо рамки політики, щоб Meteoric не міг скинути частоту
        policy->min = target_freq;
        policy->max = target_freq;

        // Наказуємо залізу виставити цю частоту
        __cpufreq_driver_target(policy, target_freq, CPUFREQ_RELATION_H);
        break;
    }
    return 0;
}

// Реєструємо планувальник під іменем "hardlock"
static struct cpufreq_governor cpufreq_gov_hardlock = {
    .name		= "hardlock",
    .governor	= cpufreq_governor_hardlock,
    .owner		= THIS_MODULE,
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
MODULE_DESCRIPTION("Hardlock CPUFreq Governor");

fs_initcall(cpufreq_gov_hardlock_init);
module_exit(cpufreq_gov_hardlock_exit);
