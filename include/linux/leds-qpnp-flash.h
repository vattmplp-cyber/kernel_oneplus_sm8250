/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2016-2020, The Linux Foundation. All rights reserved.
 */

#ifndef __LEDS_QPNP_FLASH_H
#define __LEDS_QPNP_FLASH_H

#include <linux/leds.h>

#define ENABLE_REGULATOR		BIT(0)
#define DISABLE_REGULATOR		BIT(1)
#define QUERY_MAX_AVAIL_CURRENT		BIT(2)
#define QUERY_MAX_CURRENT		BIT(3)

#define FLASH_LED_PREPARE_OPTIONS_MASK	GENMASK(3, 0)

int qpnp_flash_register_led_prepare(struct device *dev, void *data);

#if (defined CONFIG_LEDS_QTI_FLASH || defined CONFIG_LEDS_QPNP_FLASH_V2)
int qpnp_flash_led_prepare(struct led_trigger *trig, int options,
					int *max_current);
#else
static inline int qpnp_flash_led_prepare(struct led_trigger *trig, int options,
					int *max_current)
{
	return -ENODEV;
}
#endif

// === ВИПРАВЛЕНО ТУТ ===
// Ми повністю прибираємо #ifdef / #else розгалуження, залишаючи лише один чистий прототип.
// Тепер компілятор завжди знатиме, що функція існує у файлі qcom-spmi-wled.c
int wled_flash_led_prepare(struct led_trigger *trig, int options,
					int *max_current);

#endif
