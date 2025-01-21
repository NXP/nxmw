/*
 *
 * Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/version.h>
#include <errno.h>
#include <time.h>


unsigned int gpio_export(int pin);
unsigned int gpio_unexport(int pin);
unsigned int gpio_direction(int pin, int dir);
unsigned int gpio_read(int pin, int *value);
unsigned int gpio_write(int pin, unsigned int value);