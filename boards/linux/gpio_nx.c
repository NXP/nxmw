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
#include <stdio.h>
#include <stdlib.h>


#define RPI_DIRECTION_IN  0
#define RPI_DIRECTION_OUT  1
#define RPI_VAL_LOW  0x00
#define RPI_VAL_HIGH 0x01
#define RPI_MAX_PATH 40

unsigned int gpio_export(int pin)
{
	char buffer[RPI_MAX_PATH] = {0};
	size_t bytes_written = 0;
	int fd = -1;
	fd = open("/sys/class/gpio/export", O_WRONLY);
	if (-1 == fd) {
		return(0);
	}
	bytes_written = snprintf(buffer, RPI_MAX_PATH, "%d", pin);
	write(fd, buffer, bytes_written);
	close(fd);
	return(1);
}

unsigned int gpio_unexport(int pin)
{
	char buffer[RPI_MAX_PATH] = {0};
	size_t bytes_written = 0;
	int fd = -1;
	fd = open("/sys/class/gpio/unexport", O_WRONLY);
	if (-1 == fd) {
		return(0);
	}
	bytes_written = snprintf(buffer, RPI_MAX_PATH, "%d", pin);
	write(fd, buffer, bytes_written);
	close(fd);
	return(1);
}

unsigned int gpio_direction(int pin, int dir) {
	char path[RPI_MAX_PATH] = {0};
	int fd = -1, ret = -1;
	snprintf(path, RPI_MAX_PATH, "/sys/class/gpio/gpio%d/direction", pin);
	fd = open(path, O_WRONLY);
	if (-1 == fd) {
		return(0);
	}

    if (RPI_DIRECTION_IN == dir) {
        ret = write(fd, "in", 2);
    }
    else {
        ret = write(fd, "out", 3);
    }

	if (-1 == ret) {
		return(0);
	}

	close(fd);
	return(1);
}

unsigned int gpio_read(int pin, int *value) {
	char path[RPI_MAX_PATH] = {0};
	char value_str[3] = {0};
	int fd = -1;

	snprintf(path, RPI_MAX_PATH, "/sys/class/gpio/gpio%d/value", pin);
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return(0);
	}

	if (-1 == read(fd, value_str, 3)) {
		return(0);
	}

	close(fd);
    *value = atoi(value_str);
	return(1);
}

unsigned int gpio_write(int pin, unsigned int value)
{
	char path[RPI_MAX_PATH] = {0};
	int fd = -1, ret = -1;

    if ((value != RPI_VAL_HIGH) && (value != RPI_VAL_LOW)){
		return(0);
	}

	snprintf(path, RPI_MAX_PATH, "/sys/class/gpio/gpio%d/value", pin);
	fd = open(path, O_WRONLY);
	if (-1 == fd) {
		return(0);
	}

    if (value == RPI_VAL_HIGH) {
        ret = write(fd, "1", 1);
    }
    else {
        ret = write(fd, "0", 1);
    }

	if (1 != ret) {
		return(0);
	}

	close(fd);
	return(1);
}
