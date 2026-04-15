// SPDX-License-Identifier: GPL-2.0
/*
 * Machine Learning (ML) library
 *
 * Test program for ml_lib_dev testing driver
 *
 * Uses libbpf to load BPF programs, read model info from BPF maps,
 * poll the ring buffer for events, and send commands via kfuncs.
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Compile with: make -C test_application/
 * Run with:     sudo ./test_ml_lib_misc_dev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <linux/ml-lib/ml_lib_bpf.h>

#include "ml_lib_misc_dev_ioctl.h"
#include "ml_lib_monitor.skel.h"
#include "ml_lib_control.skel.h"

#define DEVICE_PATH "/dev/mllibdev"

#define ML_LIB_RING_BUF_TIMEOUT_MS		(100)
#define ML_LIB_POLL_EVENTS_TIMEOUT_MS		(200)

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static const char *event_type_str(__u32 type)
{
	switch (type) {
	case ML_LIB_BPF_EVENT_MODEL_REGISTERED:
		return "MODEL_REGISTERED";
	case ML_LIB_BPF_EVENT_MODEL_UNREGISTERED:
		return "MODEL_UNREGISTERED";
	case ML_LIB_BPF_EVENT_STATE_CHANGE:
		return "STATE_CHANGE";
	case ML_LIB_BPF_EVENT_DATASET_UPDATE:
		return "DATASET_UPDATE";
	case ML_LIB_BPF_EVENT_TEST_DEV_ACCESS:
		return "TEST_DEV_ACCESS";
	case ML_LIB_BPF_EVENT_TEST_DEV_IO:
		return "TEST_DEV_IO";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ml_lib_bpf_event *e = data;

	printf("[EVENT] type=%s model_id=%u old=%u new=%u err=%d ts=%llu\n",
		event_type_str(e->type), e->model_id,
		e->old_value, e->new_value, e->error,
		(unsigned long long)e->timestamp);

	return 0;
}

static void print_separator(const char *title)
{
	printf("\n========== %s ==========\n", title);
}

static void show_model_info_bpf(int map_fd)
{
	struct ml_lib_bpf_model_info info;
	__u32 key = 0, next_key;

	print_separator("BPF Model Info (hash map)");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &info) == 0) {
			printf("  Model ID:       %u\n", info.model_id);
			printf("  Subsystem:      %s\n", info.subsystem_name);
			printf("  Model name:     %s\n", info.model_name);
			printf("  Mode:           %u\n", info.mode);
			printf("  State:          %u\n", info.state);
			printf("  Dataset type:   %u\n", info.dataset_type);
			printf("  Dataset state:  %u\n", info.dataset_state);
			printf("  ---\n");
		}
		key = next_key;
	}
}

static void show_test_dev_stats_bpf(int map_fd)
{
	struct ml_lib_bpf_test_dev_stats stats;
	__u32 key = 0;

	print_separator("BPF Test Device Stats");

	if (bpf_map_lookup_elem(map_fd, &key, &stats) == 0) {
		printf("  Buffer size:    %llu\n",
		       (unsigned long long)stats.buffer_size);
		printf("  Data size:      %llu\n",
		       (unsigned long long)stats.data_size);
		printf("  Access count:   %llu\n",
		       (unsigned long long)stats.access_count);
		printf("  Read count:     %llu\n",
		       (unsigned long long)stats.read_count);
		printf("  Write count:    %llu\n",
		       (unsigned long long)stats.write_count);
	} else {
		printf("  (no stats available yet)\n");
	}
}

static int send_bpf_command(int prog_fd, __u32 model_id, __u32 command)
{
	struct ml_lib_bpf_cmd_ctx ctx = {
		.model_id = model_id,
		.command = command,
	};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	int ret;

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	if (ret < 0) {
		fprintf(stderr, "bpf_prog_test_run failed: %s\n",
			strerror(errno));
		return ret;
	}

	printf("  Command %u -> model %u: retval=%u\n",
		command, model_id, opts.retval);

	return opts.retval;
}

static void poll_events_bpf(struct ring_buffer *rb, int timeout_ms)
{
	print_separator("Polling BPF Ring Buffer Events");

	ring_buffer__poll(rb, timeout_ms);
}

static void test_write(int fd)
{
	const char *test_data = "Hello from userspace! This is a test of the mllibdev driver.";
	ssize_t ret;

	print_separator("Write Test");

	ret = write(fd, test_data, strlen(test_data));
	if (ret < 0) {
		perror("Write failed");
		return;
	}

	printf("Successfully wrote %zd bytes\n", ret);
	printf("Data: \"%s\"\n", test_data);
}

static void test_read(int fd)
{
	char buffer[256];
	ssize_t ret;

	print_separator("Read Test");

	/* Seek to beginning */
	lseek(fd, 0, SEEK_SET);

	ret = read(fd, buffer, sizeof(buffer) - 1);
	if (ret < 0) {
		perror("Read failed");
		return;
	}

	buffer[ret] = '\0';
	printf("Successfully read %zd bytes\n", ret);
	printf("Data: \"%s\"\n", buffer);
}

static void test_ioctl(int fd)
{
	int size;
	int ret;

	print_separator("IOCTL Tests");

	/* Get current size */
	ret = ioctl(fd, ML_LIB_TEST_DEV_IOCGETSIZE, &size);
	if (ret < 0) {
		perror("IOCTL GETSIZE failed");
		return;
	}
	printf("Current data size: %d bytes\n", size);

	/* Set new size */
	size = 50;
	ret = ioctl(fd, ML_LIB_TEST_DEV_IOCSETSIZE, &size);
	if (ret < 0) {
		perror("IOCTL SETSIZE failed");
		return;
	}
	printf("Set data size to: %d bytes\n", size);

	/* Verify new size */
	ret = ioctl(fd, ML_LIB_TEST_DEV_IOCGETSIZE, &size);
	if (ret < 0) {
		perror("IOCTL GETSIZE failed");
		return;
	}
	printf("Verified new size: %d bytes\n", size);

	/* Reset buffer */
	ret = ioctl(fd, ML_LIB_TEST_DEV_IOCRESET);
	if (ret < 0) {
		perror("IOCTL RESET failed");
		return;
	}
	printf("Buffer reset successfully\n");

	/* Verify size after reset */
	ret = ioctl(fd, ML_LIB_TEST_DEV_IOCGETSIZE, &size);
	if (ret < 0) {
		perror("IOCTL GETSIZE failed");
		return;
	}
	printf("Size after reset: %d bytes\n", size);
}

int main(void)
{
	struct ml_lib_monitor_bpf *mon = NULL;
	struct ml_lib_control_bpf *ctl = NULL;
	struct ring_buffer *rb = NULL;
	int model_map_fd, stats_map_fd, cmd_prog_fd;
	int fd, ret;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("ML Library Testing Device Driver Test Program\n");
	printf("==================================\n");

	/* Load and attach BPF monitor */
	mon = ml_lib_monitor_bpf__open_and_load();
	if (!mon) {
		fprintf(stderr, "Failed to load monitor BPF skeleton: %s\n",
			strerror(errno));
		goto skip_bpf;
	}

	if (ml_lib_monitor_bpf__attach(mon)) {
		fprintf(stderr, "Failed to attach monitor BPF programs: %s\n",
			strerror(errno));
		ml_lib_monitor_bpf__destroy(mon);
		mon = NULL;
		goto skip_bpf;
	}

	model_map_fd = bpf_map__fd(mon->maps.ml_model_map);
	stats_map_fd = bpf_map__fd(mon->maps.ml_test_dev_stats);

	/* Set up ring buffer */
	rb = ring_buffer__new(bpf_map__fd(mon->maps.ml_events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer: %s\n",
			strerror(errno));
	}

	/* Load BPF control */
	ctl = ml_lib_control_bpf__open_and_load();
	if (!ctl) {
		fprintf(stderr, "Failed to load control BPF skeleton: %s\n",
			strerror(errno));
	}

skip_bpf:
	/* Open the device */
	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		perror("Failed to open device");
		printf("\nMake sure:\n");
		printf("1. The driver module is loaded (lsmod | grep mllibdev)\n");
		printf("2. You have proper permissions (run with sudo)\n");
		printf("3. The device node exists (ls -l /dev/mllibdev)\n");
		goto cleanup;
	}

	printf("Device opened successfully: %s\n", DEVICE_PATH);

	/* Drain any events from device open */
	if (rb)
		ring_buffer__poll(rb, ML_LIB_RING_BUF_TIMEOUT_MS);

	/* Write and IOCTL tests */
	test_write(fd);
	test_ioctl(fd);

	/* BPF kfunc control commands */
	if (ctl) {
		__u32 model_id;

		ret = ioctl(fd, ML_LIB_TEST_DEV_IOCGETMODELID, &model_id);
		if (ret < 0) {
			perror("IOCTL GETMODELID failed");
			goto cleanup;
		}

		cmd_prog_fd = bpf_program__fd(ctl->progs.ml_lib_dispatch_cmd);

		print_separator("BPF kfunc Control Tests");
		printf("Sending PREPARE_DATASET command...\n");
		send_bpf_command(cmd_prog_fd, model_id,
				 ML_LIB_BPF_CMD_PREPARE_DATASET);

		/* Read test: dataset_buf is now populated by extract_dataset */
		test_read(fd);

		printf("Sending START command...\n");
		send_bpf_command(cmd_prog_fd, model_id,
				 ML_LIB_BPF_CMD_START);

		printf("Sending STOP command...\n");
		send_bpf_command(cmd_prog_fd, model_id,
				 ML_LIB_BPF_CMD_STOP);

		printf("Sending DISCARD_DATASET command...\n");
		send_bpf_command(cmd_prog_fd, model_id,
				 ML_LIB_BPF_CMD_DISCARD_DATASET);

		/* Poll to catch command events */
		if (rb)
			poll_events_bpf(rb, ML_LIB_POLL_EVENTS_TIMEOUT_MS);

		/* Show updated state */
		show_model_info_bpf(model_map_fd);
	} else {
		/* BPF control unavailable: read shows empty dataset */
		test_read(fd);
	}

	/* Show BPF-based information */
	if (mon) {
		/* Poll to catch events from tests */
		if (rb)
			poll_events_bpf(rb, ML_LIB_POLL_EVENTS_TIMEOUT_MS);

		show_model_info_bpf(model_map_fd);
		show_test_dev_stats_bpf(stats_map_fd);
	}

	/* Final stats */
	print_separator("Final Test");
	printf("All tests completed successfully!\n\n");

	close(fd);

cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (ctl)
		ml_lib_control_bpf__destroy(ctl);
	if (mon)
		ml_lib_monitor_bpf__destroy(mon);

	return 0;
}
