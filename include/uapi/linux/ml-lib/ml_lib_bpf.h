/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Machine Learning (ML) library - BPF UAPI definitions
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _UAPI_LINUX_ML_LIB_BPF_H
#define _UAPI_LINUX_ML_LIB_BPF_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/*
 * BPF control commands for ML models.
 * Used by SEC("syscall") BPF programs via kfuncs.
 */
enum ml_lib_bpf_command {
	ML_LIB_BPF_CMD_NOP = 0,
	ML_LIB_BPF_CMD_START,
	ML_LIB_BPF_CMD_STOP,
	ML_LIB_BPF_CMD_PREPARE_DATASET,
	ML_LIB_BPF_CMD_DISCARD_DATASET,
};

/*
 * struct ml_lib_bpf_cmd_ctx - command context for SEC("syscall") programs
 * @model_id: target model ID from IDR registry
 * @command: one of enum ml_lib_bpf_command
 */
struct ml_lib_bpf_cmd_ctx {
	__u32 model_id;
	__u32 command;
};

#define ML_LIB_BPF_NAME_MAX	64

/*
 * struct ml_lib_bpf_model_info - model info stored in BPF hash maps
 * @model_id: unique model identifier
 * @mode: current ml_lib_system_mode value
 * @state: current model state
 * @dataset_type: current dataset type
 * @dataset_state: current dataset state
 * @subsystem_name: name of the parent subsystem
 * @model_name: name of the ML model
 */
struct ml_lib_bpf_model_info {
	__u32 model_id;
	__u32 mode;
	__u32 state;
	__u32 dataset_type;
	__u32 dataset_state;
	char subsystem_name[ML_LIB_BPF_NAME_MAX];
	char model_name[ML_LIB_BPF_NAME_MAX];
};

/*
 * Event types emitted via BPF ring buffer
 */
enum ml_lib_bpf_event_type {
	ML_LIB_BPF_EVENT_MODEL_REGISTERED = 1,
	ML_LIB_BPF_EVENT_MODEL_UNREGISTERED,
	ML_LIB_BPF_EVENT_STATE_CHANGE,
	ML_LIB_BPF_EVENT_DATASET_UPDATE,
	ML_LIB_BPF_EVENT_TEST_DEV_ACCESS,
	ML_LIB_BPF_EVENT_TEST_DEV_IO,
};

/*
 * struct ml_lib_bpf_event - event sent through BPF ring buffer
 * @type: one of enum ml_lib_bpf_event_type
 * @model_id: model this event relates to
 * @old_value: previous state/type value (context-dependent)
 * @new_value: new state/type value (context-dependent)
 * @error: error code if applicable, 0 on success
 * @timestamp: ktime_get_ns() at event emission
 */
struct ml_lib_bpf_event {
	__u32 type;
	__u32 model_id;
	__u32 old_value;
	__u32 new_value;
	__s32 error;
	__u64 timestamp;
};

/*
 * struct ml_lib_bpf_test_dev_stats - test driver statistics
 * @buffer_size: size of the device buffer
 * @data_size: current data occupancy
 * @access_count: number of opens
 * @read_count: number of reads
 * @write_count: number of writes
 */
struct ml_lib_bpf_test_dev_stats {
	__u64 buffer_size;
	__u64 data_size;
	__u64 access_count;
	__u64 read_count;
	__u64 write_count;
};

#endif /* _UAPI_LINUX_ML_LIB_BPF_H */
