// SPDX-License-Identifier: GPL-2.0
/*
 * Machine Learning (ML) library - BPF monitoring program
 *
 * Attaches to ml_lib tracepoints and maintains a hash map of model
 * information plus a ring buffer for streaming events to userspace.
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ml-lib/ml_lib_bpf.h>
#include "ml_lib_trace_types.h"

/* Hash map: model_id -> model_info */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct ml_lib_bpf_model_info);
} ml_model_map SEC(".maps");

/* Ring buffer for streaming events to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ml_events SEC(".maps");

/* Test device stats (single entry, key=0) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ml_lib_bpf_test_dev_stats);
} ml_test_dev_stats SEC(".maps");

static void emit_event(__u32 type, __u32 model_id,
		       __u32 old_val, __u32 new_val, __s32 error)
{
	struct ml_lib_bpf_event *e;

	e = bpf_ringbuf_reserve(&ml_events, sizeof(*e), 0);
	if (!e)
		return;

	e->type = type;
	e->model_id = model_id;
	e->old_value = old_val;
	e->new_value = new_val;
	e->error = error;
	e->timestamp = bpf_ktime_get_ns();

	bpf_ringbuf_submit(e, 0);
}

/*
 * Tracepoint: ml_lib:ml_lib_model_registered
 */
SEC("tp/ml_lib/ml_lib_model_registered")
int handle_model_registered(struct trace_event_raw_ml_lib_model_registered *ctx)
{
	struct ml_lib_bpf_model_info info = {};
	__u32 model_id = ctx->model_id;

	info.model_id = model_id;
	info.mode = 0;
	info.state = 0;
	info.dataset_type = 0;
	info.dataset_state = 0;

	bpf_probe_read_kernel_str(info.subsystem_name,
				  sizeof(info.subsystem_name),
				  (void *)ctx + (ctx->__data_loc_subsystem_name & 0xFFFF));
	bpf_probe_read_kernel_str(info.model_name,
				  sizeof(info.model_name),
				  (void *)ctx + (ctx->__data_loc_model_name & 0xFFFF));

	bpf_map_update_elem(&ml_model_map, &model_id, &info, BPF_ANY);

	emit_event(ML_LIB_BPF_EVENT_MODEL_REGISTERED, model_id, 0, 0, 0);

	return 0;
}

/*
 * Tracepoint: ml_lib:ml_lib_model_unregistered
 */
SEC("tp/ml_lib/ml_lib_model_unregistered")
int handle_model_unregistered(struct trace_event_raw_ml_lib_model_unregistered *ctx)
{
	__u32 model_id = ctx->model_id;

	emit_event(ML_LIB_BPF_EVENT_MODEL_UNREGISTERED, model_id, 0, 0, 0);

	bpf_map_delete_elem(&ml_model_map, &model_id);

	return 0;
}

/*
 * Tracepoint: ml_lib:ml_lib_state_change
 */
SEC("tp/ml_lib/ml_lib_state_change")
int handle_state_change(struct trace_event_raw_ml_lib_state_change *ctx)
{
	struct ml_lib_bpf_model_info *info;
	__u32 model_id = ctx->model_id;
	int old_state = ctx->old_state;
	int new_state = ctx->new_state;

	info = bpf_map_lookup_elem(&ml_model_map, &model_id);
	if (info)
		info->state = new_state;

	emit_event(ML_LIB_BPF_EVENT_STATE_CHANGE, model_id,
		   old_state, new_state, 0);

	return 0;
}

/*
 * Tracepoint: ml_lib:ml_lib_dataset_update
 */
SEC("tp/ml_lib/ml_lib_dataset_update")
int handle_dataset_update(struct trace_event_raw_ml_lib_dataset_update *ctx)
{
	struct ml_lib_bpf_model_info *info;
	__u32 model_id = ctx->model_id;
	int dataset_type = ctx->dataset_type;
	int dataset_state = ctx->dataset_state;

	info = bpf_map_lookup_elem(&ml_model_map, &model_id);
	if (info) {
		info->dataset_type = dataset_type;
		info->dataset_state = dataset_state;
	}

	emit_event(ML_LIB_BPF_EVENT_DATASET_UPDATE, model_id,
		   dataset_type, dataset_state, 0);

	return 0;
}

/*
 * Tracepoint: ml_lib_test:ml_lib_test_dev_access
 */
SEC("tp/ml_lib_test/ml_lib_test_dev_access")
int handle_test_dev_access(struct trace_event_raw_ml_lib_test_dev_access *ctx)
{
	struct ml_lib_bpf_test_dev_stats *stats;
	struct ml_lib_bpf_test_dev_stats new_stats = {};
	__u32 key = 0;
	unsigned long access_count = ctx->access_count;

	stats = bpf_map_lookup_elem(&ml_test_dev_stats, &key);
	if (stats) {
		stats->access_count = access_count;
	} else {
		new_stats.access_count = access_count;
		bpf_map_update_elem(&ml_test_dev_stats, &key,
				    &new_stats, BPF_ANY);
	}

	emit_event(ML_LIB_BPF_EVENT_TEST_DEV_ACCESS, 0,
		   0, (__u32)access_count, 0);

	return 0;
}

/*
 * Tracepoint: ml_lib_test:ml_lib_test_dev_io
 */
SEC("tp/ml_lib_test/ml_lib_test_dev_io")
int handle_test_dev_io(struct trace_event_raw_ml_lib_test_dev_io *ctx)
{
	struct ml_lib_bpf_test_dev_stats *stats;
	struct ml_lib_bpf_test_dev_stats new_stats = {};
	__u32 key = 0;
	int op_type = ctx->op_type;
	unsigned long bytes = ctx->bytes;
	unsigned long count = ctx->count;

	stats = bpf_map_lookup_elem(&ml_test_dev_stats, &key);
	if (stats) {
		if (ctx->op_type == 0) /* read */
			stats->read_count = count;
		else /* write */
			stats->write_count = count;
	} else {
		if (op_type == 0)
			new_stats.read_count = count;
		else
			new_stats.write_count = count;
		bpf_map_update_elem(&ml_test_dev_stats, &key,
				    &new_stats, BPF_ANY);
	}

	emit_event(ML_LIB_BPF_EVENT_TEST_DEV_IO, 0,
		   op_type, (__u32)bytes, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
