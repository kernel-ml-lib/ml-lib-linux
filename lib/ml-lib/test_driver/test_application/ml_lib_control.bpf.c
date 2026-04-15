// SPDX-License-Identifier: GPL-2.0
/*
 * Machine Learning (ML) library - BPF control program
 *
 * SEC("syscall") program that uses kfuncs to dispatch commands
 * (start, stop, prepare/discard dataset) to ML models.
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/ml-lib/ml_lib_bpf.h>

/*
 * kfunc declarations - these are resolved at load time via BTF.
 */
extern struct ml_lib_model *bpf_ml_model_lookup(u32 model_id) __ksym;
extern void bpf_ml_model_release(struct ml_lib_model *model) __ksym;
extern int bpf_ml_model_start(struct ml_lib_model *model) __ksym;
extern int bpf_ml_model_stop(struct ml_lib_model *model) __ksym;
extern int bpf_ml_model_prepare_dataset(struct ml_lib_model *model) __ksym;
extern int bpf_ml_model_discard_dataset(struct ml_lib_model *model) __ksym;

/*
 * SEC("syscall") program: invoked via bpf_prog_test_run() from userspace.
 * The context is a pointer to struct ml_lib_bpf_cmd_ctx passed as data_in.
 */
SEC("syscall")
int ml_lib_dispatch_cmd(struct ml_lib_bpf_cmd_ctx *ctx)
{
	struct ml_lib_model *model;
	int ret = 0;

	if (!ctx)
		return -1;

	if (ctx->command == ML_LIB_BPF_CMD_NOP)
		return 0;

	model = bpf_ml_model_lookup(ctx->model_id);
	if (!model)
		return -1; /* model not found */

	switch (ctx->command) {
	case ML_LIB_BPF_CMD_START:
		ret = bpf_ml_model_start(model);
		break;
	case ML_LIB_BPF_CMD_STOP:
		ret = bpf_ml_model_stop(model);
		break;
	case ML_LIB_BPF_CMD_PREPARE_DATASET:
		ret = bpf_ml_model_prepare_dataset(model);
		break;
	case ML_LIB_BPF_CMD_DISCARD_DATASET:
		ret = bpf_ml_model_discard_dataset(model);
		break;
	default:
		ret = -1; /* unknown command */
		break;
	}

	bpf_ml_model_release(model);

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
