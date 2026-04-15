// SPDX-License-Identifier: GPL-2.0-only
/*
 * Machine Learning (ML) library - BPF interface
 *
 * Provides kfuncs for BPF programs to control ML models and
 * an IDR-based registry.
 *
 * Copyright (C) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/refcount.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>

#include <linux/ml-lib/ml_lib.h>

#include "bpf.h"

#define CREATE_TRACE_POINTS
#include <trace/events/ml_lib.h>

/* IDR registry for model_id -> ml_lib_model mapping */
static DEFINE_IDR(ml_model_idr);
static DEFINE_SPINLOCK(ml_model_idr_lock);

/*
 * ml_model_register_bpf - register model in IDR and emit tracepoint
 * @ml_model: model to register
 *
 * Allocates a unique model_id via IDR and fires the
 * ml_lib_model_registered tracepoint.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ml_model_register_bpf(struct ml_lib_model *ml_model)
{
	int id;

	refcount_set(&ml_model->refcount, 1);

	idr_preload(GFP_KERNEL);
	spin_lock(&ml_model_idr_lock);
	id = idr_alloc(&ml_model_idr, ml_model, 1, 0, GFP_ATOMIC);
	spin_unlock(&ml_model_idr_lock);
	idr_preload_end();

	if (id < 0)
		return id;

	ml_model->model_id = (u32)id;

	trace_ml_lib_model_registered(ml_model->model_id,
				      ml_model->subsystem_name,
				      ml_model->model_name);

	return 0;
}

/*
 * ml_model_unregister_bpf - remove model from IDR and emit tracepoint
 * @ml_model: model to unregister
 */
void ml_model_unregister_bpf(struct ml_lib_model *ml_model)
{
	trace_ml_lib_model_unregistered(ml_model->model_id);

	spin_lock(&ml_model_idr_lock);
	idr_remove(&ml_model_idr, ml_model->model_id);
	spin_unlock(&ml_model_idr_lock);
}

/* ----------------------------------------------------------------
 * BPF kfunc implementations
 * ---------------------------------------------------------------- */

__bpf_kfunc_start_defs();

/*
 * bpf_ml_model_lookup - look up a model by ID, incrementing refcount
 * @model_id: ID returned from ml_model_register_bpf()
 *
 * Returns a referenced pointer to the model, or NULL if not found.
 * The caller must release the reference via bpf_ml_model_release().
 */
__bpf_kfunc struct ml_lib_model *bpf_ml_model_lookup(u32 model_id)
{
	struct ml_lib_model *ml_model;

	spin_lock(&ml_model_idr_lock);
	ml_model = idr_find(&ml_model_idr, model_id);
	if (ml_model && !refcount_inc_not_zero(&ml_model->refcount))
		ml_model = NULL;
	spin_unlock(&ml_model_idr_lock);

	return ml_model;
}

/*
 * bpf_ml_model_release - release a model reference obtained via lookup
 * @ml_model: model pointer obtained from bpf_ml_model_lookup()
 */
__bpf_kfunc void bpf_ml_model_release(struct ml_lib_model *ml_model)
{
	if (!ml_model)
		return;

	refcount_dec(&ml_model->refcount);
}

/*
 * bpf_ml_model_start - start a model from BPF context
 * @ml_model: model to start (must hold a reference)
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ml_model_start(struct ml_lib_model *ml_model)
{
	struct ml_lib_model_run_config config = {};

	return ml_model_start(ml_model, &config);
}

/*
 * bpf_ml_model_stop - stop a model from BPF context
 * @ml_model: model to stop (must hold a reference)
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ml_model_stop(struct ml_lib_model *ml_model)
{
	return ml_model_stop(ml_model);
}

/*
 * bpf_ml_model_prepare_dataset - prepare a dataset from BPF context
 * @ml_model: model to prepare dataset for (must hold a reference)
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ml_model_prepare_dataset(struct ml_lib_model *ml_model)
{
	return ml_model_get_dataset(ml_model, NULL, NULL);
}

/*
 * bpf_ml_model_discard_dataset - discard dataset from BPF context
 * @ml_model: model whose dataset to discard (must hold a reference)
 *
 * Returns 0 on success, negative errno on failure.
 */
__bpf_kfunc int bpf_ml_model_discard_dataset(struct ml_lib_model *ml_model)
{
	return ml_model_discard_dataset(ml_model);
}

/*
 * bpf_ml_model_get_state - get current model state
 * @ml_model: model to query (must hold a reference)
 *
 * Returns the current state as an integer.
 */
__bpf_kfunc int bpf_ml_model_get_state(struct ml_lib_model *ml_model)
{
	return atomic_read(&ml_model->state);
}

/*
 * bpf_ml_model_get_mode - get current model mode
 * @ml_model: model to query (must hold a reference)
 *
 * Returns the current mode as an integer.
 */
__bpf_kfunc int bpf_ml_model_get_mode(struct ml_lib_model *ml_model)
{
	return atomic_read(&ml_model->mode);
}

/*
 * bpf_ml_model_get_id - get model ID
 * @ml_model: model to query (must hold a reference)
 *
 * Returns the model_id.
 */
__bpf_kfunc u32 bpf_ml_model_get_id(struct ml_lib_model *ml_model)
{
	return ml_model->model_id;
}

__bpf_kfunc_end_defs();

/* ----------------------------------------------------------------
 * kfunc registration
 * ---------------------------------------------------------------- */

BTF_KFUNCS_START(ml_lib_bpf_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ml_model_lookup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_ml_model_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_ml_model_start)
BTF_ID_FLAGS(func, bpf_ml_model_stop)
BTF_ID_FLAGS(func, bpf_ml_model_prepare_dataset)
BTF_ID_FLAGS(func, bpf_ml_model_discard_dataset)
BTF_ID_FLAGS(func, bpf_ml_model_get_state)
BTF_ID_FLAGS(func, bpf_ml_model_get_mode)
BTF_ID_FLAGS(func, bpf_ml_model_get_id)
BTF_KFUNCS_END(ml_lib_bpf_kfunc_ids)

static const struct btf_kfunc_id_set ml_lib_bpf_syscall_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ml_lib_bpf_kfunc_ids,
};

static const struct btf_kfunc_id_set ml_lib_bpf_tracing_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ml_lib_bpf_kfunc_ids,
};

static int __init ml_lib_bpf_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					&ml_lib_bpf_syscall_kfunc_set);
	if (ret) {
		pr_err("ml_lib: failed to register syscall kfuncs: %d\n", ret);
		return ret;
	}

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					&ml_lib_bpf_tracing_kfunc_set);
	if (ret) {
		pr_err("ml_lib: failed to register tracing kfuncs: %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * Use late_initcall so BPF subsystem is ready before we register kfuncs.
 * When built as a module, module_init is used instead.
 */
#ifndef MODULE
late_initcall(ml_lib_bpf_init);
#else
module_init(ml_lib_bpf_init);
#endif
