/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Machine Learning (ML) library - tracepoint definitions
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ml_lib

#if !defined(_TRACE_ML_LIB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ML_LIB_H

#include <linux/tracepoint.h>

TRACE_EVENT(ml_lib_model_registered,

	TP_PROTO(u32 model_id, const char *subsystem_name,
		 const char *model_name),

	TP_ARGS(model_id, subsystem_name, model_name),

	TP_STRUCT__entry(
		__field(u32, model_id)
		__string(subsystem_name, subsystem_name)
		__string(model_name, model_name)
	),

	TP_fast_assign(
		__entry->model_id = model_id;
		__assign_str(subsystem_name);
		__assign_str(model_name);
	),

	TP_printk("model_id=%u subsystem=%s model=%s",
		  __entry->model_id,
		  __get_str(subsystem_name),
		  __get_str(model_name))
);

TRACE_EVENT(ml_lib_model_unregistered,

	TP_PROTO(u32 model_id),

	TP_ARGS(model_id),

	TP_STRUCT__entry(
		__field(u32, model_id)
	),

	TP_fast_assign(
		__entry->model_id = model_id;
	),

	TP_printk("model_id=%u", __entry->model_id)
);

TRACE_EVENT(ml_lib_state_change,

	TP_PROTO(u32 model_id, int old_state, int new_state),

	TP_ARGS(model_id, old_state, new_state),

	TP_STRUCT__entry(
		__field(u32, model_id)
		__field(int, old_state)
		__field(int, new_state)
	),

	TP_fast_assign(
		__entry->model_id = model_id;
		__entry->old_state = old_state;
		__entry->new_state = new_state;
	),

	TP_printk("model_id=%u old_state=%d new_state=%d",
		  __entry->model_id,
		  __entry->old_state,
		  __entry->new_state)
);

TRACE_EVENT(ml_lib_dataset_update,

	TP_PROTO(u32 model_id, int dataset_type, int dataset_state),

	TP_ARGS(model_id, dataset_type, dataset_state),

	TP_STRUCT__entry(
		__field(u32, model_id)
		__field(int, dataset_type)
		__field(int, dataset_state)
	),

	TP_fast_assign(
		__entry->model_id = model_id;
		__entry->dataset_type = dataset_type;
		__entry->dataset_state = dataset_state;
	),

	TP_printk("model_id=%u dataset_type=%d dataset_state=%d",
		  __entry->model_id,
		  __entry->dataset_type,
		  __entry->dataset_state)
);

#endif /* _TRACE_ML_LIB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
