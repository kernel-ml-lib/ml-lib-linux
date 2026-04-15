/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Machine Learning (ML) library - test driver tracepoint definitions
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ml_lib_test

#if !defined(_TRACE_ML_LIB_TEST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ML_LIB_TEST_H

#include <linux/tracepoint.h>

TRACE_EVENT(ml_lib_test_dev_access,

	TP_PROTO(unsigned long access_count),

	TP_ARGS(access_count),

	TP_STRUCT__entry(
		__field(unsigned long, access_count)
	),

	TP_fast_assign(
		__entry->access_count = access_count;
	),

	TP_printk("access_count=%lu", __entry->access_count)
);

TRACE_EVENT(ml_lib_test_dev_io,

	TP_PROTO(int op_type, size_t bytes, unsigned long count),

	TP_ARGS(op_type, bytes, count),

	TP_STRUCT__entry(
		__field(int, op_type)
		__field(size_t, bytes)
		__field(unsigned long, count)
	),

	TP_fast_assign(
		__entry->op_type = op_type;
		__entry->bytes = bytes;
		__entry->count = count;
	),

	TP_printk("op_type=%d bytes=%zu count=%lu",
		  __entry->op_type,
		  __entry->bytes,
		  __entry->count)
);

#endif /* _TRACE_ML_LIB_TEST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
