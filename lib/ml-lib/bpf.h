// SPDX-License-Identifier: GPL-2.0-only
/*
 * Machine Learning (ML) library - BPF interface
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _LINUX_ML_LIB_BPF_H
#define _LINUX_ML_LIB_BPF_H

/* Command constants */
#define ML_LIB_BPF_CMD_NOP		0
#define ML_LIB_BPF_CMD_START		1
#define ML_LIB_BPF_CMD_STOP		2
#define ML_LIB_BPF_CMD_PREPARE_DATASET	3
#define ML_LIB_BPF_CMD_DISCARD_DATASET	4

int ml_model_register_bpf(struct ml_lib_model *ml_model);
void ml_model_unregister_bpf(struct ml_lib_model *ml_model);

#endif /* _LINUX_ML_LIB_BPF_H */
