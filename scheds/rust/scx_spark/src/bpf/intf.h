/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),

	/* Kernel definitions */
	CLOCK_BOOTTIME		= 7,

	/* DSQ modes */
	DSQ_MODE_NODE = 0,
	DSQ_MODE_CPU = 1,
	DSQ_MODE_SHARED = 2,

	/* GPU workload types */
	GPU_WORKLOAD_NONE = 0,
	GPU_WORKLOAD_TRAINING = 1,
	GPU_WORKLOAD_INFERENCE = 2,
	GPU_WORKLOAD_DATA_PREP = 3,
	GPU_WORKLOAD_MIXED = 4,

	/* GPU memory pressure thresholds */
	GPU_MEM_PRESSURE_LOW = 50,    /* 50% memory usage */
	GPU_MEM_PRESSURE_MED = 75,    /* 75% memory usage */
	GPU_MEM_PRESSURE_HIGH = 90,   /* 90% memory usage */
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

struct cpu_arg {
	s32 cpu_id;
};

struct domain_arg {
	s32 lvl_id;
	s32 cpu_id;
	s32 sibling_cpu_id;
};

/* GPU context for single-GPU optimization */
struct gpu_ctx {
	u64 memory_used;           /* Current GPU memory usage in bytes */
	u64 memory_total;          /* Total GPU memory in bytes */
	u64 compute_utilization;   /* GPU compute utilization (0-100) */
	u32 numa_node;             /* GPU's NUMA node */
	u64 last_update;           /* Last update timestamp */
	bool is_active;            /* Whether GPU is actively being used */
};

/* GPU-aware task context extension */
struct gpu_task_ctx {
	u32 workload_type;         /* Type of GPU workload */
	u64 gpu_memory_usage;      /* Task's GPU memory usage */
	u64 last_gpu_access;       /* Last GPU access timestamp */
	bool gpu_affinity_set;     /* Whether GPU affinity is set */
	u32 preferred_numa_node;   /* Preferred NUMA node for GPU access */
};

#endif /* __INTF_H */
