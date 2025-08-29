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
	DSQ_MODE_CPU = 0,
	DSQ_MODE_SHARED = 1,

	/* Maximum command name length for workload detection */
	MAX_COMM_LEN = 16,

	/* Workload types */
	WORKLOAD_TYPE_UNKNOWN = 0,
	WORKLOAD_TYPE_LATENCY_SENSITIVE = 1,  /* High nvcsw, short bursts */
	WORKLOAD_TYPE_CPU_INTENSIVE = 2,      /* Low nvcsw, long runtime */
	WORKLOAD_TYPE_CACHE_SENSITIVE = 3,    /* High LLC/TLB misses */
	WORKLOAD_TYPE_GPU_INTENSIVE = 4,      /* GPU operations detected */
	WORKLOAD_TYPE_MIXED = 5,              /* Mixed characteristics */
	MAX_WORKLOAD_TYPES = 6,

	/* Core types */
	CORE_TYPE_BIG = 1,
	CORE_TYPE_LITTLE = 2,
	CORE_TYPE_TURBO = 3,

	/* Classification constants */
	MIN_SAMPLES_FOR_CLASSIFICATION = 10,
	CLASSIFICATION_INTERVAL_NS = 500 * NSEC_PER_MSEC,
	CONFIDENCE_THRESHOLD = 70,            /* 70% confidence required */
	CONFIDENCE_LOW_THRESHOLD = 40,        /* Below this, enable perf monitoring */
	POLICY_SWITCH_THRESHOLD = 25,         /* 25% of tasks for global policy */
	POLICY_SWITCH_HYSTERESIS = 5,         /* 5% hysteresis band */
	
	/* Perf event monitoring states */
	PERF_MON_DISABLED = 0,
	PERF_MON_PENDING = 1,
	PERF_MON_ACTIVE = 2,
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
	s32 mask_type;  /* 0 = primary, 1 = big, 2 = little, 3 = turbo */
};

struct domain_arg {
	s32 lvl_id;
	s32 cpu_id;
	s32 sibling_cpu_id;
	s32 core_type;
};

/* Performance event data collected on-demand */
struct perf_event_data {
	/* Cache performance */
	u64 llc_misses;                /* Last level cache misses */
	u64 llc_references;            /* Last level cache references */
	u64 tlb_misses;                /* TLB misses */
	u64 tlb_references;            /* TLB references */
	
	/* Memory bandwidth */
	u64 memory_bandwidth;          /* Estimated memory bandwidth usage */
	u64 local_memory_accesses;     /* NUMA local memory accesses */
	u64 remote_memory_accesses;    /* NUMA remote memory accesses */
	
	/* CPU performance */
	u64 instructions_retired;      /* Total instructions executed */
	u64 cycles;                    /* CPU cycles consumed */
	u64 branch_misses;             /* Branch mispredictions */
	
	/* Monitoring metadata */
	u64 last_perf_sample;          /* Last perf event sample time */
	u32 perf_sample_count;         /* Number of perf samples collected */
	u32 _padding;                  /* Padding for alignment */
};

/* Classification metrics for workload detection */
struct classification_metrics {
	/* Behavior counters */
	u64 behavior_samples;          /* Total samples collected */
	u64 wakeup_count;              /* Number of wakeups */
	u64 io_wait_count;             /* Times task waited for I/O */
	u64 cpu_migrations;            /* Number of CPU migrations */
	u64 cache_misses;              /* Estimated cache misses (from migrations) */
	
	/* Timing metrics */
	u64 total_runtime;             /* Total accumulated runtime */
	u64 total_sleep_time;          /* Total time spent sleeping */
	u64 avg_runtime_per_slice;     /* Average runtime per scheduling slice */
	u64 avg_sleep_duration;        /* Average sleep duration */
	
	/* GPU/Accelerator metrics */
	u64 gpu_usage_count;           /* GPU operation count */
	u64 last_gpu_access;           /* Last GPU access timestamp */
	
	/* Workload classification */
	u32 confidence_scores[MAX_WORKLOAD_TYPES];  /* Confidence for each type */
	u64 last_classification;       /* Last classification timestamp */
	u64 classification_count;      /* Number of reclassifications */
	
	/* Performance monitoring state */
	u8 perf_mon_state;             /* Current perf monitoring state */
	u8 needs_detailed_analysis;    /* Flag for ambiguous classification */
};

/* Enhanced workload information */
struct workload_info {
	/* Current classification */
	u32 current_type;              /* Current workload type */
	u32 previous_type;             /* Previous workload type */
	u32 type_confidence;           /* Confidence in current type (0-100) */
	
	/* Historical tracking */
	u32 type_history[4];           /* Rolling history of types */
	u8 history_index;              /* Current position in history */
	
	/* Classification metrics */
	struct classification_metrics metrics;
	
	/* Performance event data (populated on-demand) */
	struct perf_event_data perf_data;
	
	/* Policy hints for scheduler */
	u8 prefer_big_core;            /* Hint to prefer performance cores */
	u8 prefer_cache_local;         /* Hint to minimize cache migrations */
	u8 latency_critical;           /* Hint for latency-critical handling */
};

#endif /* __INTF_H */
