/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	struct bpf_cpumask __kptr *l3_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

struct task_ctx {
	/*
	 * Temporary cpumask for calculating scheduling domains.
	 */
	struct bpf_cpumask __kptr *l3_cpumask;

	/*
	 * Task's average used time slice.
	 */
	u64 exec_runtime;
	u64 last_run_at;

	/*
	 * Task's deadline, defined as:
	 *
	 *   deadline = vruntime + exec_vruntime
	 *
	 * Here, vruntime represents the task's total runtime, scaled inversely by
	 * its weight, while exec_vruntime accounts for the vruntime accumulated
	 * from the moment the task becomes runnable until it voluntarily releases
	 * the CPU.
	 *
	 * Fairness is ensured through vruntime, whereas exec_vruntime helps in
	 * prioritizing latency-sensitive tasks: tasks that are frequently blocked
	 * waiting for an event (typically latency sensitive) will accumulate a
	 * smaller exec_vruntime, compared to tasks that continuously consume CPU
	 * without interruption.
	 *
	 * As a result, tasks with a smaller exec_vruntime will have a shorter
	 * deadline and will be dispatched earlier, ensuring better responsiveness
	 * for latency-sensitive tasks.
	 */
	u64 deadline;

	/*
	 * Task's recently used CPU: used to determine whether we need to
	 * refresh the task's cpumasks.
	 */
	s32 recent_used_cpu;
};




struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}


static void task_update_domain(struct task_struct *p, struct task_ctx *tctx,
			       s32 cpu, const struct cpumask *cpumask)
{
	struct bpf_cpumask *l3_domain;
	struct bpf_cpumask  *l3_mask;
	struct cpu_ctx *cctx;

	/*
	 * Refresh task's recently used CPU every time the task's domain
	 * is updated.
	 */
	tctx->recent_used_cpu = cpu;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	l3_domain = cctx->l3_cpumask;
	l3_mask = tctx->l3_cpumask;

	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		return;
	}

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * L3 cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	if (l3_domain)
		bpf_cpumask_and(l3_mask, cast_mask(l3_mask), cast_mask(l3_domain));
}

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}



static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	s32 cpu = 0;
	const struct cpumask *idle_cpumask;
	const struct cpumask *l3_mask;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	if (tctx->recent_used_cpu != prev_cpu)
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);

	l3_mask = cast_mask(tctx->l3_cpumask);
	if (l3_mask && bpf_cpumask_empty(l3_mask))
		l3_mask = NULL;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	

	//Look for idle cores with the same L3 cache domain (this also prioritizes another core of the same "type" (big/little) as the current core, due to the CPU topology.)
	if (l3_mask) {
		cpu = scx_bpf_pick_idle_cpu(l3_mask, 0);
		bpf_printk("l3 cpu: %d\n", cpu);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}
	//Look for any idle core usable by the task
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	bpf_printk("Any idle core: %d\n", cpu);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	/*
	 * If we couldn't find any CPU, or in case of error, return the
	 * previously used CPU.
	 */
	if (cpu < 0)
		cpu = prev_cpu;

	return cpu;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;
	bool is_idle = false;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	//pick_idle_cpu returns -ENOENT if the task has no cpumask, so we need to return the previous cpu in that case
	if (cpu == -ENOENT)
		cpu = prev_cpu;

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 prev_cpu = scx_bpf_task_cpu(p);


	/*
	 * Dispatch regular tasks to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
/*
	 * Refresh the task domain if it was migrated to a different CPU,
	 * without going through ops.select_cpu().
	 *
	 * This ensures the proactive wakeup (see below) will target a CPU
	 * near the one the task was most recently running on, preventing
	 * expensive cross-LLC or cross-node migrations.
	 */
	if (tctx->recent_used_cpu != prev_cpu){
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);
	}
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, 0);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
		return;

}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
}

s32 BPF_STRUCT_OPS(simple_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	/*
	 * Create task's L3 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	task_update_domain(p, tctx, cpu, p->cpus_ptr);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	int err;

	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create Shared DSQ: %d", err);
		return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .init_task		= (void *)simple_init_task,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
