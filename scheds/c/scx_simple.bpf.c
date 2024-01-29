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
#include "scx_simple.h"

char _license[] SEC("license") = "GPL";

const volatile bool switch_partial;

struct user_exit_info uei;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, MAX_CPU);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Always dispatch on CPU #2 just for fun */
	s32 cpu = 2;
	// s32 cpu = scx_bpf_task_cpu(p);
	//
	// ^- with this enabled instead everything works.

	stat_inc(cpu);
	scx_bpf_dispatch(p, cpu, SCX_SLICE_DFL, enq_flags);
	scx_bpf_kick_cpu(cpu, 0);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(cpu);
}

static int dsq_init(void)
{
	int err;
	s32 cpu;

	bpf_for(cpu, 0, MAX_CPU) {
		err = scx_bpf_create_dsq(cpu, -1);
		if (err) {
			scx_bpf_error("failed to create pcpu DSQ %d: %d",
				      cpu, err);
			return err;
		}
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	if (!switch_partial)
		scx_bpf_switch_all();
	return dsq_init();
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
	.select_cpu		= (void *)simple_select_cpu,
	.enqueue		= (void *)simple_enqueue,
	.dispatch		= (void *)simple_dispatch,
	.init			= (void *)simple_init,
	.exit			= (void *)simple_exit,
	.timeout_ms		= 5000,
	.name			= "simple",
};
