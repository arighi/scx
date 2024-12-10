/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static inline void update_task_slice(struct task_struct *p)
{
	p->scx.slice = SCX_SLICE_DFL;
}

static u64 task_vtime(struct task_struct *p)
{
	u64 vtime_min = vtime_now - SCX_SLICE_DFL * 100 / p->scx.weight;

	if (vtime_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	return p->scx.dsq_vtime;
}

static bool is_wake_sync(const struct task_struct *p,
			 const struct task_struct *current,
			 s32 prev_cpu, s32 cpu, u64 wake_flags)
{
	if (wake_flags & SCX_WAKE_SYNC)
		return true;

	if (is_kthread(current) && (p->nr_cpus_allowed == 1) && (prev_cpu == cpu))
		return true;

	return false;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	s32 cpu = bpf_get_smp_processor_id();
	bool is_idle = false;

	if (is_wake_sync(p, current, cpu, prev_cpu, wake_flags)) {
		if (!(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0 &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			return cpu;
		}
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return cpu;
	}

	return prev_cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	if ((p->nr_cpus_allowed == 1) || p->migration_disabled) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				 enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

	scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, task_vtime(p), enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_consume(SHARED_DSQ))
		return;

	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		update_task_slice(prev);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .flags			= SCX_OPS_ENQ_EXITING,
	       .timeout_ms		= 5000,
	       .name			= "simple");
