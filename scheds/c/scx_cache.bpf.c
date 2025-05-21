/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

#define SLICE_MAX	SCX_SLICE_DFL

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per-task context.
 *
 * TODO: Fill with the proper attributes to determine cache occupancy
 * per-task.
 */
struct task_ctx {
	u64 cache_occupancy_id;
	s32 cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Get cache occupancy associated to @cache_occupancy_id.
 */
static u64 cache_occupancy(u64 cache_occupancy_id)
{
	/*
	 * TODO: Implement a way to retrieve the actual cache occupancy.
	 */
	return 0;
}

/*
 * TODO: Introduce a configuratble cache occupancy threshold.
 */
#define CACHE_THRESHOLD		32768ULL

/*
 * Return true if a task is cache-sensitive, false otherwise.
 */
static inline bool is_cache_sensitive(const struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return false;

	return cache_occupancy(tctx->cache_occupancy_id) >= CACHE_THRESHOLD;
}

/*
 * Return true if the task still wants to run, false otherwise.
 */
static inline bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
			 u64 wake_flags, bool from_enqueue)
{
	s32 cpu;

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		bool is_idle = false;

		if (from_enqueue)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Select an optimal idle CPU for a task (triggered on task wakeup).
 */
s32 BPF_STRUCT_OPS(cache_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/*
	 * Pick the optimal idle CPU for the task.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, false);
	if (cpu >= 0)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_MAX, 0);

	return cpu >= 0 ? cpu : prev_cpu;
}

/*
 * Return true if task can attempt a migration to an idle CPU, false
 * otherwise.
 */
static bool can_migrate(const struct task_struct *p, u64 enq_flags)
{
	/*
	 * Per-CPU tasks are not allowed to migrate.
	 */
	if (is_pcpu_task(p))
		return false;

	/*
	 * Attempt a migration on wakeup (if ops.select_cpu() was skipped)
	 * or if the task was re-enqueued due to a higher scheduling class
	 * stealing the CPU it was queued on.
	 */
	return (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) ||
	       (enq_flags & SCX_ENQ_REENQ);
}

void BPF_STRUCT_OPS(cache_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 */
	if (can_migrate(p, enq_flags)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SLICE_MAX, enq_flags);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Keep using the same CPU in case of a cache-sensitive task,
	 * otherwise use to the global DSQ and allow the task to be
	 * picked by the first available CPU.
	 */
	if (is_cache_sensitive(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_MAX, enq_flags);
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		return;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SLICE_MAX, enq_flags);
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(cache_dispatch, s32 cpu, struct task_struct *prev)
{
	if (prev && is_queued(prev))
		prev->scx.slice = SLICE_MAX;
}

/*
 * A task starts running on a CPU (update its cache occupancy statistics.
 */
void BPF_STRUCT_OPS(cache_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * If the task migrates to a different CPU refresh its cache
	 * occupancy.
	 */
	if (tctx->cpu != cpu) {
		tctx->cpu = cpu;
		/* TODO: allocate / refresh cache occupancy ID */
		tctx->cache_occupancy_id = 0;
	}
}

s32 BPF_STRUCT_OPS(cache_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	tctx->cpu = -1;

	return 0;
}

void BPF_STRUCT_OPS(cache_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cache_ops,
	       .select_cpu		= (void *)cache_select_cpu,
	       .enqueue			= (void *)cache_enqueue,
	       .dispatch		= (void *)cache_dispatch,
	       .running			= (void *)cache_running,
	       .init_task		= (void *)cache_init_task,
	       .exit			= (void *)cache_exit,
	       .flags			= SCX_OPS_ALLOW_QUEUED_WAKEUP |
					  SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_MIGRATION_DISABLED,
	       .timeout_ms		= 5000,
	       .name			= "cache");
