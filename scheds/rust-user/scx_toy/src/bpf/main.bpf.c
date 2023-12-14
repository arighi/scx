/* Copyright (c) Andrea Righi <andrea.righi@canonical.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

/*
 * Maximum amount of tasks enqueued/dispatched between kernel and user-space.
 */
#define MAX_ENQUEUED_TASKS 1024

char _license[] SEC("license") = "GPL";

/*
 * Exit info
 */
int exit_kind = SCX_EXIT_NONE;
char exit_msg[SCX_EXIT_MSG_LEN];

/*
 * Scheduler attributes and statistics
 */
u32 usersched_pid;
u64 nr_enqueues, nr_user_dispatches, nr_kernel_dispatches;
static bool usersched_needed;

/*
 * Tasks enqueued to the user-space for scheduling.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key, 0);
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} enqueued SEC(".maps");

/*
 * Tasks enqueued by the user-space for dispatching.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(key, 0);
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} dispatched SEC(".maps");

/* Per-task scheduling context */
struct task_storage {
	u64 start_ns;
	u64 stop_ns;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_storage);
} task_storage_map SEC(".maps");

/* Return true if the target task "p" is a kernel thread */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

/* Return true if the target task "p" is the user-space scheduler */
static inline bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

void BPF_STRUCT_OPS(toy_running, struct task_struct *p)
{
	struct task_storage *ts;

	ts = bpf_task_storage_get(&task_storage_map, p, 0, 0);
	if (!ts) {
		scx_bpf_error("Failed to look up task-local storage for %s", p->comm);
		return;
	}
	ts->start_ns = bpf_ktime_get_ns();
	ts->stop_ns = ts->start_ns;
}

void BPF_STRUCT_OPS(toy_stopping, struct task_struct *p, bool runnable)
{
	struct task_storage *ts;

	ts = bpf_task_storage_get(&task_storage_map, p, 0, 0);
	if (!ts)
		return;
	ts->stop_ns = bpf_ktime_get_ns();
}

static inline u64 time_diff(u64 end, u64 start)
{
	return (s64)end - (s64)start;
}

static u64 task_slice(struct task_struct *p)
{
	struct task_storage *ts;
	u64 slice_ns;

	ts = bpf_task_storage_get(&task_storage_map, p, 0, 0);
	if (!ts)
		return 0;
	slice_ns = time_diff(ts->stop_ns, ts->start_ns);

	return MIN(slice_ns, SCX_SLICE_DFL);
}

static u64 task_deadline(struct task_struct *p)
{
	return bpf_ktime_get_ns() + task_slice(p) * 100 / p->scx.weight;
}

/* Dispatch a task on the local per-CPU FIFO */
static inline void dispatch_task_local(struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
}

/* Dispatch a task on the global FIFO */
static inline void dispatch_task_global(struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	__sync_fetch_and_add(&nr_user_dispatches, 1);
}

void BPF_STRUCT_OPS(toy_enqueue, struct task_struct *p, u64 enq_flags)
{
        struct task_ctx task;

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here.
	 */
	if (is_usersched_task(p))
		return;

        /*
	 * Dispatch per-cpu kthreads on the local FIFO directly from the
	 * kernel.
         */
	if (is_kthread(p) && p->nr_cpus_allowed == 1) {
		dispatch_task_local(p, enq_flags | SCX_ENQ_LOCAL);
		return;
	}

	/*
	 * Other tasks can be added to the @enqueued list and they will be
	 * processed by the user-space scheduler.
	 *
	 * If the @enqueued list is full (user-space scheduler is congested)
	 * tasks will be dispatched directly from the kernel to the global
	 * FIFO.
	 */
	task.pid = p->pid;
	task.data = task_deadline(p);
	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		dispatch_task_global(p, enq_flags);
		return;
	}

	/*
	 * Task was sent to user-space correctly, wake-up the user-space
	 * scheduler.
	 */
	usersched_needed = true;
	__sync_fetch_and_add(&nr_enqueues, 1);
}

/* Run the user-space scheduler directly */
static void dispatch_user_scheduler(void)
{
	struct task_struct *p;

	if (!usersched_needed)
		return;
	usersched_needed = false;

	p = bpf_task_from_pid(usersched_pid);
	if (!p) {
		scx_bpf_error("Failed to find usersched task %d", usersched_pid);
		return;
	}
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
	bpf_task_release(p);
}

void BPF_STRUCT_OPS(toy_dispatch, s32 cpu, struct task_struct *prev)
{
	/* Check if the user-space scheduler needs to run */
	dispatch_user_scheduler();

	/*
	 * Then consume all tasks from the dispatched list and dispatch them to
	 * the global FIFO (the proper ordering has been already determined by
	 * the user-space scheduler).
	 */
	bpf_repeat(MAX_ENQUEUED_TASKS) {
		struct task_struct *p;
		struct task_ctx task;

		if (!scx_bpf_dispatch_nr_slots())
			break;
		if (bpf_map_pop_elem(&dispatched, &task))
			break;
		p = bpf_task_from_pid(task.pid);
		if (!p)
			continue;
		dispatch_task_global(p, 0);
		bpf_task_release(p);
	}
}

s32 BPF_STRUCT_OPS(toy_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 cpu;

	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu < 0)
		return prev_cpu;

	return cpu;

}

s32 BPF_STRUCT_OPS(toy_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	if (bpf_task_storage_get(&task_storage_map, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(toy_init)
{
	scx_bpf_switch_all();
	return 0;
}

void BPF_STRUCT_OPS(toy_exit, struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_kind = ei->kind;
}

SEC(".struct_ops.link")
struct sched_ext_ops toy = {
	.select_cpu		= (void *)toy_select_cpu,
	.enqueue		= (void *)toy_enqueue,
	.dispatch		= (void *)toy_dispatch,
	.running		= (void *)toy_running,
	.stopping		= (void *)toy_stopping,
	.prep_enable		= (void *)toy_prep_enable,
	.init			= (void *)toy_init,
	.exit			= (void *)toy_exit,
	.timeout_ms		= 5000,
	.name			= "toy",
};
