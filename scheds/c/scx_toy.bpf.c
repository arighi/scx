/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2023 Canonical Ltd.
 */

#include <scx/common.bpf.h>
#include "scx_toy.h"

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

/*
 * This contains the PID of the scheduler task itself (initialized in
 * scx_toy.c).
 */
const volatile s32 usersched_pid;

/* Set when the user-space scheduler needs to run */
static bool usersched_needed;

/* Notify the user-space counterpart when the BPF program exits */
struct user_exit_info uei;

/* Enqueues statistics */
u64 nr_failed_enqueues, nr_kernel_enqueues, nr_user_enqueues;

/*
 * BPF map to store enqueue events.
 *
 * The producer of this map is this BPF program, the consumer is the user-space
 * scheduler task.
 */
struct {
        __uint(type, BPF_MAP_TYPE_QUEUE);
        __uint(max_entries, MAX_TASKS);
        __type(value, struct scx_toy_enqueued_task);
} enqueued SEC(".maps");

/*
 * BPF map to store dispatch events.
 *
 * The producer of this map is the user-space scheduler task, the consumer is
 * this BPF program.
 */
struct {
        __uint(type, BPF_MAP_TYPE_QUEUE);
        __uint(max_entries, MAX_TASKS);
        __type(value, s32);
} dispatched SEC(".maps");

/* Return true if the target task "p" is a kernel thread */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

/* Return true if the target task "p" is the user-space scheduler task */
static bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

/*
 * Dispatch user-space scheduler directly.
 */
static void dispatch_user_scheduler(void)
{
        struct task_struct *p;

        if (!usersched_needed)
                return;
        p = bpf_task_from_pid(usersched_pid);
        if (!p)
                return;
        usersched_needed = false;
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        bpf_task_release(p);
}

void BPF_STRUCT_OPS(toy_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct scx_toy_enqueued_task task = {
		.pid = p->pid,
	};

        /*
         * User-space scheduler will be dispatched only when needed from
         * toy_dispatch(), so we can skip it here.
         */
        if (is_usersched_task(p))
            return;

	if (is_kthread(p)) {
		/*
		 * We want to dispatch kernel threads and the scheduler task
		 * directly here for efficiency reasons, rather than passing
		 * the events to the user-space scheduler counterpart.
		 */
		__sync_fetch_and_add(&nr_kernel_enqueues, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		/*
		 * We couldn't push the task to the "enqueued" map, dispatch
		 * the event here and register the failure in the failure
		 * counter.
		 */
		__sync_fetch_and_add(&nr_failed_enqueues, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	} else {
		/*
		 * Enqueue event will be processed and task will be dispatched
		 * in user-space by the scheduler task.
		 */
		__sync_fetch_and_add(&nr_user_enqueues, 1);
	}
}

void BPF_STRUCT_OPS(toy_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p;
	s32 pid;

        dispatch_user_scheduler();

	/*
	 * Get a dispatch event from user-space and dispatch the corresponding
	 * task.
	 */
	if (bpf_map_pop_elem(&dispatched, &pid))
		return;

	p = bpf_task_from_pid(pid);
	if (!p)
		return;

	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
	bpf_task_release(p);
}

s32 BPF_STRUCT_OPS(toy_init)
{
	return 0;
}

void BPF_STRUCT_OPS(toy_exit, struct scx_exit_info *ei)
{
	/* Notify user-space counterpart that the BPF program terminated */
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(toy_ops,
	       .enqueue			= (void *)toy_enqueue,
	       .dispatch		= (void *)toy_dispatch,
	       .init			= (void *)toy_init,
	       .exit			= (void *)toy_exit,
	       .timeout_ms		= 5000,
	       .name			= "toy");
